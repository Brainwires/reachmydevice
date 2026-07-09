//! ReachMyDevice browser viewer (WASM).
//!
//! A no-install viewer: it authenticates to the rendezvous over WebSocket, acts
//! as the WebRTC **answerer** to a native host, receives the host's H.264 video
//! track (decoded by the browser), and sends mouse/keyboard input back over the
//! host's `control` data channel as `rmd-protocol` protobufs.
//!
//! Video is shown in a `<video>` element (the browser decodes H.264 and composites
//! it on the GPU). A wgpu-canvas render path (for overlays/scaling effects) is a
//! planned follow-up; the transport, signaling, and input here are codec-agnostic.
//!
//! ## Wire compatibility
//! The `/ws` relay envelope (`{to,payload}` / `{from,payload}` with
//! `kind: "hello" | "signal"`) and the `SignalMsg` JSON
//! (`{"type":"offer|answer|candidate","data":…}`) exactly mirror the native
//! `RendezvousClient`, so the rendezvous server is unchanged.

mod input;
mod signaling;

use signaling::Relay;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::{spawn_local, JsFuture};
use web_sys::{
    HtmlCanvasElement, HtmlVideoElement, MediaStream, MessageEvent, MouseEvent, RtcConfiguration,
    RtcDataChannel, RtcDataChannelEvent, RtcIceCandidateInit, RtcPeerConnection,
    RtcPeerConnectionIceEvent, RtcSdpType, RtcSessionDescriptionInit, RtcTrackEvent, Response,
    TouchEvent, WheelEvent,
};

/// Runtime configuration, from URL query params on the page:
/// `?server=wss://app.reachmy.dev&token=…&host=<device_id>`.
#[derive(Clone)]
struct Config {
    /// WebSocket base, e.g. `wss://app.reachmy.dev` (no trailing `/ws`).
    server: String,
    /// Device bearer token for the rendezvous `/ws` auth.
    token: String,
    /// The host device_id to connect to.
    host_id: String,
}

impl Config {
    fn from_url() -> Result<Config, String> {
        let window = web_sys::window().ok_or("no window")?;
        let search = window.location().search().map_err(|_| "no search")?;
        let params = web_sys::UrlSearchParams::new_with_str(&search)
            .map_err(|_| "bad query string".to_string())?;
        let server = params
            .get("server")
            .filter(|s| !s.is_empty())
            .or_else(|| default_ws_base(&window))
            .ok_or("missing ?server=")?;
        let token = params.get("token").unwrap_or_default();
        let host_id = params.get("host").unwrap_or_default();
        if token.is_empty() {
            return Err("missing ?token=".into());
        }
        if host_id.is_empty() {
            return Err("missing ?host= (the host device id)".into());
        }
        Ok(Config {
            server,
            token,
            host_id,
        })
    }
}

/// Default the WebSocket base to this page's origin (so the console-hosted viewer
/// talks to the same rendezvous), upgrading http→ws / https→wss.
fn default_ws_base(window: &web_sys::Window) -> Option<String> {
    let loc = window.location();
    let proto = loc.protocol().ok()?;
    let host = loc.host().ok()?;
    let ws = if proto == "https:" { "wss" } else { "ws" };
    Some(format!("{ws}://{host}"))
}

/// Fetch the ICE servers for this session from the rendezvous `/api/ice`. The
/// server returns objects already shaped like `RTCIceServer`
/// (`{urls, username?, credential?}`), so the array is used verbatim. Falls back
/// to a public STUN server if the request fails, so a same-LAN session can still
/// try direct/reflexive connectivity.
async fn fetch_ice_servers(window: &web_sys::Window, ws_base: &str, token: &str) -> js_sys::Array {
    let http_base = ws_base
        .replacen("wss://", "https://", 1)
        .replacen("ws://", "http://", 1);
    let url = format!("{}/api/ice?token={}", http_base.trim_end_matches('/'), token);
    match fetch_ice_array(window, &url).await {
        Ok(arr) if arr.length() > 0 => return arr,
        Ok(_) => web_sys::console::warn_1(&"[rmd] /api/ice returned no servers".into()),
        Err(e) => web_sys::console::warn_1(
            &format!("[rmd] /api/ice failed ({e:?}); falling back to public STUN").into(),
        ),
    }
    let ice = js_sys::Array::new();
    let stun = js_sys::Object::new();
    js_sys::Reflect::set(&stun, &"urls".into(), &"stun:stun.l.google.com:19302".into()).ok();
    ice.push(&stun);
    ice
}

/// Perform the `/api/ice` GET and extract the `ice_servers` array.
async fn fetch_ice_array(window: &web_sys::Window, url: &str) -> Result<js_sys::Array, JsValue> {
    let resp: Response = JsFuture::from(window.fetch_with_str(url)).await?.dyn_into()?;
    if !resp.ok() {
        return Err(format!("HTTP {}", resp.status()).into());
    }
    let json = JsFuture::from(resp.json()?).await?;
    js_sys::Reflect::get(&json, &"ice_servers".into())?.dyn_into::<js_sys::Array>()
}

/// Shared session state across the many web-sys callbacks.
struct Session {
    pc: RtcPeerConnection,
    relay: Relay,
    host_id: String,
    /// The host-created `control` data channel, once it arrives + opens.
    control: RefCell<Option<RtcDataChannel>>,
    /// The `<video>` element showing the decoded stream (also the input surface).
    video: HtmlVideoElement,
    /// Whether we've already sent our protocol `Hello` over the control channel.
    hello_sent: RefCell<bool>,
}

impl Session {
    /// Stop this session's callbacks from firing and close its transports. Called
    /// before building a replacement session on reconnect, so a dead pc/socket
    /// can't dispatch late frames or re-trigger the reconnect logic.
    fn teardown(&self) {
        self.pc.set_onconnectionstatechange(None);
        self.pc.set_ontrack(None);
        self.pc.set_onicecandidate(None);
        self.pc.set_ondatachannel(None);
        self.pc.close();
        self.relay.close();
    }
}

/// Long-lived app state that survives across reconnects (the session inside is
/// rebuilt each time the connection drops). A backgrounded phone freezes JS and
/// drops the media/socket; on resume the old session is dead and never recovers,
/// so we detect that (pc `Failed`/`Disconnected`, or the tab becoming visible
/// again) and rebuild the whole session.
struct App {
    cfg: Config,
    /// The `<video>` element (reused across reconnects; it's a page fixture).
    video: HtmlVideoElement,
    /// The live session, replaced on each reconnect.
    current: RefCell<Option<Rc<Session>>>,
    /// True while a connect attempt is scheduled or in progress (up to session
    /// creation) — guards against stacking reconnects.
    connecting: Cell<bool>,
}

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
    let _ = tracing_wasm::try_set_as_global_default();
    // Only run a session when the connect params are present. Otherwise the page's
    // connect screen (login + host picker, in index.html) is shown and it will
    // reload here with `?token=&host=` once the user chooses a host.
    if !has_session_params() {
        return;
    }
    spawn_local(async {
        if let Err(e) = run().await {
            web_sys::console::error_1(&format!("[rmd-web-viewer] fatal: {e}").into());
            show_error(&e);
        }
    });
}

/// Whether the URL carries both `token` and `host` (i.e. a session to run).
fn has_session_params() -> bool {
    web_sys::window()
        .and_then(|w| w.location().search().ok())
        .and_then(|s| web_sys::UrlSearchParams::new_with_str(&s).ok())
        .map(|p| {
            p.get("token").filter(|t| !t.is_empty()).is_some()
                && p.get("host").filter(|h| !h.is_empty()).is_some()
        })
        .unwrap_or(false)
}

async fn run() -> Result<(), String> {
    let cfg = Config::from_url()?;
    let window = web_sys::window().ok_or("no window")?;
    let document = window.document().ok_or("no document")?;

    // The <video> element that displays the decoded H.264 track + captures input.
    let video: HtmlVideoElement = document
        .get_element_by_id("screen")
        .and_then(|e| e.dyn_into::<HtmlVideoElement>().ok())
        .ok_or("no <video id=screen> in page")?;
    video.set_autoplay(true);
    video.set_muted(true);
    let _ = video.set_attribute("playsinline", "true");

    let app = Rc::new(App {
        cfg,
        video,
        current: RefCell::new(None),
        connecting: Cell::new(false),
    });

    // Rebuild the connection when the tab becomes visible again with no healthy
    // session (the classic phone case: suspend freezes JS + kills the socket, and
    // the dead session never recovers on its own).
    {
        let app = app.clone();
        let document2 = document.clone();
        let cb = Closure::<dyn FnMut()>::new(move || {
            if document2.hidden() {
                return; // only act on becoming visible
            }
            let healthy = app.current.borrow().as_ref().is_some_and(|s| {
                matches!(
                    s.pc.connection_state(),
                    web_sys::RtcPeerConnectionState::Connected
                        | web_sys::RtcPeerConnectionState::Connecting
                        | web_sys::RtcPeerConnectionState::New
                )
            });
            if !healthy {
                web_sys::console::log_1(&"[rmd] visible again; reconnecting".into());
                schedule_reconnect(app.clone());
            }
        });
        document
            .add_event_listener_with_callback("visibilitychange", cb.as_ref().unchecked_ref())
            .ok();
        cb.forget();
    }

    connect(app).await;
    Ok(())
}

/// Build a fresh WebRTC session (answerer) and announce to the host. Replaces any
/// previous session, tearing it down first. Idempotent under the `connecting`
/// guard so overlapping reconnect triggers collapse into one attempt.
async fn connect(app: Rc<App>) {
    if app.connecting.replace(true) {
        return; // an attempt is already in flight
    }
    // Tear the old session down so its dead pc/socket stops firing callbacks.
    if let Some(old) = app.current.borrow_mut().take() {
        old.teardown();
    }

    let Some(window) = web_sys::window() else {
        app.connecting.set(false);
        return;
    };

    // --- WebRTC peer connection (answerer) --------------------------------
    // Ask the rendezvous which ICE servers to use (STUN + TURN with ephemeral
    // credentials). Without a relay, a cross-NAT host won't connect. Re-fetched
    // each attempt so expired TURN credentials are refreshed on reconnect.
    let rtc_cfg = RtcConfiguration::new();
    let ice = fetch_ice_servers(&window, &app.cfg.server, &app.cfg.token).await;
    rtc_cfg.set_ice_servers(&ice);
    let pc = match RtcPeerConnection::new_with_configuration(&rtc_cfg) {
        Ok(pc) => pc,
        Err(e) => {
            app.connecting.set(false);
            web_sys::console::error_1(&format!("[rmd] pc: {e:?}").into());
            schedule_reconnect(app.clone());
            return;
        }
    };
    let relay = match Relay::connect(&app.cfg.server, &app.cfg.token) {
        Ok(r) => r,
        Err(e) => {
            pc.close();
            app.connecting.set(false);
            web_sys::console::error_1(&format!("[rmd] ws: {e}").into());
            schedule_reconnect(app.clone());
            return;
        }
    };

    let session = Rc::new(Session {
        pc: pc.clone(),
        relay: relay.clone(),
        host_id: app.cfg.host_id.clone(),
        control: RefCell::new(None),
        video: app.video.clone(),
        hello_sent: RefCell::new(false),
    });

    wire_pc_callbacks(&session, &app);
    wire_relay_callbacks(&session);

    *app.current.borrow_mut() = Some(session);
    app.connecting.set(false);

    // Announce presence so the host learns our device id and sends its offer.
    relay.send_hello(&app.cfg.host_id);
    set_status("connecting…");
}

/// Schedule a reconnect after a short backoff (debounced by the `connecting`
/// guard so a burst of Failed/visibility events yields a single attempt).
fn schedule_reconnect(app: Rc<App>) {
    if app.connecting.get() {
        return; // already scheduled or in progress
    }
    app.connecting.set(true); // hold the guard across the backoff delay
    let cb = Closure::once_into_js(move || {
        app.connecting.set(false); // release so connect() can re-acquire
        spawn_local(connect(app));
    });
    if let Some(win) = web_sys::window() {
        let _ = win.set_timeout_with_callback_and_timeout_and_arguments_0(
            cb.unchecked_ref(),
            1000,
        );
    }
}

/// Attach ontrack / onicecandidate / ondatachannel / connectionstatechange.
fn wire_pc_callbacks(session: &Rc<Session>, app: &Rc<App>) {
    let pc = &session.pc;

    // Inbound video track → attach the MediaStream to the <video> element.
    {
        let video = session.video.clone();
        let cb = Closure::<dyn FnMut(RtcTrackEvent)>::new(move |ev: RtcTrackEvent| {
            let streams = ev.streams();
            if let Some(stream) = streams.get(0).dyn_ref::<MediaStream>() {
                video.set_src_object(Some(stream));
                let _ = video.play();
                set_status("connected");
            }
        });
        pc.set_ontrack(Some(cb.as_ref().unchecked_ref()));
        cb.forget();
    }

    // Our ICE candidates → trickle to the host over the relay.
    {
        let s = session.clone();
        let cb = Closure::<dyn FnMut(RtcPeerConnectionIceEvent)>::new(
            move |ev: RtcPeerConnectionIceEvent| {
                if let Some(cand) = ev.candidate() {
                    s.relay
                        .send_signal(&s.host_id, &SignalMsg::Candidate(cand.candidate()));
                }
            },
        );
        pc.set_onicecandidate(Some(cb.as_ref().unchecked_ref()));
        cb.forget();
    }

    // The host creates the `control` data channel; capture it when it arrives.
    {
        let s = session.clone();
        let cb = Closure::<dyn FnMut(RtcDataChannelEvent)>::new(move |ev: RtcDataChannelEvent| {
            let dc = ev.channel();
            wire_data_channel(&s, &dc);
            *s.control.borrow_mut() = Some(dc);
        });
        pc.set_ondatachannel(Some(cb.as_ref().unchecked_ref()));
        cb.forget();
    }

    // Surface connection-state changes, and rebuild the session when it drops.
    {
        let pc2 = pc.clone();
        let app = app.clone();
        let cb = Closure::<dyn FnMut()>::new(move || {
            let st = pc2.connection_state();
            web_sys::console::log_1(&format!("[rmd] pc state: {st:?}").into());
            if matches!(
                st,
                web_sys::RtcPeerConnectionState::Failed
                    | web_sys::RtcPeerConnectionState::Disconnected
            ) {
                set_status("disconnected — reconnecting…");
                schedule_reconnect(app.clone());
            }
        });
        pc.set_onconnectionstatechange(Some(cb.as_ref().unchecked_ref()));
        cb.forget();
    }
}

/// On the control channel: send our `Hello` once open, then attach input, and
/// log inbound control (HelloAck/pong/etc.).
fn wire_data_channel(session: &Rc<Session>, dc: &RtcDataChannel) {
    // Once open, send the protocol Hello (role=Viewer, supports H.264).
    {
        let s = session.clone();
        let dc_open = dc.clone();
        let cb = Closure::<dyn FnMut()>::new(move || {
            if !*s.hello_sent.borrow() {
                let hello = rmd_protocol::hello("web-viewer", rmd_protocol::Role::Viewer, 0);
                let bytes = rmd_protocol::encode(&hello);
                let _ = dc_open.send_with_u8_array(&bytes);
                *s.hello_sent.borrow_mut() = true;
                attach_input(&s, &dc_open);
                set_status("session ready");
            }
        });
        dc.set_onopen(Some(cb.as_ref().unchecked_ref()));
        cb.forget();
    }

    // Inbound control (HelloAck, DisplayList, Pong…).
    {
        // Clone the channel so we can re-send a password-bearing Hello.
        let dc_msg = dc.clone();
        let cb = Closure::<dyn FnMut(MessageEvent)>::new(move |ev: MessageEvent| {
            if let Ok(buf) = ev.data().dyn_into::<js_sys::ArrayBuffer>() {
                let bytes = js_sys::Uint8Array::new(&buf).to_vec();
                if let Ok(env) = rmd_protocol::decode(&bytes) {
                    if let Some(rmd_protocol::pb::envelope::Payload::HelloAck(ack)) = env.payload {
                        if ack.password_required {
                            // Host wants a connection password (or ours was wrong):
                            // prompt and re-send the Hello with it (not via the URL).
                            match prompt_password() {
                                Some(pw) => {
                                    let hello = rmd_protocol::with_password(
                                        rmd_protocol::hello(
                                            "web-viewer",
                                            rmd_protocol::Role::Viewer,
                                            0,
                                        ),
                                        pw,
                                    );
                                    let _ = dc_msg
                                        .send_with_u8_array(&rmd_protocol::encode(&hello));
                                    set_status("checking password…");
                                }
                                None => set_status("connection password required"),
                            }
                        } else if !ack.accepted {
                            set_status(&format!("rejected: {}", ack.reason));
                        } else {
                            set_status("connected");
                        }
                    }
                }
            }
        });
        dc.set_binary_type(web_sys::RtcDataChannelType::Arraybuffer);
        dc.set_onmessage(Some(cb.as_ref().unchecked_ref()));
        cb.forget();
    }
}

/// Prompt the user for the host's connection password (browser dialog). Returns
/// `None` if they cancel or leave it blank. Kept out of the URL/history.
fn prompt_password() -> Option<String> {
    let win = web_sys::window()?;
    match win.prompt_with_message("This host requires a connection password:") {
        Ok(Some(s)) if !s.is_empty() => Some(s),
        _ => None,
    }
}

/// Attach mouse + keyboard listeners on the video surface; encode to protobuf and
/// send over the control channel.
fn attach_input(session: &Rc<Session>, dc: &RtcDataChannel) {
    let video = session.video.clone();

    // Normalized position helper: viewport client px -> host source coords in
    // [0,1], un-rotating for the current view (`data-rot`; CSS rotate(90deg) is
    // clockwise, so these are its inverses). Shared by mouse + touch.
    let norm = {
        let video = video.clone();
        move |cx: f64, cy: f64| -> (f64, f64) {
            let rect = video.get_bounding_client_rect();
            let w = rect.width().max(1.0);
            let h = rect.height().max(1.0);
            let bx = (cx - rect.left()) / w;
            let by = (cy - rect.top()) / h;
            match video.get_attribute("data-rot").as_deref() {
                Some("1") => (by, 1.0 - bx),
                Some("2") => (1.0 - bx, 1.0 - by),
                Some("3") => (1.0 - by, bx),
                _ => (bx, by),
            }
        }
    };
    let rect_norm = {
        let norm = norm.clone();
        move |ev: &MouseEvent| norm(ev.client_x() as f64, ev.client_y() as f64)
    };

    // mousemove
    {
        let dc = dc.clone();
        let rect_norm = rect_norm.clone();
        let cb = Closure::<dyn FnMut(MouseEvent)>::new(move |ev: MouseEvent| {
            let (x, y) = rect_norm(&ev);
            let _ = dc.send_with_u8_array(&input::mouse_move(x, y));
        });
        video
            .add_event_listener_with_callback("mousemove", cb.as_ref().unchecked_ref())
            .ok();
        cb.forget();
    }
    // mousedown / mouseup
    for (event, pressed) in [("mousedown", true), ("mouseup", false)] {
        let dc = dc.clone();
        let rect_norm = rect_norm.clone();
        let cb = Closure::<dyn FnMut(MouseEvent)>::new(move |ev: MouseEvent| {
            ev.prevent_default();
            let (x, y) = rect_norm(&ev);
            let btn = input::dom_button_to_proto(ev.button());
            let _ = dc.send_with_u8_array(&input::mouse_button(btn, pressed, x, y));
        });
        video
            .add_event_listener_with_callback(event, cb.as_ref().unchecked_ref())
            .ok();
        cb.forget();
    }
    // Touch = trackpad semantics, branching on the current finger count. A drag
    // moves the cursor by a RELATIVE delta (a comparable distance) — it does NOT
    // jump the cursor to the point under the finger; a tap clicks in place:
    //   • one-finger tap        → LEFT-click at the cursor's current location
    //   • two-finger tap        → RIGHT-click at the cursor's current location
    //   • one-finger press+drag → move the cursor by the finger's delta (hover)
    //   • three-finger swipe    → wheel scroll (all four directions, content
    //                             follows the fingers)
    // The host moves/clicks AT the coords it's sent (absolute), so we keep a
    // virtual cursor here, add each finger delta into it (clamped to [0,1]), and
    // send that — never the raw finger point. The move delta is taken through
    // `norm`, whose origin cancels in the difference, so rotation + scaling are
    // handled for free. (The very first move establishes position from the seeded
    // centre; there's no host cursor feedback to sync to.) We track the PRIMARY
    // touch (`touches[0]`) and reset the delta anchor whenever the finger set
    // changes, so adding/removing a finger doesn't fling the cursor. preventDefault
    // stops the browser scrolling or double-firing as a mouse.
    {
        use std::cell::Cell;
        const SENS: f64 = 1.0; // finger→cursor gain; 1.0 = comparable distance
        const SCROLL_SENS: f64 = 1.0; // finger px → wheel px, content-follows-finger
        let moved = Rc::new(Cell::new(false)); // did this gesture cross the drag threshold?
        let start = Rc::new(Cell::new((0.0f64, 0.0f64))); // first-finger client px (threshold anchor)
        let prev = Rc::new(Cell::new((0.0f64, 0.0f64))); // previous primary-touch client px (delta anchor)
        let cursor = Rc::new(Cell::new((0.5f64, 0.5f64))); // virtual cursor, normalized
        let has_pos = Rc::new(Cell::new(false)); // has the cursor position been established?
        let max_fingers = Rc::new(Cell::new(0u32)); // most fingers down at once this gesture

        // Snapshot the primary touch's client-px position, if any.
        fn primary(ev: &TouchEvent) -> Option<(f64, f64)> {
            ev.touches()
                .get(0)
                .map(|t| (t.client_x() as f64, t.client_y() as f64))
        }

        // touchstart: (re)anchor the delta to the primary touch and track the peak
        // finger count. Does NOT move the cursor.
        {
            let (moved, start, prev, max_fingers) =
                (moved.clone(), start.clone(), prev.clone(), max_fingers.clone());
            let cb = Closure::<dyn FnMut(TouchEvent)>::new(move |ev: TouchEvent| {
                ev.prevent_default();
                let n = ev.touches().length();
                if n > max_fingers.get() {
                    max_fingers.set(n);
                }
                if let Some(p) = primary(&ev) {
                    prev.set(p); // re-anchor so the new finger doesn't fling
                    if n == 1 {
                        start.set(p);
                        moved.set(false);
                    }
                }
            });
            video
                .add_event_listener_with_callback("touchstart", cb.as_ref().unchecked_ref())
                .ok();
            cb.forget();
        }
        // touchmove: branch on the CURRENT finger count — 1 = move cursor by delta,
        // 3+ = wheel scroll by delta, 2 = nothing (a pending right-click). Any move
        // past the threshold marks the gesture a drag so touchend won't click.
        {
            let dc = dc.clone();
            let norm = norm.clone();
            let (moved, start, prev, cursor, has_pos) = (
                moved.clone(),
                start.clone(),
                prev.clone(),
                cursor.clone(),
                has_pos.clone(),
            );
            let cb = Closure::<dyn FnMut(TouchEvent)>::new(move |ev: TouchEvent| {
                ev.prevent_default();
                let n = ev.touches().length();
                let Some((cx, cy)) = primary(&ev) else {
                    return;
                };
                let (px, py) = prev.get();
                prev.set((cx, cy));
                let (sx, sy) = start.get();
                if (cx - sx).hypot(cy - sy) > 8.0 {
                    moved.set(true);
                }
                if n >= 3 {
                    // Three-finger swipe → wheel scroll. Content follows the
                    // fingers (drag down → content down), in raw client px.
                    let (dx, dy) = ((cx - px) * SCROLL_SENS, (cy - py) * SCROLL_SENS);
                    if dx != 0.0 || dy != 0.0 {
                        let _ = dc.send_with_u8_array(&input::mouse_scroll(dx, dy));
                    }
                } else if n <= 1 {
                    // Normalized (un-rotated) finger delta: `norm` is affine, so the
                    // origin cancels and only the displacement survives.
                    let (nx, ny) = norm(cx, cy);
                    let (npx, npy) = norm(px, py);
                    let (mut ux, mut uy) = cursor.get();
                    ux = (ux + (nx - npx) * SENS).clamp(0.0, 1.0);
                    uy = (uy + (ny - npy) * SENS).clamp(0.0, 1.0);
                    cursor.set((ux, uy));
                    has_pos.set(true);
                    let _ = dc.send_with_u8_array(&input::mouse_move(ux, uy));
                }
            });
            video
                .add_event_listener_with_callback("touchmove", cb.as_ref().unchecked_ref())
                .ok();
            cb.forget();
        }
        // touchend: re-anchor the delta while fingers remain; on the LAST lift, a
        // tap (never dragged) clicks — right for two fingers, left for one, nothing
        // for three+ — at the virtual cursor, NOT the tap point. A drag/swipe just
        // ends. Cold start (a tap before any drag → no known cursor): fall back to
        // the tap point + adopt it.
        {
            let dc = dc.clone();
            let norm = norm.clone();
            let (moved, prev, cursor, has_pos, max_fingers) = (
                moved.clone(),
                prev.clone(),
                cursor.clone(),
                has_pos.clone(),
                max_fingers.clone(),
            );
            let cb = Closure::<dyn FnMut(TouchEvent)>::new(move |ev: TouchEvent| {
                ev.prevent_default();
                if let Some(p) = primary(&ev) {
                    prev.set(p); // a finger lifted but others remain — re-anchor
                    return;
                }
                let fingers = max_fingers.get();
                let dragged = moved.get();
                max_fingers.set(0); // reset for the next gesture
                if dragged {
                    return; // it was a drag/swipe, not a tap
                }
                // DOM button: 0 = left (one finger), 2 = right (two fingers);
                // three+ finger taps do nothing.
                let btn = match fingers {
                    1 => input::dom_button_to_proto(0),
                    2 => input::dom_button_to_proto(2),
                    _ => return,
                };
                let (x, y) = if has_pos.get() {
                    cursor.get()
                } else if let Some(t) = ev.changed_touches().get(0) {
                    let p = norm(t.client_x() as f64, t.client_y() as f64);
                    cursor.set(p);
                    has_pos.set(true);
                    p
                } else {
                    return;
                };
                let _ = dc.send_with_u8_array(&input::mouse_button(btn, true, x, y));
                let _ = dc.send_with_u8_array(&input::mouse_button(btn, false, x, y));
            });
            video
                .add_event_listener_with_callback("touchend", cb.as_ref().unchecked_ref())
                .ok();
            cb.forget();
        }
    }
    // contextmenu → suppress (right-click is sent as an input event instead)
    {
        let cb = Closure::<dyn FnMut(MouseEvent)>::new(move |ev: MouseEvent| ev.prevent_default());
        video
            .add_event_listener_with_callback("contextmenu", cb.as_ref().unchecked_ref())
            .ok();
        cb.forget();
    }
    // wheel
    {
        let dc = dc.clone();
        let cb = Closure::<dyn FnMut(WheelEvent)>::new(move |ev: WheelEvent| {
            ev.prevent_default();
            let _ = dc.send_with_u8_array(&input::mouse_scroll(-ev.delta_x(), -ev.delta_y()));
        });
        video
            .add_event_listener_with_callback("wheel", cb.as_ref().unchecked_ref())
            .ok();
        cb.forget();
    }
    // key down / up on the document (video isn't focusable by default)
    if let Some(win) = web_sys::window() {
        for (event, pressed) in [("keydown", true), ("keyup", false)] {
            let dc = dc.clone();
            let cb = Closure::<dyn FnMut(web_sys::KeyboardEvent)>::new(
                move |ev: web_sys::KeyboardEvent| {
                    if let Some(hid) = input::code_to_hid(&ev.code()) {
                        ev.prevent_default();
                        let mods = input::modifier_mask(
                            ev.shift_key(),
                            ev.ctrl_key(),
                            ev.alt_key(),
                            ev.meta_key(),
                            ev.get_modifier_state("CapsLock"),
                        );
                        let _ = dc.send_with_u8_array(&input::key(hid, pressed, mods));
                    }
                },
            );
            win.add_event_listener_with_callback(event, cb.as_ref().unchecked_ref())
                .ok();
            cb.forget();
        }
    }
}

/// A signaling message, identical JSON to the native `rmd_transport::SignalMsg`.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
#[serde(tag = "type", content = "data", rename_all = "lowercase")]
pub enum SignalMsg {
    Offer(String),
    Answer(String),
    Candidate(String),
}

/// Unwrap the SDP from the native peer's JSON `RTCSessionDescription` wire form
/// (`{"type","sdp"}`). Falls back to treating the payload as raw SDP, so a peer
/// that ever sends bare SDP still works.
fn sdp_from_wire(wire: &str) -> String {
    serde_json::from_str::<serde_json::Value>(wire)
        .ok()
        .and_then(|v| v.get("sdp").and_then(|s| s.as_str()).map(str::to_owned))
        .unwrap_or_else(|| wire.to_owned())
}

/// Encode an SDP as the JSON `RTCSessionDescription` wire form the native host
/// decodes. `json!` handles escaping the SDP's CRLFs correctly.
fn wrap_description(kind: &str, sdp: &str) -> String {
    serde_json::json!({ "type": kind, "sdp": sdp }).to_string()
}

/// Handle a `SignalMsg` from the host: apply the offer + answer it, or add a
/// trickled ICE candidate.
fn wire_relay_callbacks(session: &Rc<Session>) {
    let s = session.clone();
    session.relay.on_signal(move |msg: SignalMsg| {
        let s = s.clone();
        spawn_local(async move {
            if let Err(e) = handle_signal(&s, msg).await {
                web_sys::console::error_1(&format!("[rmd] signal error: {e}").into());
            }
        });
    });
}

async fn handle_signal(session: &Rc<Session>, msg: SignalMsg) -> Result<(), String> {
    match msg {
        SignalMsg::Offer(wire) => {
            // The native host encodes the description as a JSON RTCSessionDescription
            // (`{"type","sdp"}`, matching `rtc`'s serde form); unwrap it to the raw
            // SDP the browser's setRemoteDescription expects. Passing the JSON blob
            // straight in makes Chrome fail with "Expect line: v=".
            let sdp = sdp_from_wire(&wire);
            let desc = RtcSessionDescriptionInit::new(RtcSdpType::Offer);
            desc.set_sdp(&sdp);
            JsFuture::from(session.pc.set_remote_description(&desc))
                .await
                .map_err(|e| format!("set_remote(offer): {e:?}"))?;
            let answer = JsFuture::from(session.pc.create_answer())
                .await
                .map_err(|e| format!("create_answer: {e:?}"))?;
            let answer_sdp = js_sys::Reflect::get(&answer, &"sdp".into())
                .ok()
                .and_then(|v| v.as_string())
                .ok_or("answer has no sdp")?;
            let adesc = RtcSessionDescriptionInit::new(RtcSdpType::Answer);
            adesc.set_sdp(&answer_sdp);
            JsFuture::from(session.pc.set_local_description(&adesc))
                .await
                .map_err(|e| format!("set_local(answer): {e:?}"))?;
            // Reply in the same JSON RTCSessionDescription form the host decodes
            // (`serde_json::from_str::<RTCSessionDescription>`); a raw SDP would
            // fail its parse.
            session.relay.send_signal(
                &session.host_id,
                &SignalMsg::Answer(wrap_description("answer", &answer_sdp)),
            );
        }
        SignalMsg::Answer(_) => { /* viewer is the answerer; ignore */ }
        SignalMsg::Candidate(cand) => {
            let init = RtcIceCandidateInit::new(&cand);
            // The host trickles bare candidate strings; media is a single m-line,
            // so index 0 / mid "0" is correct for our single-track session.
            init.set_sdp_m_line_index(Some(0));
            init.set_sdp_mid(Some("0"));
            let promise = session
                .pc
                .add_ice_candidate_with_opt_rtc_ice_candidate_init(Some(&init));
            let _ = JsFuture::from(promise).await;
        }
    }
    Ok(())
}

fn set_status(text: &str) {
    if let Some(el) = web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.get_element_by_id("status"))
    {
        el.set_text_content(Some(text));
    }
}

fn show_error(msg: &str) {
    set_status(&format!("error: {msg}"));
}

// Silence "unused" for the canvas import kept for the planned wgpu path.
#[allow(dead_code)]
fn _canvas_marker(_c: HtmlCanvasElement) {}
