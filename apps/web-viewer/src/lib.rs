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
mod swipe;

use signaling::Relay;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::{spawn_local, JsFuture};
use web_sys::{
    HtmlCanvasElement, HtmlVideoElement, MediaStream, MessageEvent, MouseEvent, RtcConfiguration,
    RtcDataChannel, RtcDataChannelEvent, RtcIceCandidateInit, RtcPeerConnection,
    RtcPeerConnectionIceEvent, RtcRtpReceiver, RtcSdpType, RtcSessionDescriptionInit, RtcTrackEvent,
    Response, TouchEvent, WheelEvent,
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
    /// The host's connection password once the user has entered it — shared with
    /// [`App`] so it survives reconnects. On (re)connect the Hello carries it, so a
    /// reconnect after a background/resume re-authenticates automatically instead
    /// of stalling at "connected" with no video (the host won't stream until
    /// authorized).
    password: Rc<RefCell<Option<String>>>,
    /// `setInterval` handle for the live-latency monitor (see
    /// [`start_latency_control`]); cleared on teardown so it doesn't outlive the pc.
    latency_timer: RefCell<Option<i32>>,
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
        if let Some(id) = self.latency_timer.borrow_mut().take() {
            if let Some(w) = web_sys::window() {
                w.clear_interval_with_handle(id);
            }
        }
        self.video.set_playback_rate(1.0);
        self.pc.close();
        self.relay.close();
        // Hide the local touch cursor so it doesn't linger over the frozen/blank
        // frame while disconnected/reconnecting — it reappears on the next touch of a
        // live session (a fresh session starts with no established position).
        hide_touch_cursor();
    }
}

/// Hide the local touch-cursor overlay. Used on teardown/disconnect; the overlay is
/// otherwise only driven by touch, so nothing would clear it while reconnecting.
fn hide_touch_cursor() {
    if let Some(el) = web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.get_element_by_id("cursor"))
    {
        el.set_class_name("hidden");
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
    /// The host's connection password, remembered across reconnects (see
    /// [`Session::password`]).
    password: Rc<RefCell<Option<String>>>,
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
        password: Rc::new(RefCell::new(None)),
    });

    // Losing focus / backgrounding must NOT tear the session down — keeping a live
    // connection through a blur is the whole point on desktop (and stops mobile
    // browsers, which fire visibilitychange constantly, from cycling reconnects +
    // re-prompting the password). We act ONLY when the page (re)gains focus: if the
    // session isn't healthy by then, reconnect. A drop while hidden is handled by the
    // connection-state watcher, which defers its reconnect to the next foreground.
    {
        let app = app.clone();
        let document2 = document.clone();
        let cb = Closure::<dyn FnMut()>::new(move || {
            // Hidden → do nothing; leave the existing session running.
            if document2.hidden() {
                return;
            }
            // Became visible → reconnect ONLY if there's no healthy session.
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
        password: app.password.clone(),
        latency_timer: RefCell::new(None),
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

/// Pin video playback to the live edge. WebRTC playout latency creeps up over a
/// session — a network burst, or the phone being backgrounded and resumed, leaves
/// the jitter buffer full — and the browser doesn't reliably drain it, so the view
/// falls behind "live". We (1) ask the receiver to keep its buffer minimal, and
/// (2) sample the jitter-buffer delay once a second and, when it grows, play a
/// touch faster to *drain* the backlog and catch up — never dropping frames. The
/// hint is re-asserted every tick, so a background→resume self-heals within a second.
fn start_latency_control(session: &Rc<Session>, receiver: RtcRtpReceiver) {
    // ADAPTIVE jitter buffer. A fixed target of 0 gives the lowest latency on a good
    // link but starves (freezes) on a slow/jittery one, where a cushion is needed to
    // ride out late frames. So we keep the target small when playback is smooth and
    // GROW it whenever the video actually freezes (a whole second with no frames
    // played), then shrink it back once things settle — low latency when we can,
    // smoothness when we must.
    let buf_ms = Rc::new(Cell::new(80.0f64)); // current jitterBufferTarget, ms
    const FLOOR: f64 = 50.0;
    const CEIL: f64 = 1000.0;
    apply_jitter_target(&receiver, buf_ms.get());
    let Some(window) = web_sys::window() else {
        return;
    };
    let pc = session.pc.clone();
    let video = session.video.clone();
    // Previous cumulative (jitterBufferDelay, jitterBufferEmittedCount) so we can
    // derive the delay over just the last interval, not the lifetime average.
    let prev = Rc::new(RefCell::new((0.0_f64, 0.0_f64)));
    let cb = Closure::<dyn FnMut()>::new(move || {
        apply_jitter_target(&receiver, buf_ms.get());
        let pc = pc.clone();
        let video = video.clone();
        let prev = prev.clone();
        let buf_ms = buf_ms.clone();
        let receiver = receiver.clone();
        spawn_local(async move {
            let Ok(stats) = JsFuture::from(pc.get_stats()).await else {
                return;
            };
            let Some((jbd, jbe)) = inbound_video_jitter_totals(&stats) else {
                return;
            };
            let (pjbd, pjbe) = *prev.borrow();
            *prev.borrow_mut() = (jbd, jbe);
            let emitted = jbe - pjbe;
            if emitted <= 0.0 {
                // A whole second with no frames played = a freeze. Add a cushion and
                // apply it immediately so the buffer can refill instead of starving.
                let n = (buf_ms.get() + 250.0).min(CEIL);
                buf_ms.set(n);
                apply_jitter_target(&receiver, n);
                video.set_playback_rate(1.0);
                return;
            }
            let target_s = buf_ms.get() / 1000.0;
            let delay = (jbd - pjbd) / emitted; // avg playout delay, seconds
            let excess = delay - target_s; // lag beyond our cushion → catch this up
            // FAST-FORWARD: play faster to drain accumulated lag back toward live —
            // the further behind, the brisker (screen content tolerates a quick
            // catch-up). Rate hint helps on browsers that honour it for a MediaStream.
            let rate = if excess > 0.6 {
                1.35
            } else if excess > 0.30 {
                1.22
            } else if excess > 0.12 {
                1.10
            } else {
                1.0
            };
            if (video.playback_rate() - rate).abs() > 0.01 {
                video.set_playback_rate(rate);
            }
            // No freeze this second → the cushion isn't needed; shrink it toward the
            // floor PROPORTIONALLY (fast) so the browser drains the buffer back to
            // live within a few seconds. A real freeze re-grows it, so a jittery link
            // just settles at the smallest cushion that stays smooth. This shrink is
            // the primary catch-up on browsers that ignore playbackRate for a stream.
            buf_ms.set((FLOOR + (buf_ms.get() - FLOOR) * 0.55).max(FLOOR));
        });
    });
    if let Ok(id) = window
        .set_interval_with_callback_and_timeout_and_arguments_0(cb.as_ref().unchecked_ref(), 1000)
    {
        *session.latency_timer.borrow_mut() = Some(id);
    }
    cb.forget();
}

/// Set the receiver's playout/jitter-buffer target. Two property names for two eras:
/// `playoutDelayHint` (seconds, Chrome) and the spec `jitterBufferTarget`
/// (milliseconds, Chrome 114+ / Safari 17+). Set both; whichever the browser doesn't
/// know is ignored.
fn apply_jitter_target(receiver: &RtcRtpReceiver, target_ms: f64) {
    let r: &JsValue = receiver.as_ref();
    let _ = js_sys::Reflect::set(
        r,
        &JsValue::from_str("playoutDelayHint"),
        &JsValue::from_f64(target_ms / 1000.0),
    );
    let _ = js_sys::Reflect::set(
        r,
        &JsValue::from_str("jitterBufferTarget"),
        &JsValue::from_f64(target_ms),
    );
}

/// Cumulative `(jitterBufferDelay, jitterBufferEmittedCount)` of the inbound video
/// track from a `getStats` report. The caller diffs successive samples to get the
/// recent playout delay. `None` if the report has no inbound video yet.
fn inbound_video_jitter_totals(report: &JsValue) -> Option<(f64, f64)> {
    let iter = js_sys::try_iter(report).ok().flatten()?;
    for entry in iter {
        let Ok(entry) = entry else { continue };
        // Each entry is [id, statsObject]; we want the object at index 1.
        let val = js_sys::Array::from(&entry).get(1);
        let field = |name: &str| js_sys::Reflect::get(&val, &JsValue::from_str(name)).ok();
        if field("type").and_then(|v| v.as_string()).as_deref() != Some("inbound-rtp") {
            continue;
        }
        if field("kind").and_then(|v| v.as_string()).as_deref() != Some("video") {
            continue;
        }
        let jbd = field("jitterBufferDelay").and_then(|v| v.as_f64())?;
        let jbe = field("jitterBufferEmittedCount").and_then(|v| v.as_f64())?;
        return Some((jbd, jbe));
    }
    None
}

/// Attach ontrack / onicecandidate / ondatachannel / connectionstatechange.
fn wire_pc_callbacks(session: &Rc<Session>, app: &Rc<App>) {
    let pc = &session.pc;

    // Inbound video track → attach the MediaStream to the <video> element.
    {
        let video = session.video.clone();
        let session = session.clone();
        let cb = Closure::<dyn FnMut(RtcTrackEvent)>::new(move |ev: RtcTrackEvent| {
            let streams = ev.streams();
            if let Some(stream) = streams.get(0).dyn_ref::<MediaStream>() {
                video.set_src_object(Some(stream));
                let _ = video.play();
                set_status("connected");
                // Keep playback pinned to the live edge (low buffer + catch-up).
                start_latency_control(&session, ev.receiver());
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
                // Only auto-reconnect while the tab is FOREGROUND. A drop while hidden
                // (backgrounded/locked) is an intentional disconnect — stay down and
                // let the visibilitychange handler reconnect when it's foreground again.
                let hidden = web_sys::window()
                    .and_then(|w| w.document())
                    .is_some_and(|d| d.hidden());
                if hidden {
                    set_status("disconnected (backgrounded)");
                } else {
                    set_status("disconnected — reconnecting…");
                    schedule_reconnect(app.clone());
                }
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
                let hello = rmd_protocol::hello(
                    "web-viewer",
                    rmd_protocol::Role::Viewer,
                    rmd_protocol::FEATURE_CLIENT_CURSOR,
                );
                // Carry the remembered password so a reconnect re-authenticates
                // without re-prompting (and doesn't stall unauthorized).
                let hello = match s.password.borrow().as_ref() {
                    Some(pw) => rmd_protocol::with_password(hello, pw.clone()),
                    None => hello,
                };
                let _ = dc_open.send_with_u8_array(&rmd_protocol::encode(&hello));
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
        // Clone the channel + session so we can re-send a password-bearing Hello
        // and remember the password for reconnects.
        let dc_msg = dc.clone();
        let s = session.clone();
        let cb = Closure::<dyn FnMut(MessageEvent)>::new(move |ev: MessageEvent| {
            if let Ok(buf) = ev.data().dyn_into::<js_sys::ArrayBuffer>() {
                let bytes = js_sys::Uint8Array::new(&buf).to_vec();
                if let Ok(env) = rmd_protocol::decode(&bytes) {
                    if let Some(rmd_protocol::pb::envelope::Payload::HelloAck(ack)) = env.payload {
                        if ack.password_required {
                            // Host wants a connection password (or the remembered one
                            // was wrong): prompt, remember it (for reconnects), and
                            // re-send the Hello with it (not via the URL).
                            match prompt_password() {
                                Some(pw) => {
                                    *s.password.borrow_mut() = Some(pw.clone());
                                    let hello = rmd_protocol::with_password(
                                        rmd_protocol::hello(
                                            "web-viewer",
                                            rmd_protocol::Role::Viewer,
                                            rmd_protocol::FEATURE_CLIENT_CURSOR,
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

    // Pinch-zoom is done LOCALLY on the phone: an inline CSS transform on #zoomwrap
    // zooms + pans only the video (the header/#bar is a separate fixed element, so it
    // never moves — the keyboard/rotate controls stay reachable while zoomed). This
    // is instant (no host round-trip), and because it transforms an ancestor of the
    // <video>, the video's getBoundingClientRect already reflects the zoom, so the
    // existing pointer mapping (`norm`) stays correct with no reprojection.
    let doc = web_sys::window().and_then(|w| w.document());
    let zoomwrap = doc
        .as_ref()
        .and_then(|d| d.get_element_by_id("zoomwrap"))
        .and_then(|e| e.dyn_into::<web_sys::HtmlElement>().ok());
    let stage = doc
        .as_ref()
        .and_then(|d| d.get_element_by_id("stage"));
    // Apply the zoom transform (screen-space: screen = pan + scale·content, origin at
    // the wrap's top-left). Clears the transform entirely at 1× so the wrap stops
    // being a containing block and the rotated-view layout is unchanged.
    let apply_zoom = {
        let zoomwrap = zoomwrap.clone();
        move |s: f64, tx: f64, ty: f64| {
            if let Some(z) = &zoomwrap {
                if s <= 1.0001 {
                    let _ = z.style().set_property("transform", "");
                } else {
                    let _ = z.style().set_property(
                        "transform",
                        &format!("translate({tx}px,{ty}px) scale({s})"),
                    );
                }
            }
        }
    };

    // Record the time of the last touch so the mouse handlers can ignore the
    // browser's synthesized compatibility mouse events after a touch — a "ghost
    // click" guard. Real (desktop) mouse input has `last_touch == 0`, far in the
    // past, so it's unaffected.
    let last_touch = Rc::new(Cell::new(0.0f64));

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
    // Rotate a screen-space delta (px) into host space for the current `data-rot`.
    // Scroll/wheel deltas need the same rotation `norm` applies to positions — it's
    // `norm`'s linear part (the inverse of CSS `rotate(rot*90deg)` clockwise) —
    // otherwise a swipe/scroll in a rotated (e.g. landscape) view moves the wrong
    // axis. Portrait (`rot` 0) is the identity, which is why it already felt right.
    let rot_delta = {
        let video = video.clone();
        move |dx: f64, dy: f64| -> (f64, f64) {
            match video.get_attribute("data-rot").as_deref() {
                Some("1") => (dy, -dx),
                Some("2") => (-dx, -dy),
                Some("3") => (-dy, dx),
                _ => (dx, dy),
            }
        }
    };

    // mousemove
    {
        let dc = dc.clone();
        let rect_norm = rect_norm.clone();
        let last_touch = last_touch.clone();
        let cb = Closure::<dyn FnMut(MouseEvent)>::new(move |ev: MouseEvent| {
            if is_ghost_mouse(&last_touch) {
                return; // synthesized from a touch — the touch handler owns it
            }
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
        let last_touch = last_touch.clone();
        let cb = Closure::<dyn FnMut(MouseEvent)>::new(move |ev: MouseEvent| {
            if is_ghost_mouse(&last_touch) {
                return;
            }
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
    // Touch = trackpad semantics, branching on the current finger count. The app
    // now owns EVERY touch (we `preventDefault` all branches; the browser never
    // pinch-zooms or scrolls the page — see `touch-action:none` on #screen):
    //   • one-finger tap                → LEFT-click at the cursor's location
    //   • one-finger press+drag         → move the cursor by the finger's delta
    //   • one-finger long-press / double-tap-hold, then drag → DRAG-SELECT: hold
    //       the left button down through the move (mode via `data-dragmode`)
    //   • two-finger QUICK tap          → RIGHT-click at the cursor's location
    //   • two-finger pinch + drag       → LOCAL zoom + pan of the video only (a CSS
    //       transform on #zoomwrap; the header stays put, zero round-trip lag)
    //   • three-finger swipe            → wheel scroll (content follows fingers)
    //
    // The host moves/clicks AT the coords it's sent (absolute), so we keep a
    // virtual cursor here, add each finger delta into it (clamped to [0,1]), and
    // send that — never the raw finger point. The move delta is taken through
    // `norm`, whose origin cancels in the difference, so rotation + scaling are
    // handled for free. We track the PRIMARY touch (`touches[0]`) and reset the
    // delta anchor whenever the finger set changes, so adding/removing a finger
    // doesn't fling the cursor.
    //
    // Zoom is a persistent screen-space transform on #zoomwrap (`translate scale`),
    // so it's instant and, because it transforms an ancestor of the <video>, the
    // video's getBoundingClientRect already reflects it — `norm` needs no change and
    // cursor deltas get finer with zoom for free. The host streams the full frame
    // (no crop); we don't send SetZoom in this mode.
    {
        const SENS: f64 = 1.0; // finger→cursor gain; 1.0 = comparable distance
        const SCROLL_SENS: f64 = 3.0; // finger px → wheel px (amplified; 1:1 felt sluggish)
        const TAP_MS: f64 = 300.0; // max press time for a two-finger tap = right-click
        const LONGPRESS_MS: i32 = 400; // press-and-hold time to arm a drag-select
        const DOUBLE_TAP_MS: f64 = 300.0; // max gap for double-tap-hold to arm a drag
        const MAX_ZOOM: f64 = 8.0; // local zoom cap
        let moved = Rc::new(Cell::new(false)); // did this gesture cross the drag threshold?
        let start = Rc::new(Cell::new((0.0f64, 0.0f64))); // first-finger client px (threshold anchor)
        let start_ms = Rc::new(Cell::new(0.0f64)); // gesture start time (for the tap window)
        let prev = Rc::new(Cell::new((0.0f64, 0.0f64))); // previous primary-touch client px (delta anchor)
        let cursor = Rc::new(Cell::new((0.5f64, 0.5f64))); // virtual cursor, normalized
        let has_pos = Rc::new(Cell::new(false)); // has the cursor position been established?
        let max_fingers = Rc::new(Cell::new(0u32)); // most fingers down at once this gesture
        let finger_down = Rc::new(Cell::new(false)); // is at least one finger currently down?
        let dragging = Rc::new(Cell::new(false)); // is drag-select holding the left button?
        let last_tap_ms = Rc::new(Cell::new(0.0f64)); // time of the last clean 1-finger tap (double-tap)
        let lp_handle = Rc::new(Cell::new(None::<i32>)); // pending long-press timeout id
        // Persistent local zoom transform (survives across gestures until changed).
        // Screen-space: content→screen is `screen = pan + scale·content` in stage-
        // local px (the #zoomwrap CSS transform), so the video's bounding rect
        // reflects it and pointer mapping needs no reprojection.
        let scale = Rc::new(Cell::new(1.0f64)); // ≥1; 1 = no zoom
        let pan = Rc::new(Cell::new((0.0f64, 0.0f64))); // translate (tx,ty) in stage-local px
        let pinch_dist = Rc::new(Cell::new(0.0f64)); // previous two-finger distance (0 = not pinching)
        let pinch_cen = Rc::new(Cell::new((0.0f64, 0.0f64))); // previous two-finger centroid (client px)

        // Draw the local touch cursor at the virtual cursor's on-screen point — the
        // inverse of `norm()` (re-rotate for `data-rot`, then to viewport px via the
        // video's live bounding rect, which already includes the zoom transform). Only
        // shown once a touch established a position (`has_pos`); desktop uses the native
        // pointer. Called after every position/zoom change (all happen on touchmove/end).
        let place_cursor: Rc<dyn Fn()> = {
            let video = video.clone();
            let cursor = cursor.clone();
            let has_pos = has_pos.clone();
            let el = web_sys::window()
                .and_then(|w| w.document())
                .and_then(|d| d.get_element_by_id("cursor"))
                .and_then(|e| e.dyn_into::<web_sys::HtmlElement>().ok());
            Rc::new(move || {
                let Some(el) = el.as_ref() else { return };
                if !has_pos.get() {
                    el.set_class_name("hidden");
                    return;
                }
                let (nx, ny) = cursor.get();
                let rect = video.get_bounding_client_rect();
                let w = rect.width().max(1.0);
                let h = rect.height().max(1.0);
                // Re-rotate the normalized point back to box coords, and rotate the
                // arrow itself by the same amount so it matches the video orientation
                // (the video is rotated `rot*90°` clockwise). Pivot is the tip (2,1),
                // set via CSS transform-origin, so the tip stays on the target point.
                let (bx, by, deg) = match video.get_attribute("data-rot").as_deref() {
                    Some("1") => (1.0 - ny, nx, 90),
                    Some("2") => (1.0 - nx, 1.0 - ny, 180),
                    Some("3") => (ny, 1.0 - nx, 270),
                    _ => (nx, ny, 0),
                };
                let x = rect.left() + bx * w - 1.5;
                let y = rect.top() + by * h - 0.8;
                let _ = el.style().set_property(
                    "transform",
                    &format!("translate({x:.1}px,{y:.1}px) rotate({deg}deg)"),
                );
                el.set_class_name("");
            })
        };

        // Re-orient the cursor when the view rotates. The rotate control (page UI) sets
        // `data-rot` + a CSS transform that transitions over ~0.2s; nothing else re-runs
        // `place_cursor` until the next touch, so the arrow wouldn't re-rotate on its own.
        // `transitionstart` fixes the angle immediately (data-rot is already set),
        // `transitionend` finalizes the on-screen position once the video settles.
        {
            let place_cursor = place_cursor.clone();
            let cb = Closure::<dyn FnMut(web_sys::Event)>::new(move |_e: web_sys::Event| {
                place_cursor();
            });
            for name in ["transitionstart", "transitionend"] {
                let _ = video.add_event_listener_with_callback(name, cb.as_ref().unchecked_ref());
            }
            cb.forget();
        }

        // Snapshot the primary touch's client-px position, if any.
        fn primary(ev: &TouchEvent) -> Option<(f64, f64)> {
            ev.touches()
                .get(0)
                .map(|t| (t.client_x() as f64, t.client_y() as f64))
        }
        // Both touch points' client-px positions, if a second finger is present.
        fn two_points(ev: &TouchEvent) -> Option<((f64, f64), (f64, f64))> {
            let t = ev.touches();
            let a = t.get(0)?;
            let b = t.get(1)?;
            Some((
                (a.client_x() as f64, a.client_y() as f64),
                (b.client_x() as f64, b.client_y() as f64),
            ))
        }

        // Long-press timer target, reused across presses. Fires only if a single
        // finger is still down, hasn't moved, and isn't already dragging → arms a
        // drag-select by pressing the left button at the virtual cursor (or, cold,
        // at the press point like a tap does).
        let lp_fn: Rc<js_sys::Function> = {
            let (dc, norm, cursor, dragging, finger_down, moved, max_fingers, has_pos, start, lp_handle) = (
                dc.clone(),
                norm.clone(),
                cursor.clone(),
                dragging.clone(),
                finger_down.clone(),
                moved.clone(),
                max_fingers.clone(),
                has_pos.clone(),
                start.clone(),
                lp_handle.clone(),
            );
            let c = Closure::<dyn FnMut()>::new(move || {
                lp_handle.set(None);
                if !(finger_down.get() && !moved.get() && max_fingers.get() == 1 && !dragging.get()) {
                    return;
                }
                let (x, y) = if has_pos.get() {
                    cursor.get()
                } else {
                    let (sx, sy) = start.get();
                    let p = norm(sx, sy);
                    cursor.set(p);
                    has_pos.set(true);
                    p
                };
                let _ = dc.send_with_u8_array(&input::mouse_button(0, true, x, y));
                dragging.set(true);
            });
            let f = c.as_ref().unchecked_ref::<js_sys::Function>().clone();
            c.forget();
            Rc::new(f)
        };

        // touchstart: (re)anchor the delta to the primary touch, track the peak
        // finger count, arm drag-select (1 finger) or baseline the pinch (2), and
        // preventDefault (the app owns every touch now).
        {
            let dc = dc.clone();
            let vidattr = video.clone();
            let moved = moved.clone();
            let start = start.clone();
            let start_ms = start_ms.clone();
            let prev = prev.clone();
            let max_fingers = max_fingers.clone();
            let last_touch = last_touch.clone();
            let finger_down = finger_down.clone();
            let dragging = dragging.clone();
            let last_tap_ms = last_tap_ms.clone();
            let lp_handle = lp_handle.clone();
            let lp_fn = lp_fn.clone();
            let pinch_dist = pinch_dist.clone();
            let pinch_cen = pinch_cen.clone();
            let cursor = cursor.clone();
            let has_pos = has_pos.clone();
            let cb = Closure::<dyn FnMut(TouchEvent)>::new(move |ev: TouchEvent| {
                ev.prevent_default();
                last_touch.set(now_ms());
                let n = ev.touches().length();
                // Fresh gesture (first finger of a new touch sequence): clear the
                // drag flag so a stale drag from the previous gesture can't suppress
                // this one's tap/right-click (fingers may land simultaneously, so
                // this can't live only in the n==1 branch below).
                if !finger_down.get() {
                    moved.set(false);
                }
                if n > max_fingers.get() {
                    max_fingers.set(n);
                }
                finger_down.set(true);
                // A second finger means "zoom", not drag: cancel a pending long-press
                // and release any in-progress drag-select, then baseline the pinch.
                if n >= 2 {
                    clear_lp(&lp_handle);
                    if dragging.get() {
                        let (x, y) = cursor.get();
                        let _ = dc.send_with_u8_array(&input::mouse_button(0, false, x, y));
                        dragging.set(false);
                    }
                    if let Some((a, b)) = two_points(&ev) {
                        pinch_dist.set((a.0 - b.0).hypot(a.1 - b.1).max(1.0));
                        pinch_cen.set(((a.0 + b.0) / 2.0, (a.1 + b.1) / 2.0));
                    }
                }
                if let Some(p) = primary(&ev) {
                    prev.set(p); // re-anchor so the new finger doesn't fling
                    if n == 1 {
                        start.set(p);
                        start_ms.set(now_ms());
                        moved.set(false);
                        // Arm drag-select per the client's selected mode.
                        let doubletap =
                            vidattr.dataset().get("dragmode").as_deref() == Some("doubletap");
                        if doubletap {
                            // A held second tap within the window starts a drag now.
                            if now_ms() - last_tap_ms.get() < DOUBLE_TAP_MS
                                && has_pos.get()
                                && !dragging.get()
                            {
                                let (x, y) = cursor.get();
                                let _ = dc.send_with_u8_array(&input::mouse_button(0, true, x, y));
                                dragging.set(true);
                            }
                        } else {
                            arm_lp(&lp_handle, &lp_fn, LONGPRESS_MS);
                        }
                    }
                }
            });
            video
                .add_event_listener_with_callback("touchstart", cb.as_ref().unchecked_ref())
                .ok();
            cb.forget();
        }
        // touchmove: branch on the CURRENT finger count — 1 = move cursor by delta
        // (button held if drag-selecting), 2 = host zoom + pan, 3+ = wheel scroll.
        // All branches preventDefault (the app owns every touch). A move past the
        // threshold marks the gesture a drag (so touchend won't click) and cancels a
        // pending long-press.
        {
            let dc = dc.clone();
            let norm = norm.clone();
            let rot_delta = rot_delta.clone();
            let moved = moved.clone();
            let start = start.clone();
            let prev = prev.clone();
            let cursor = cursor.clone();
            let has_pos = has_pos.clone();
            let last_touch = last_touch.clone();
            let lp_handle = lp_handle.clone();
            let scale = scale.clone();
            let pan = pan.clone();
            let pinch_dist = pinch_dist.clone();
            let pinch_cen = pinch_cen.clone();
            let stage = stage.clone();
            let apply_zoom = apply_zoom.clone();
            let place_cursor = place_cursor.clone();
            let max_fingers = max_fingers.clone();
            let cb = Closure::<dyn FnMut(TouchEvent)>::new(move |ev: TouchEvent| {
                ev.prevent_default();
                last_touch.set(now_ms());
                let n = ev.touches().length();
                // A gesture that has ever had 3+ fingers is a scroll, not a pinch. Skip
                // the pinch math on its transient 2-finger phases (fingers land/lift one
                // at a time) — otherwise `s = s0 * dist/pinch_dist` runs against a stale
                // baseline and lurches the zoom/pan. Just re-baseline and let it scroll.
                if n == 2 && max_fingers.get() >= 3 {
                    pinch_dist.set(0.0);
                    return;
                }
                if n == 2 {
                    // Two-finger pinch: LOCAL zoom+pan of the video, screen-space. The
                    // grabbed content point (under the previous centroid) is moved to
                    // the new centroid at the new scale — one formula handles both
                    // zoom and pan. `screen = pan + scale·content` (origin = stage
                    // top-left), so centroids are in stage-local px.
                    let Some((a, b)) = two_points(&ev) else {
                        return;
                    };
                    let dist = (a.0 - b.0).hypot(a.1 - b.1).max(1.0);
                    let (ox, oy) = stage
                        .as_ref()
                        .map(|s| {
                            let r = s.get_bounding_client_rect();
                            (r.left(), r.top())
                        })
                        .unwrap_or((0.0, 0.0));
                    let cen = ((a.0 + b.0) / 2.0, (a.1 + b.1) / 2.0); // client px
                    let pd = pinch_dist.get();
                    if pd <= 0.0 {
                        pinch_dist.set(dist);
                        pinch_cen.set(cen);
                        return;
                    }
                    moved.set(true); // a pinch is never a right-click tap
                    let s0 = scale.get();
                    let s = (s0 * (dist / pd)).clamp(1.0, MAX_ZOOM);
                    let (tx0, ty0) = pan.get();
                    // Stage-local centroids (current + previous).
                    let (cx, cy) = (cen.0 - ox, cen.1 - oy);
                    let pcen = pinch_cen.get();
                    let (pcx, pcy) = (pcen.0 - ox, pcen.1 - oy);
                    // Content grabbed at the previous centroid: q = (prevScreen - t0)/s0.
                    let qx = (pcx - tx0) / s0;
                    let qy = (pcy - ty0) / s0;
                    // Put it under the new centroid at the new scale: t = c - s·q.
                    let (tx, ty) = (cx - s * qx, cy - s * qy);
                    scale.set(s);
                    pan.set((tx, ty));
                    pinch_dist.set(dist);
                    pinch_cen.set(cen);
                    apply_zoom(s, tx, ty);
                    place_cursor(); // the zoom moved the cursor's on-screen point
                    return;
                }
                let Some((cx, cy)) = primary(&ev) else {
                    return;
                };
                let (px, py) = prev.get();
                prev.set((cx, cy));
                let (sx, sy) = start.get();
                if (cx - sx).hypot(cy - sy) > 8.0 && !moved.get() {
                    moved.set(true);
                    clear_lp(&lp_handle); // a moving finger isn't a long-press
                }
                if n >= 3 {
                    // Three-finger swipe → wheel scroll. Content follows the fingers
                    // (drag down → content down), rotated into host space so it's
                    // correct in a landscape/rotated view (not just portrait).
                    let (dx, dy) =
                        rot_delta((cx - px) * SCROLL_SENS, (cy - py) * SCROLL_SENS);
                    if dx != 0.0 || dy != 0.0 {
                        let _ = dc.send_with_u8_array(&input::mouse_scroll(dx, dy));
                    }
                } else if n <= 1 {
                    // Normalized (un-rotated) finger delta: `norm` is affine, so the
                    // origin cancels and only the displacement survives. The host has
                    // the button down if we're drag-selecting, so this drags.
                    let (nx, ny) = norm(cx, cy);
                    let (npx, npy) = norm(px, py);
                    let (mut ux, mut uy) = cursor.get();
                    ux = (ux + (nx - npx) * SENS).clamp(0.0, 1.0);
                    uy = (uy + (ny - npy) * SENS).clamp(0.0, 1.0);
                    cursor.set((ux, uy));
                    has_pos.set(true);
                    let _ = dc.send_with_u8_array(&input::mouse_move(ux, uy));
                    place_cursor();
                }
            });
            video
                .add_event_listener_with_callback("touchmove", cb.as_ref().unchecked_ref())
                .ok();
            cb.forget();
        }
        // touchend: while fingers remain, re-anchor + drop the pinch baseline. On the
        // LAST lift: release a drag-select if one is held; else a tap (never dragged)
        // clicks at the virtual cursor — left for one finger, right for a QUICK two-
        // finger tap (a longer two-finger press was a pinch). A clean 1-finger tap is
        // recorded for double-tap-hold. Cold start: fall back to the tap point.
        {
            let dc = dc.clone();
            let norm = norm.clone();
            let moved = moved.clone();
            let start_ms = start_ms.clone();
            let prev = prev.clone();
            let cursor = cursor.clone();
            let has_pos = has_pos.clone();
            let max_fingers = max_fingers.clone();
            let last_touch = last_touch.clone();
            let finger_down = finger_down.clone();
            let dragging = dragging.clone();
            let last_tap_ms = last_tap_ms.clone();
            let lp_handle = lp_handle.clone();
            let pinch_dist = pinch_dist.clone();
            let scale = scale.clone();
            let pan = pan.clone();
            let apply_zoom = apply_zoom.clone();
            let place_cursor = place_cursor.clone();
            let cb = Closure::<dyn FnMut(TouchEvent)>::new(move |ev: TouchEvent| {
                last_touch.set(now_ms());
                if let Some(p) = primary(&ev) {
                    prev.set(p); // a finger lifted but others remain — re-anchor
                    pinch_dist.set(0.0); // re-baseline the pinch on the next 2-finger move
                    return;
                }
                // Last finger up.
                finger_down.set(false);
                clear_lp(&lp_handle);
                let fingers = max_fingers.get();
                let dragged = moved.get();
                let quick = now_ms() - start_ms.get() < TAP_MS;
                max_fingers.set(0); // reset for the next gesture
                pinch_dist.set(0.0);
                // Pinched (nearly) all the way back out → snap to 1× and clear the
                // transform so the wrap stops being a containing block.
                if scale.get() <= 1.0001 {
                    scale.set(1.0);
                    pan.set((0.0, 0.0));
                    apply_zoom(1.0, 0.0, 0.0);
                    place_cursor(); // zoom reset moved the cursor's on-screen point
                }
                // Release a held drag-select — this is a button-up, not a click.
                if dragging.get() {
                    let (x, y) = cursor.get();
                    let _ = dc.send_with_u8_array(&input::mouse_button(0, false, x, y));
                    dragging.set(false);
                    return;
                }
                if dragged {
                    return; // it was a drag/swipe/pinch, not a tap
                }
                // 1 finger → left-click; 2 fingers → right-click but only for a
                // quick tap (else it was a pinch/hold — leave it alone). 3+ → nothing.
                let btn = match fingers {
                    1 => input::dom_button_to_proto(0),
                    2 if quick => input::dom_button_to_proto(2),
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
                place_cursor(); // show the cursor at the tap point (cold start) / current pos
                // A clean 1-finger tap arms double-tap-hold.
                if fingers == 1 {
                    last_tap_ms.set(now_ms());
                }
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
        let rot_delta = rot_delta.clone();
        let cb = Closure::<dyn FnMut(WheelEvent)>::new(move |ev: WheelEvent| {
            ev.prevent_default();
            let (dx, dy) = rot_delta(-ev.delta_x(), -ev.delta_y());
            let _ = dc.send_with_u8_array(&input::mouse_scroll(dx, dy));
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
                    // Physical/Bluetooth keyboard path (the on-screen keyboard sends
                    // HID directly via `attach_keyboard`).
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

    attach_keyboard(dc);
}

/// Cancel a pending long-press timer (if any) and clear its handle.
fn clear_lp(handle: &Cell<Option<i32>>) {
    if let (Some(id), Some(w)) = (handle.get(), web_sys::window()) {
        w.clear_timeout_with_handle(id);
    }
    handle.set(None);
}

/// (Re)arm the long-press timer to fire `f` after `ms`.
fn arm_lp(handle: &Cell<Option<i32>>, f: &js_sys::Function, ms: i32) {
    clear_lp(handle);
    if let Some(w) = web_sys::window() {
        if let Ok(id) = w.set_timeout_with_callback_and_timeout_and_arguments_0(f, ms) {
            handle.set(Some(id));
        }
    }
}

/// Current high-res time in ms (`performance.now()`); 0.0 if unavailable.
fn now_ms() -> f64 {
    web_sys::window()
        .and_then(|w| w.performance())
        .map(|p| p.now())
        .unwrap_or(0.0)
}

/// Whether a mouse event is a browser-synthesized "ghost" event just after a
/// touch (within 700ms) — the touch handlers already produced the real input, so
/// the mouse handlers must ignore it. We now `preventDefault` every touch, which
/// suppresses most of these compatibility events, but the guard stays as a
/// belt-and-suspenders against browsers that still emit them.
fn is_ghost_mouse(last_touch: &Rc<Cell<f64>>) -> bool {
    now_ms() - last_touch.get() < 700.0
}

/// Wire the custom on-screen keyboard (`#kb`, built in index.html). Each `.k`
/// button sends HID over `dc` on pointerdown. Sticky modifiers (`data-mod`)
/// accumulate + highlight until the next non-modifier key, which sends with the
/// armed mods then clears — so Ctrl then C = Ctrl+C, unsticking after. Character
/// keys (`data-char`) map via char→HID; `data-code` via `KeyboardEvent.code`→HID;
/// `data-combo` is a chord (Ctrl-Alt-Del). The `?123` layer toggle (`data-layer`)
/// is presentation and handled in JS — ignored here.
fn attach_keyboard(dc: &RtcDataChannel) {
    let Some(document) = web_sys::window().and_then(|w| w.document()) else {
        return;
    };
    if document.get_element_by_id("kb").is_none() {
        return; // page has no keyboard UI — nothing to wire
    }

    // Armed sticky modifiers (a `rmd_protocol::modifiers` bitmask). Shift here is
    // ONE-SHOT — it applies to the next letter, then `clear_mods` unsticks it.
    let mods = Rc::new(Cell::new(0u32));
    // Caps-lock: a separate, latched client-side toggle (not in `mods`, so it
    // survives `clear_mods`). While on, every letter is sent with Shift.
    let caps = Rc::new(Cell::new(false));

    // Clear the armed one-shot modifiers and un-highlight their buttons. Caps-lock
    // is NOT in `mods`, so it survives; the letter-case visual then reflects caps.
    let clear_mods: Rc<dyn Fn()> = {
        let mods = mods.clone();
        let caps = caps.clone();
        let document = document.clone();
        Rc::new(move || {
            mods.set(0);
            if let Ok(list) = document.query_selector_all("#kb [data-mod]") {
                for i in 0..list.length() {
                    if let Some(el) = list
                        .item(i)
                        .and_then(|n| n.dyn_into::<web_sys::Element>().ok())
                    {
                        let _ = el.class_list().remove_1("armed");
                    }
                }
            }
            set_letter_case(&document, caps.get());
        })
    };

    // Hold-to-repeat for non-modifier keys (character keys + named-code keys like
    // Backspace / arrows): after a short initial delay, holding the key resends it on
    // a fixed cadence, like a hardware keyboard's auto-repeat. Modifiers, caps-lock,
    // layer toggles and the Ctrl-Alt-Del combo never repeat. Only one key repeats at
    // a time; the interval and its closure are dropped on release, so nothing leaks.
    const REPEAT_TICK_MS: i32 = 55; // cadence once armed (~18 keys/s)
    const REPEAT_DELAY_TICKS: u32 = 7; // ticks before the first repeat (~385 ms)
    let rpt_handle: Rc<Cell<Option<i32>>> = Rc::new(Cell::new(None));
    let rpt_closure: Rc<RefCell<Option<Closure<dyn FnMut()>>>> = Rc::new(RefCell::new(None));
    let stop_repeat: Rc<dyn Fn()> = {
        let rpt_handle = rpt_handle.clone();
        let rpt_closure = rpt_closure.clone();
        Rc::new(move || {
            if let (Some(id), Some(w)) = (rpt_handle.take(), web_sys::window()) {
                w.clear_interval_with_handle(id);
            }
            rpt_closure.borrow_mut().take();
        })
    };
    let start_repeat: Rc<dyn Fn(u32, u32)> = {
        let dc = dc.clone();
        let rpt_handle = rpt_handle.clone();
        let rpt_closure = rpt_closure.clone();
        let stop_repeat = stop_repeat.clone();
        Rc::new(move |hid: u32, m: u32| {
            stop_repeat(); // only one key repeats at a time
            let Some(w) = web_sys::window() else {
                return;
            };
            let dc = dc.clone();
            let ticks = Cell::new(0u32);
            let cb = Closure::<dyn FnMut()>::new(move || {
                let n = ticks.get() + 1;
                ticks.set(n);
                if n >= REPEAT_DELAY_TICKS {
                    kb_send(&dc, hid, m);
                }
            });
            if let Ok(id) = w.set_interval_with_callback_and_timeout_and_arguments_0(
                cb.as_ref().unchecked_ref(),
                REPEAT_TICK_MS,
            ) {
                rpt_handle.set(Some(id));
            }
            *rpt_closure.borrow_mut() = Some(cb);
        })
    };
    // Any pointer release / cancel anywhere ends the current repeat.
    {
        let stop_repeat = stop_repeat.clone();
        let cb = Closure::<dyn FnMut(web_sys::Event)>::new(move |_e: web_sys::Event| stop_repeat());
        if let Some(w) = web_sys::window() {
            for ev in ["pointerup", "pointercancel"] {
                let _ = w.add_event_listener_with_callback(ev, cb.as_ref().unchecked_ref());
            }
        }
        cb.forget();
    }

    let Ok(btns) = document.query_selector_all("#kb .k") else {
        return;
    };
    for i in 0..btns.length() {
        let Some(el) = btns
            .item(i)
            .and_then(|n| n.dyn_into::<web_sys::Element>().ok())
        else {
            continue;
        };
        // Layer/page toggles (123↔ABC, ⇧ on a symbol page) are presentation only —
        // JS swaps the visible layer; the WASM layer ignores them.
        if el.get_attribute("data-layer").is_some() || el.get_attribute("data-page").is_some() {
            continue;
        }
        // QWERTY letter keys are owned by the swipe/tap handler below (so a swipe
        // doesn't type its first letter on touchdown); everything else taps here.
        if el.get_attribute("data-char").is_some()
            && el.closest(".klet").ok().flatten().is_some()
        {
            continue;
        }
        let dc = dc.clone();
        let mods = mods.clone();
        let caps = caps.clone();
        let clear = clear_mods.clone();
        let doc = document.clone();
        let el_cb = el.clone();
        let start_repeat = start_repeat.clone();
        let stop_repeat = stop_repeat.clone();
        let cb = Closure::<dyn FnMut(web_sys::Event)>::new(move |ev: web_sys::Event| {
            ev.prevent_default(); // no text selection / double-tap-zoom / synthetic mouse
            stop_repeat(); // a new press cancels any key still auto-repeating
            let send_key = |hid: u32, m: u32| {
                let _ = dc.send_with_u8_array(&input::key(hid, true, m));
                let _ = dc.send_with_u8_array(&input::key(hid, false, m));
            };
            // Caps-lock: latch the toggle + its highlight (does not clear mods).
            if el_cb.get_attribute("data-caps").is_some() {
                let on = !caps.get();
                caps.set(on);
                let _ = if on {
                    el_cb.class_list().add_1("armed")
                } else {
                    el_cb.class_list().remove_1("armed")
                };
                set_letter_case(&doc, on || (mods.get() & input::mod_bit("shift")) != 0);
                return;
            }
            if let Some(name) = el_cb.get_attribute("data-mod") {
                // Toggle this sticky modifier + its highlight.
                let bit = input::mod_bit(&name);
                let cur = mods.get();
                if cur & bit != 0 {
                    mods.set(cur & !bit);
                    let _ = el_cb.class_list().remove_1("armed");
                } else {
                    mods.set(cur | bit);
                    let _ = el_cb.class_list().add_1("armed");
                }
                // Uppercase the letter labels while a shift is pending.
                if name == "shift" {
                    set_letter_case(&doc, (mods.get() & bit) != 0 || caps.get());
                }
            } else if let Some(ch) = el_cb.get_attribute("data-char") {
                if let Some((hid, shift)) = ch.chars().next().and_then(input::char_to_hid) {
                    let m = if shift {
                        mods.get() | input::mod_bit("shift")
                    } else {
                        mods.get()
                    };
                    send_key(hid, m);
                    start_repeat(hid, m); // hold to repeat
                }
                clear();
                clear_suggestions(&doc);
            } else if let Some(combo) = el_cb.get_attribute("data-combo") {
                if combo == "ctrl-alt-del" {
                    send_key(0x4C, input::mod_bit("ctrl") | input::mod_bit("alt")); // Delete
                }
                clear();
                clear_suggestions(&doc);
            } else if let Some(code) = el_cb.get_attribute("data-code") {
                if let Some(hid) = input::code_to_hid(&code) {
                    let m = mods.get();
                    send_key(hid, m);
                    start_repeat(hid, m); // hold to repeat (e.g. Backspace, arrows)
                }
                clear();
                clear_suggestions(&doc);
            }
        });
        el.add_event_listener_with_callback("pointerdown", cb.as_ref().unchecked_ref())
            .ok();
        cb.forget();
    }

    attach_swipe(dc, &document, &mods, &clear_mods, &caps);
}

/// Toggle the `#kb.up` class so the letter labels render uppercase (via CSS
/// `text-transform`) while a shift is pending or caps-lock is on.
fn set_letter_case(document: &web_sys::Document, up: bool) {
    if let Some(kb) = document.get_element_by_id("kb") {
        let _ = kb.class_list().toggle_with_force("up", up);
    }
}

/// Empty the word-suggestion bar.
fn clear_suggestions(doc: &web_sys::Document) {
    if let Some(bar) = doc.get_element_by_id("kb-suggest") {
        bar.set_inner_html("");
    }
}

/// Send a HID key as a press+release with the given modifier bitmask.
fn kb_send(dc: &RtcDataChannel, hid: u32, mods: u32) {
    let _ = dc.send_with_u8_array(&input::key(hid, true, mods));
    let _ = dc.send_with_u8_array(&input::key(hid, false, mods));
}

/// Type a whole word (lowercase, char→HID) followed by a space.
fn kb_send_word(dc: &RtcDataChannel, word: &str, caps: bool) {
    for c in word.chars() {
        if let Some((hid, shift)) = input::char_to_hid(c) {
            kb_send(dc, hid, if shift || caps { input::mod_bit("shift") } else { 0 });
        }
    }
    kb_send(dc, 0x2C, 0); // trailing space
}

/// Read the 26 letter-key centres (client px, so rotation is baked in), indexed
/// by `letter - 'a'`. `None` if the QWERTY layer isn't rendered/ready.
fn read_letter_centers(doc: &web_sys::Document) -> Option<[(f64, f64); 26]> {
    let list = doc.query_selector_all("#kb .klet [data-char]").ok()?;
    let mut xy = [(f64::NAN, f64::NAN); 26];
    let mut filled = 0;
    for i in 0..list.length() {
        let Some(el) = list.item(i).and_then(|n| n.dyn_into::<web_sys::Element>().ok()) else {
            continue;
        };
        let Some(b) = el.get_attribute("data-char").and_then(|s| s.bytes().next()) else {
            continue;
        };
        if !b.is_ascii_lowercase() {
            continue;
        }
        let r = el.get_bounding_client_rect();
        xy[(b - b'a') as usize] = (r.left() + r.width() / 2.0, r.top() + r.height() / 2.0);
        filled += 1;
    }
    if filled < 20 {
        return None; // keyboard not laid out yet
    }
    for e in xy.iter_mut() {
        if e.0.is_nan() {
            *e = (0.0, 0.0);
        }
    }
    Some(xy)
}

/// Swipe (word-gesture) + tap input on the QWERTY layer. A stationary touch on a
/// letter types it; a drag across letters is decoded to a word (SHARK²-style, see
/// `swipe`), typed with a trailing space, and the top candidates are offered in
/// `#kb-suggest` — tapping one replaces the last word.
fn attach_swipe(
    dc: &RtcDataChannel,
    document: &web_sys::Document,
    mods: &Rc<Cell<u32>>,
    clear_mods: &Rc<dyn Fn()>,
    caps: &Rc<Cell<bool>>,
) {
    let Ok(Some(klet)) = document.query_selector(".klet") else {
        return;
    };
    let decoder = Rc::new(swipe::SwipeDecoder::new());
    let path: Rc<RefCell<Vec<(f64, f64)>>> = Rc::new(RefCell::new(Vec::new()));
    let tap_char: Rc<Cell<Option<char>>> = Rc::new(Cell::new(None));
    let last_word_len = Rc::new(Cell::new(0usize)); // chars+space of the last inserted word

    // touchstart: begin tracking only if the finger lands on a letter key.
    {
        let path = path.clone();
        let tap_char = tap_char.clone();
        let cb = Closure::<dyn FnMut(TouchEvent)>::new(move |ev: TouchEvent| {
            let ch = ev
                .target()
                .and_then(|t| t.dyn_into::<web_sys::Element>().ok())
                .and_then(|e| e.closest("[data-char]").ok().flatten())
                .and_then(|e| e.get_attribute("data-char"))
                .and_then(|s| s.chars().next());
            match ch {
                Some(c) => {
                    ev.prevent_default();
                    tap_char.set(Some(c));
                    let mut p = path.borrow_mut();
                    p.clear();
                    if let Some(t) = ev.touches().get(0) {
                        p.push((t.client_x() as f64, t.client_y() as f64));
                    }
                }
                None => tap_char.set(None), // e.g. shift/backspace — let the tap handler above run
            }
        });
        klet.add_event_listener_with_callback("touchstart", cb.as_ref().unchecked_ref())
            .ok();
        cb.forget();
    }
    // touchmove: accumulate the path while tracking a letter gesture.
    {
        let path = path.clone();
        let tap_char = tap_char.clone();
        let cb = Closure::<dyn FnMut(TouchEvent)>::new(move |ev: TouchEvent| {
            if tap_char.get().is_none() {
                return;
            }
            ev.prevent_default();
            if let Some(t) = ev.touches().get(0) {
                path.borrow_mut().push((t.client_x() as f64, t.client_y() as f64));
            }
        });
        klet.add_event_listener_with_callback("touchmove", cb.as_ref().unchecked_ref())
            .ok();
        cb.forget();
    }
    // touchend: classify tap vs swipe and act.
    {
        let dc = dc.clone();
        let document = document.clone();
        let mods = mods.clone();
        let caps = caps.clone();
        let clear = clear_mods.clone();
        let decoder = decoder.clone();
        let path = path.clone();
        let tap_char = tap_char.clone();
        let last_word_len = last_word_len.clone();
        let cb = Closure::<dyn FnMut(TouchEvent)>::new(move |ev: TouchEvent| {
            let Some(start_char) = tap_char.replace(None) else {
                return; // not a letter gesture
            };
            ev.prevent_default();
            let pts = std::mem::take(&mut *path.borrow_mut());
            let Some(centers) = read_letter_centers(&document) else {
                return;
            };

            // Distinct keys crossed + arc length distinguish a swipe from a tap.
            let key_w = {
                let q = centers[(b'q' - b'a') as usize];
                let w = centers[(b'w' - b'a') as usize];
                ((q.0 - w.0).powi(2) + (q.1 - w.1).powi(2)).sqrt().max(20.0)
            };
            let arc: f64 = pts
                .windows(2)
                .map(|w| ((w[0].0 - w[1].0).powi(2) + (w[0].1 - w[1].1).powi(2)).sqrt())
                .sum();
            let mut distinct = 0u32;
            let mut last = 255u8;
            for &p in &pts {
                let k = swipe::nearest_letter(p, &centers);
                if k != last {
                    distinct += 1;
                    last = k;
                }
            }
            let is_swipe = distinct >= 2 && arc > key_w * 1.2;

            if is_swipe {
                let words = decoder.decode(&pts, &centers, 5);
                if let Some(&best) = words.first() {
                    kb_send_word(&dc, best, caps.get());
                    last_word_len.set(best.len() + 1);
                    show_suggestions(&dc, &document, &words, &last_word_len, &caps);
                }
                clear(); // a completed word clears any armed modifier (not caps-lock)
            } else {
                // Tap: type the letter, honouring one-shot shift AND caps-lock.
                if let Some((hid, shift)) = input::char_to_hid(start_char) {
                    let m = if shift || caps.get() {
                        mods.get() | input::mod_bit("shift")
                    } else {
                        mods.get()
                    };
                    kb_send(&dc, hid, m);
                }
                clear();
                clear_suggestions(&document);
            }
        });
        klet.add_event_listener_with_callback("touchend", cb.as_ref().unchecked_ref())
            .ok();
        cb.forget();
    }
}

/// Populate `#kb-suggest` with the candidate words. Tapping one replaces the last
/// inserted word (backspace its chars+space, type the new word+space).
fn show_suggestions(
    dc: &RtcDataChannel,
    document: &web_sys::Document,
    words: &[&str],
    last_word_len: &Rc<Cell<usize>>,
    caps: &Rc<Cell<bool>>,
) {
    let Some(bar) = document.get_element_by_id("kb-suggest") else {
        return;
    };
    bar.set_inner_html("");
    for &w in words {
        let Ok(btn) = document.create_element("button") else {
            continue;
        };
        btn.set_class_name("sug");
        btn.set_text_content(Some(w));
        let dc = dc.clone();
        let word = w.to_string();
        let lwl = last_word_len.clone();
        let caps = caps.clone();
        let cb = Closure::<dyn FnMut(web_sys::Event)>::new(move |ev: web_sys::Event| {
            ev.prevent_default();
            for _ in 0..lwl.get() {
                kb_send(&dc, 0x2A, 0); // backspace the previously inserted word + space
            }
            kb_send_word(&dc, &word, caps.get());
            lwl.set(word.len() + 1);
        });
        btn.add_event_listener_with_callback("pointerdown", cb.as_ref().unchecked_ref())
            .ok();
        cb.forget();
        let _ = bar.append_child(&btn);
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
