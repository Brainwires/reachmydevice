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
use std::cell::RefCell;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::{spawn_local, JsFuture};
use web_sys::{
    HtmlCanvasElement, HtmlVideoElement, MediaStream, MessageEvent, MouseEvent, RtcConfiguration,
    RtcDataChannel, RtcDataChannelEvent, RtcIceCandidateInit, RtcPeerConnection,
    RtcPeerConnectionIceEvent, RtcSdpType, RtcSessionDescriptionInit, RtcTrackEvent, Response,
    WheelEvent,
};

/// Runtime configuration, from URL query params on the page:
/// `?server=wss://app.reachmy.dev&token=…&host=<device_id>`.
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

    // --- WebRTC peer connection (answerer) --------------------------------
    // Ask the rendezvous which ICE servers to use (STUN + TURN with ephemeral
    // credentials). Without a relay, a cross-NAT host won't connect.
    let rtc_cfg = RtcConfiguration::new();
    let ice = fetch_ice_servers(&window, &cfg.server, &cfg.token).await;
    rtc_cfg.set_ice_servers(&ice);
    let pc =
        RtcPeerConnection::new_with_configuration(&rtc_cfg).map_err(|e| format!("pc: {e:?}"))?;

    let relay = Relay::connect(&cfg.server, &cfg.token).map_err(|e| format!("ws: {e}"))?;

    let session = Rc::new(Session {
        pc: pc.clone(),
        relay: relay.clone(),
        host_id: cfg.host_id.clone(),
        control: RefCell::new(None),
        video: video.clone(),
        hello_sent: RefCell::new(false),
    });

    wire_pc_callbacks(&session);
    wire_relay_callbacks(&session);

    // Announce presence so the host learns our device id and sends its offer.
    relay.send_hello(&cfg.host_id);
    set_status("connecting…");
    Ok(())
}

/// Attach ontrack / onicecandidate / ondatachannel / connectionstatechange.
fn wire_pc_callbacks(session: &Rc<Session>) {
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

    // Surface connection-state changes.
    {
        let pc2 = pc.clone();
        let cb = Closure::<dyn FnMut()>::new(move || {
            let st = pc2.connection_state();
            web_sys::console::log_1(&format!("[rmd] pc state: {st:?}").into());
            if matches!(
                st,
                web_sys::RtcPeerConnectionState::Failed
                    | web_sys::RtcPeerConnectionState::Disconnected
            ) {
                set_status("disconnected");
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

    // Inbound control (HelloAck, DisplayList, Pong…) — logged for now.
    {
        let cb = Closure::<dyn FnMut(MessageEvent)>::new(move |ev: MessageEvent| {
            if let Ok(buf) = ev.data().dyn_into::<js_sys::ArrayBuffer>() {
                let bytes = js_sys::Uint8Array::new(&buf).to_vec();
                if let Ok(env) = rmd_protocol::decode(&bytes) {
                    if let Some(rmd_protocol::pb::envelope::Payload::HelloAck(ack)) = env.payload {
                        if !ack.accepted {
                            set_status(&format!("rejected: {}", ack.reason));
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

/// Attach mouse + keyboard listeners on the video surface; encode to protobuf and
/// send over the control channel.
fn attach_input(session: &Rc<Session>, dc: &RtcDataChannel) {
    let video = session.video.clone();

    // Normalized pointer position helper.
    let rect_norm = {
        let video = video.clone();
        move |ev: &MouseEvent| -> (f64, f64) {
            let rect = video.get_bounding_client_rect();
            let w = rect.width().max(1.0);
            let h = rect.height().max(1.0);
            // Position within the on-screen (possibly rotated) video box.
            let bx = (ev.client_x() as f64 - rect.left()) / w;
            let by = (ev.client_y() as f64 - rect.top()) / h;
            // Un-rotate to the host's source coordinates using the view's
            // quarter-turn count (`data-rot`, set by the rotate button). CSS
            // rotate(90deg) is clockwise; these are its inverses.
            match video.get_attribute("data-rot").as_deref() {
                Some("1") => (by, 1.0 - bx),
                Some("2") => (1.0 - bx, 1.0 - by),
                Some("3") => (1.0 - by, bx),
                _ => (bx, by),
            }
        }
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
