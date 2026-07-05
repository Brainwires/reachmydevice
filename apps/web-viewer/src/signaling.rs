//! Rendezvous `/ws` relay client (browser WebSocket).
//!
//! Mirrors the native `RendezvousClient` wire protocol exactly, so the server is
//! unchanged: connect to `{server}/ws?token=…`, then exchange
//! `{"to":…,"payload":{…}}` / `{"from":…,"payload":{…}}` frames where `payload`
//! is `{"kind":"hello"}` or `{"kind":"signal","msg":<SignalMsg>}`.

use crate::SignalMsg;
use std::cell::RefCell;
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{MessageEvent, WebSocket};

/// The relayed `payload`, tagged by `kind` — matches the native `Payload` enum.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum Payload {
    Hello,
    Signal { msg: SignalMsg },
}

#[derive(serde::Serialize)]
struct Outbound<'a> {
    to: &'a str,
    payload: Payload,
}

#[derive(serde::Deserialize)]
struct Inbound {
    #[allow(dead_code)]
    from: String,
    payload: Payload,
}

/// A cloneable handle to the relay WebSocket.
#[derive(Clone)]
pub struct Relay {
    ws: WebSocket,
    /// Signal handler, installed by `on_signal` and invoked from `onmessage`.
    on_signal: Rc<RefCell<Option<Box<dyn Fn(SignalMsg)>>>>,
}

impl Relay {
    /// Open the authenticated relay socket. The `onmessage` handler is wired here
    /// and dispatches signals to the closure registered via [`Relay::on_signal`].
    pub fn connect(server: &str, token: &str) -> Result<Relay, String> {
        let url = format!("{}/ws?token={}", server.trim_end_matches('/'), token);
        let ws = WebSocket::new(&url).map_err(|e| format!("WebSocket::new: {e:?}"))?;
        ws.set_binary_type(web_sys::BinaryType::Arraybuffer);

        let on_signal: Rc<RefCell<Option<Box<dyn Fn(SignalMsg)>>>> = Rc::new(RefCell::new(None));

        // Inbound relay frames → dispatch signals.
        {
            let on_signal = on_signal.clone();
            let cb = Closure::<dyn FnMut(MessageEvent)>::new(move |ev: MessageEvent| {
                let Some(text) = ev.data().as_string() else {
                    return;
                };
                let Ok(inbound) = serde_json::from_str::<Inbound>(&text) else {
                    web_sys::console::debug_1(&"[rmd] bad relay frame".into());
                    return;
                };
                if let Payload::Signal { msg } = inbound.payload {
                    if let Some(handler) = on_signal.borrow().as_ref() {
                        handler(msg);
                    }
                }
            });
            ws.set_onmessage(Some(cb.as_ref().unchecked_ref()));
            cb.forget();
        }

        // Log socket errors/close so failures are visible in the console.
        {
            let cb = Closure::<dyn FnMut(web_sys::Event)>::new(move |_| {
                web_sys::console::error_1(&"[rmd] relay socket error".into());
            });
            ws.set_onerror(Some(cb.as_ref().unchecked_ref()));
            cb.forget();
        }

        Ok(Relay { ws, on_signal })
    }

    /// Register the handler invoked for each inbound `SignalMsg`.
    pub fn on_signal<F: Fn(SignalMsg) + 'static>(&self, f: F) {
        *self.on_signal.borrow_mut() = Some(Box::new(f));
    }

    /// Announce presence so the host learns our device id (re-sent by the caller
    /// is unnecessary: the browser connects after the host is typically online,
    /// and the socket buffers until open).
    pub fn send_hello(&self, host_id: &str) {
        self.send_when_open(&Outbound {
            to: host_id,
            payload: Payload::Hello,
        });
    }

    /// Send a wrapped signaling message to the host.
    pub fn send_signal(&self, host_id: &str, msg: &SignalMsg) {
        self.send_when_open(&Outbound {
            to: host_id,
            payload: Payload::Signal { msg: msg.clone() },
        });
    }

    /// Serialize + send now if the socket is open, else once it opens.
    fn send_when_open<T: serde::Serialize>(&self, out: &T) {
        let Ok(text) = serde_json::to_string(out) else {
            return;
        };
        if self.ws.ready_state() == WebSocket::OPEN {
            let _ = self.ws.send_with_str(&text);
        } else {
            // Queue via an onopen one-shot.
            let ws = self.ws.clone();
            let text = text.clone();
            let cb = Closure::<dyn FnMut()>::new(move || {
                let _ = ws.send_with_str(&text);
            });
            // Chain: don't clobber a prior onopen — most sends happen post-open,
            // and the initial hello is the only pre-open send in practice.
            self.ws.set_onopen(Some(cb.as_ref().unchecked_ref()));
            cb.forget();
        }
    }
}
