//! Sans-IO WebRTC driver loop (runs on the transport thread).
//!
//! Owns the `rtci` `RTCPeerConnection`, the UDP socket, the H.264 RTP
//! packetizer/depacketizer, and the data channel, and pumps the sans-IO state
//! machine: drain [`DriverCmd`]s, `poll_write` → socket, socket → `handle_read`,
//! advance timers, drain `poll_event`/`poll_read` → [`TransportEvent`]s. Also
//! enables GCC (host) and publishes its target bitrate.
//!
//! # Roles
//!
//! - **Host** = offerer + video sender. Adds an H.264 send track and the
//!   reliable/ordered `control` data channel, creates the offer, and runs the
//!   default interceptor set (GCC congestion control + pacer + circuit breaker,
//!   fed by TWCC / RFC 8888 feedback).
//! - **Viewer** = answerer + video receiver. Adds a `recvonly` H.264
//!   transceiver, answers the offer, reassembles the incoming track into
//!   Annex-B access units, and uses the default interceptors (which include the
//!   TWCC *receiver* that feeds the host's GCC).
//!
//! Both roles use `rtci`'s default interceptor set, and `RTCPeerConnection` is
//! not generic over its chain, so each role builds its own `pc` and hands it to
//! the one shared [`event_loop`].

use crate::{
    DriverCmd, IceServer, SignalMsg, TransportConfig, TransportEvent, TransportRole, VideoCodec,
};
use anyhow::Context;
use bytes::{Bytes, BytesMut};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::time::{Duration, Instant};

use rtci::data_channel::{RTCDataChannelId, RTCDataChannelInit};
use rtci::ice::mdns::MulticastDnsMode;
use rtci::interceptor::{CongestionControlHandle, Registry};
use rtci::media::io::sample_builder::SampleBuilder;
use rtci::media_stream::MediaStreamTrack;
use rtci::peer_connection::configuration::RTCConfigurationBuilder;
use rtci::peer_connection::configuration::interceptor_registry::register_default_interceptors_with_handles;
use rtci::peer_connection::configuration::media_engine::{
    MIME_TYPE_AV1, MIME_TYPE_H264, MediaEngine,
};
use rtci::peer_connection::configuration::setting_engine::SettingEngineBuilder;
use rtci::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtci::peer_connection::message::RTCMessage;
use rtci::peer_connection::message::TaggedRTCMessage;
use rtci::peer_connection::sdp::RTCSessionDescription;
use rtci::peer_connection::srflx::ReflexiveGathering;
use rtci::peer_connection::state::RTCPeerConnectionState;
use rtci::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, CandidateRelayConfig, CandidateServerReflexiveConfig,
    RTCDtlsRole, RTCIceCandidate, RTCIceCandidateInit, RTCIceServer,
};
use rtci::peer_connection::turn_streams::RelayGathering;
use rtci::peer_connection::{RTCPeerConnection, RTCPeerConnectionBuilder};
use rtci::rtcp::payload_feedbacks::full_intra_request::FullIntraRequest;
use rtci::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use rtci::rtp::codec::h264::H264Packet;
use rtci::rtp::packetizer::{Packetizer, new_packetizer};
use rtci::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    RtpCodecKind,
};
use rtci::rtp_transceiver::{
    RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverInit, SSRC,
};
use rtci::sansio::Protocol;
use rtci::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use rtci::stun::addr::MappedAddress;
use rtci::stun::message::{BINDING_REQUEST, Getter, Message, TransactionId};
use rtci::stun::xoraddr::XorMappedAddress;
use rtci::turn::client::{
    Client as TurnClient, ClientConfig as TurnClientConfig, Event as TurnEvent,
};

/// Video RTP clock rate (Hz) — timestamps advance at 90 kHz for H.264 and AV1.
const VIDEO_CLOCK_RATE: u32 = 90_000;
/// H.264 dynamic payload type used on the wire.
const H264_PAYLOAD_TYPE: u8 = 102;
/// AV1 dynamic payload type used on the wire.
const AV1_PAYLOAD_TYPE: u8 = 41;
/// AV1 `sdp_fmtp_line` (main profile, level auto).
const AV1_FMTP: &str = "profile-id=0";
/// Outbound RTP MTU (bytes) for the packetizer, leaving headroom under 1500.
const RTP_OUTBOUND_MTU: usize = 1200;
/// `SampleBuilder` reorder window, in RTP sequence numbers.
const SAMPLE_BUILDER_MAX_LATE: u16 = 128;
/// Upper bound on how long a single socket read may block, so command and
/// timeout servicing stays responsive without busy-spinning.
const MAX_SOCKET_READ_WAIT: Duration = Duration::from_millis(5);
/// Safety valve for the sans-IO timer service. A due timer is normally fired and
/// the loop re-pumped immediately (so freshly generated outbound datagrams flush
/// without waiting on a read). But a handler stuck reporting an already-expired
/// deadline that `handle_timeout` cannot advance (e.g. a dead ICE/DTLS/SCTP timer
/// on a session that failed before it ever connected) would re-pump forever and
/// peg a core. After this many back-to-back immediate fires we stop short-cutting
/// and fall through to a bounded blocking read, so the loop can never busy-spin.
const MAX_CONSECUTIVE_REFIRES: u32 = 256;
/// `sdp_fmtp_line` announcing constrained-baseline, packetization-mode 1.
const H264_FMTP: &str = "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f";
/// Default STUN port (RFC 5389) when a `stun:` URL omits one.
const STUN_DEFAULT_PORT: u16 = 3478;
/// How long to wait for a single STUN Binding response before retrying.
const STUN_READ_TIMEOUT: Duration = Duration::from_millis(800);
/// How many times to (re)send a STUN Binding request before giving up.
const STUN_MAX_ATTEMPTS: usize = 3;

/// Run the driver loop until [`DriverCmd::Shutdown`] or the command channel closes.
pub(crate) fn run(
    config: TransportConfig,
    cmd_rx: Receiver<DriverCmd>,
    event_tx: Sender<TransportEvent>,
    bitrate_bps: Arc<AtomicU32>,
) -> anyhow::Result<()> {
    match config.role {
        TransportRole::Host => run_host(config, cmd_rx, event_tx, bitrate_bps),
        TransportRole::Viewer => run_viewer(config, cmd_rx, event_tx, bitrate_bps),
    }
}

/// The codec parameters shared by the send track and the RTP packetizer.
///
/// The fork's `RTCRtpCodec::payloader()` selects the payloader from the MIME
/// type, so switching this to AV1 auto-selects `Av1Payloader` — no packetizer
/// change needed. Both use the 90 kHz video clock.
fn codec_params(codec: VideoCodec) -> RTCRtpCodecParameters {
    let (mime_type, sdp_fmtp_line, payload_type) = match codec {
        VideoCodec::H264 => (MIME_TYPE_H264, H264_FMTP, H264_PAYLOAD_TYPE),
        VideoCodec::Av1 => (MIME_TYPE_AV1, AV1_FMTP, AV1_PAYLOAD_TYPE),
    };
    RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: mime_type.to_owned(),
            clock_rate: VIDEO_CLOCK_RATE,
            channels: 0,
            sdp_fmtp_line: sdp_fmtp_line.to_owned(),
            rtcp_feedback: vec![],
        },
        payload_type,
    }
}

/// Translate the app's ICE-server URL strings into `rtc`'s config type.
fn ice_servers(servers: &[IceServer]) -> Vec<RTCIceServer> {
    servers
        .iter()
        .filter(|s| !s.urls.is_empty())
        .map(|s| RTCIceServer {
            urls: s.urls.clone(),
            username: s.username.clone().unwrap_or_default(),
            credential: s.credential.clone().unwrap_or_default(),
        })
        .collect()
}

/// Bind the local UDP socket for the session and report its bound address.
fn bind_socket(bind_addr: SocketAddr) -> anyhow::Result<(UdpSocket, SocketAddr)> {
    let socket = UdpSocket::bind(bind_addr).context("bind transport UDP socket")?;
    let local_addr = socket.local_addr().context("read local addr")?;
    Ok((socket, local_addr))
}

/// Resolves the local address an inbound datagram arrived on.
///
/// rtci credits an inbound datagram to a local candidate only on an exact
/// address match (`rtci_ice::Agent::find_local_candidate`), so a socket bound to
/// a wildcard (`0.0.0.0`) can't report its own `local_addr` — that matches no
/// host candidate and the datagram is discarded. A plain `UdpSocket` doesn't
/// expose the destination IP (no `IP_PKTINFO`), so for a wildcard bind we use the
/// source IP the OS routes to that peer from (a connected probe socket's
/// `local_addr`), which is the interface the peer reaches us on for any
/// symmetric route. Cached per peer IP. A concrete bind reports itself.
struct LocalAddrResolver {
    bound: SocketAddr,
    by_peer: HashMap<IpAddr, SocketAddr>,
}

impl LocalAddrResolver {
    fn new(bound: SocketAddr) -> Self {
        Self {
            bound,
            by_peer: HashMap::new(),
        }
    }

    fn local_for(&mut self, peer: SocketAddr) -> SocketAddr {
        if !self.bound.ip().is_unspecified() {
            return self.bound;
        }
        let bound = self.bound;
        *self.by_peer.entry(peer.ip()).or_insert_with(|| {
            let probe_bind: SocketAddr = if peer.is_ipv4() {
                (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
            } else {
                (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
            };
            UdpSocket::bind(probe_bind)
                .and_then(|probe| {
                    probe.connect(peer)?;
                    probe.local_addr()
                })
                .map(|a| SocketAddr::new(a.ip(), bound.port()))
                .unwrap_or(bound)
        })
    }
}

/// Gather every local ICE candidate for the bound socket: a host candidate per
/// local interface plus a server-reflexive candidate per reachable STUN server.
///
/// Because the `rtc` engine is sans-IO it never gathers candidates itself — it
/// owns no socket. We do it here, once, on the *already-bound* UDP socket and
/// *before* the driver loop takes it over, so no STUN response can race with
/// live ICE traffic. Returned candidates are serialized `RTCIceCandidateInit`s
/// ready to `add_local_candidate` + trickle to the peer.
///
/// Gathering never fails the session: a down interface or an unanswered STUN
/// server is logged and skipped, so we always return at least the host
/// candidate(s) we can build.
fn gather_local_candidates(
    socket: &UdpSocket,
    local_addr: SocketAddr,
    ice_servers: &[IceServer],
) -> Vec<RTCIceCandidateInit> {
    let mut candidates = Vec::new();

    // Host candidates. A concrete bind (e.g. `127.0.0.1` or a LAN IP) is its
    // own single host candidate; a wildcard bind (`0.0.0.0`) expands to every
    // local IPv4 interface (loopback included, so same-host tests still
    // connect) since `0.0.0.0` itself is useless on the wire.
    for ip in host_candidate_ips(local_addr.ip()) {
        match build_host_candidate(ip, local_addr.port()) {
            Ok(init) => candidates.push(init),
            Err(e) => tracing::debug!("transport: skip host candidate {ip}: {e}"),
        }
    }

    // Server-reflexive candidates: one STUN Binding exchange per `stun:` URL
    // across every configured server.
    for url in ice_servers.iter().flat_map(|s| &s.urls) {
        let Some(host_port) = parse_stun_url(url) else {
            continue; // not a stun: URL (e.g. turn:) — handled by ICE, not here
        };
        match gather_srflx_candidate(socket, local_addr, &host_port, url) {
            Ok(Some(init)) => candidates.push(init),
            Ok(None) => tracing::debug!("transport: STUN {url} yielded no srflx candidate"),
            Err(e) => tracing::debug!("transport: STUN {url} gather failed: {e}"),
        }
    }

    candidates
}

/// The local IPv4 addresses to advertise as host candidates for a given bound
/// IP. A concrete, non-wildcard bind yields exactly that address; a wildcard
/// bind expands to every local IPv4 interface address (loopback included).
fn host_candidate_ips(bound_ip: IpAddr) -> Vec<IpAddr> {
    match bound_ip {
        IpAddr::V4(v4) if !v4.is_unspecified() => vec![IpAddr::V4(v4)],
        IpAddr::V6(v6) if !v6.is_unspecified() => vec![IpAddr::V6(v6)],
        // Wildcard bind: enumerate interfaces. We advertise IPv4 host
        // candidates (the transport binds IPv4); loopback is kept so that
        // loopback/same-host sessions still find a working pair.
        _ => match if_addrs::get_if_addrs() {
            Ok(ifaces) => ifaces
                .into_iter()
                .map(|iface| iface.ip())
                .filter(IpAddr::is_ipv4)
                .collect(),
            Err(e) => {
                tracing::debug!("transport: interface enumeration failed: {e}");
                Vec::new()
            }
        },
    }
}

/// Build a host ICE candidate at `ip:port`, serialized for signaling.
fn build_host_candidate(ip: IpAddr, port: u16) -> anyhow::Result<RTCIceCandidateInit> {
    let candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: ip.to_string(),
            port,
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()
    .context("build host candidate")?;
    RTCIceCandidate::from(&candidate)
        .to_json()
        .context("serialize host candidate")
}

/// Extract `host:port` from a `stun:`/`stuns:` URL, applying the default STUN
/// port when none is present. Returns `None` for non-STUN URLs (e.g. `turn:`).
fn parse_stun_url(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("stun:")
        .or_else(|| url.strip_prefix("stuns:"))?;
    // Drop any `?transport=...` query suffix.
    let rest = rest.split('?').next().unwrap_or(rest);
    if rest.contains(':') {
        Some(rest.to_owned()) // already host:port
    } else {
        Some(format!("{rest}:{STUN_DEFAULT_PORT}"))
    }
}

/// Discover our public (server-reflexive) mapping via one STUN Binding exchange
/// on the bound socket, and build the matching srflx candidate. Returns
/// `Ok(None)` when the server can't be resolved or never answers.
fn gather_srflx_candidate(
    socket: &UdpSocket,
    local_addr: SocketAddr,
    host_port: &str,
    url: &str,
) -> anyhow::Result<Option<RTCIceCandidateInit>> {
    // Resolve the STUN server to an address of the same family as our socket.
    let want_ipv4 = local_addr.is_ipv4();
    let server_addr = host_port
        .to_socket_addrs()
        .context("resolve STUN server")?
        .find(|a| a.is_ipv4() == want_ipv4);
    let Some(server_addr) = server_addr else {
        return Ok(None);
    };

    let Some(public_addr) = stun_binding_request(socket, server_addr)? else {
        return Ok(None);
    };

    // The srflx candidate's advertised address/port is our public mapping; its
    // related (base) address/port is the local bound socket it was gathered on.
    let candidate = CandidateServerReflexiveConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: public_addr.ip().to_string(),
            port: public_addr.port(),
            component: 1,
            ..Default::default()
        },
        rel_addr: local_addr.ip().to_string(),
        rel_port: local_addr.port(),
        url: Some(url.to_owned()),
    }
    .new_candidate_server_reflexive()
    .context("build srflx candidate")?;
    let init = RTCIceCandidate::from(&candidate)
        .to_json()
        .context("serialize srflx candidate")?;
    Ok(Some(init))
}

/// Send a STUN Binding request on `socket` to `server_addr` and return the
/// reflexive (public) address the server observed, or `Ok(None)` if it never
/// answered.
///
/// The exchange is a plain RFC 5389 Binding transaction: build a 20-byte
/// request (message type + magic cookie + a fresh 96-bit transaction id, no
/// attributes), send it, and read back a Binding success response carrying our
/// public `ip:port` in XOR-MAPPED-ADDRESS (or the legacy MAPPED-ADDRESS). We
/// retry a few times with a short read timeout to ride out packet loss.
fn stun_binding_request(
    socket: &UdpSocket,
    server_addr: SocketAddr,
) -> anyhow::Result<Option<SocketAddr>> {
    // Build the Binding request. `build` writes the serialized bytes into
    // `request.raw`; `TransactionId` is `Copy`, so we keep `txn` to match it
    // against the response below.
    let mut request = Message::new();
    let txn = TransactionId::new();
    request
        .build(&[Box::new(BINDING_REQUEST), Box::new(txn)])
        .context("build STUN binding request")?;

    socket
        .set_read_timeout(Some(STUN_READ_TIMEOUT))
        .context("set STUN read timeout")?;

    let mut buf = vec![0u8; 1500];
    for _ in 0..STUN_MAX_ATTEMPTS {
        if let Err(e) = socket.send_to(&request.raw, server_addr) {
            tracing::debug!("transport: STUN send_to error: {e}");
            continue;
        }

        // Await the response (bounded by the read timeout set above).
        let (n, from) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue; // no answer within the timeout — retry
            }
            Err(e) => return Err(anyhow::anyhow!("STUN recv_from: {e}")),
        };
        if from != server_addr {
            continue; // stray datagram from elsewhere — ignore
        }

        // Decode and confirm it answers *our* request, then read the mapping.
        let mut response = Message::new();
        if response.write(&buf[..n]).is_err() {
            continue; // not a well-formed STUN message
        }
        if response.transaction_id != txn {
            continue; // response to a different transaction
        }
        if let Some(addr) = mapped_address(&response) {
            return Ok(Some(addr));
        }
    }
    Ok(None)
}

/// Read the reflexive address out of a STUN Binding response, preferring
/// XOR-MAPPED-ADDRESS and falling back to the legacy MAPPED-ADDRESS.
fn mapped_address(response: &Message) -> Option<SocketAddr> {
    let mut xor = XorMappedAddress::default();
    if xor.get_from(response).is_ok() {
        return Some(SocketAddr::new(xor.ip, xor.port));
    }
    let mut plain = MappedAddress::default();
    if plain.get_from(response).is_ok() {
        return Some(SocketAddr::new(plain.ip, plain.port));
    }
    None
}

/// How long to wait for the TURN Allocate handshake (Allocate → 401 → auth
/// Allocate → success) before giving up and running relay-less.
const TURN_SETUP_TIMEOUT: Duration = Duration::from_secs(4);
/// How often an idle host retries a TURN allocation that failed at startup (most
/// often a 437 Allocation Mismatch: the previous process's allocation on the same
/// 5-tuple is still live on coturn until its lifetime runs out).
const TURN_RETRY_INTERVAL: Duration = Duration::from_secs(30);
/// Delay before the FIRST retry after a failed startup allocation. A restart's 437
/// is usually the predecessor's just-released allocation: coturn answers a Refresh
/// with lifetime 0 with success but only deletes the allocation after a 1 s timer
/// (`refresh_relay_connection` floors the lifetime to 1), so a retry a few seconds
/// later succeeds. Later retries fall back to [`TURN_RETRY_INTERVAL`].
const TURN_FIRST_RETRY: Duration = Duration::from_secs(3);
/// Upper bound on releasing the allocation (Refresh lifetime=0) at shutdown.
const TURN_RELEASE_TIMEOUT: Duration = Duration::from_secs(1);

/// A TURN relay allocation held on the *host's* transport socket, plus the
/// routing state that makes it transparent to the sans-IO `rtc` engine.
///
/// The engine has no TURN client, so on its own the host only ever advertises
/// `host` + `srflx` candidates — leaving a peer behind symmetric NAT / CGNAT with
/// no reachable path (its srflx mapping won't accept a relay's inbound). This
/// wraps the [`TurnClient`] and bridges it into the driver's single-socket loop:
/// we Allocate a relay on coturn, advertise a `relay` candidate, and then
/// transparently frame traffic to/from any peer that turns out to need the relay.
///
/// Routing follows the engine's own candidate choice: rtci tags every outbound
/// datagram with the local candidate address it is sent from, so a datagram from
/// the relay candidate (`relayed_addr`) is wrapped through coturn and everything
/// else goes straight out of the socket. Inbound relayed data is handed back
/// tagged with `relayed_addr` as its local address, so the ICE agent matches it to
/// the relay candidate (rtci discards datagrams whose local address is no known
/// candidate). Permissions are installed on coturn for every peer the engine
/// checks, so a symmetric-NAT peer's checks can bootstrap through our relay.
struct TurnRelay {
    client: TurnClient,
    /// coturn's address — inbound datagrams from here are TURN protocol, not peer
    /// media, and are demuxed to the client instead of the peer connection.
    server_addr: SocketAddr,
    /// Our allocated relayed transport address (advertised as the relay candidate).
    relayed_addr: SocketAddr,
    /// Peer IPs we've already asked coturn to permit (dedup CreatePermission).
    permitted: HashSet<IpAddr>,
}

/// Pick the first usable `turn:` server (URL + credentials) from the ICE list,
/// preferring UDP. Returns `(server "host:port", username, credential, url)`.
fn first_turn_server(ice_servers: &[IceServer]) -> Option<(String, String, String, String)> {
    for s in ice_servers {
        let (Some(username), Some(credential)) = (&s.username, &s.credential) else {
            continue;
        };
        if username.is_empty() || credential.is_empty() {
            continue;
        }
        // Prefer a UDP turn URL; fall back to any turn URL.
        let pick = s
            .urls
            .iter()
            .find(|u| u.starts_with("turn:") && u.contains("transport=udp"))
            .or_else(|| s.urls.iter().find(|u| u.starts_with("turn:")));
        if let Some(url) = pick {
            let rest = url.trim_start_matches("turn:");
            let host_port = rest.split('?').next().unwrap_or(rest).to_string();
            let host_port = if host_port.contains(':') {
                host_port
            } else {
                format!("{host_port}:{STUN_DEFAULT_PORT}")
            };
            return Some((host_port, username.clone(), credential.clone(), url.clone()));
        }
    }
    None
}

impl TurnRelay {
    /// Allocate a relay on coturn over `socket` and build the matching `relay`
    /// candidate. Drives the (blocking, bounded) Allocate handshake inline — the
    /// same socket the session will use, before the event loop owns it. Returns
    /// `None` (run relay-less, no regression) if there's no TURN server, the
    /// server can't be resolved, or the allocation doesn't complete in time.
    ///
    /// `first_attempt` picks the log level of a server rejection: warn at startup,
    /// debug on the idle retries that follow (see [`HostTurn`]).
    fn setup(
        socket: &UdpSocket,
        local_addr: SocketAddr,
        ice_servers: &[IceServer],
        first_attempt: bool,
    ) -> Option<(TurnRelay, RTCIceCandidateInit)> {
        let (server_str, username, credential, url) = first_turn_server(ice_servers)?;
        let want_ipv4 = local_addr.is_ipv4();
        let server_addr = server_str
            .to_socket_addrs()
            .ok()?
            .find(|a| a.is_ipv4() == want_ipv4)?;

        // realm is left empty: coturn returns it in the 401 challenge and the
        // client adopts it for the long-term MESSAGE-INTEGRITY key.
        let cfg = TurnClientConfig {
            stun_serv_addr: server_str.clone(),
            turn_serv_addr: server_str,
            local_addr,
            transport_protocol: TransportProtocol::UDP,
            username,
            password: credential,
            realm: String::new(),
            software: String::new(),
            rto_in_ms: 0,
            ..Default::default()
        };
        let crypto_provider = match rtci::crypto::default_provider() {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!("transport: TURN crypto provider unavailable: {e}");
                return None;
            }
        };
        let mut client = match TurnClient::new(cfg, crypto_provider) {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!("transport: TURN client init failed: {e}");
                return None;
            }
        };
        if let Err(e) = client.allocate(Instant::now()) {
            tracing::debug!("transport: TURN allocate() failed: {e}");
            return None;
        }

        let deadline = Instant::now() + TURN_SETUP_TIMEOUT;
        let mut buf = vec![0u8; 2048];
        let mut relayed_addr: Option<SocketAddr> = None;
        'drive: while Instant::now() < deadline {
            while let Some(t) = client.poll_write() {
                let _ = socket.send_to(&t.message, t.transport.peer_addr);
            }
            while let Some(ev) = client.poll_event() {
                match ev {
                    TurnEvent::AllocateResponse(_, addr) => {
                        relayed_addr = Some(addr);
                        break 'drive;
                    }
                    TurnEvent::AllocateError(_, e) => {
                        if first_attempt {
                            tracing::warn!("transport: TURN allocate rejected: {e}");
                        } else {
                            tracing::debug!("transport: TURN allocate retry rejected: {e}");
                        }
                        return None;
                    }
                    _ => {}
                }
            }
            let now = Instant::now();
            let to = client
                .poll_timeout()
                .unwrap_or(now + Duration::from_millis(100))
                .min(deadline);
            if to <= now {
                let _ = client.handle_timeout(now);
                continue;
            }
            let _ = socket.set_read_timeout(Some((to - now).max(Duration::from_millis(1))));
            match socket.recv_from(&mut buf) {
                Ok((n, from)) if from == server_addr => {
                    let _ = client.handle_read(TaggedBytesMut {
                        now: Instant::now(),
                        transport: TransportContext {
                            local_addr,
                            peer_addr: from,
                            ecn: None,
                            transport_protocol: TransportProtocol::UDP,
                        },
                        message: BytesMut::from(&buf[..n]),
                    });
                }
                // Stray packet from someone other than coturn this early: ignore.
                Ok(_) => {}
                Err(_) => {}
            }
            let _ = client.handle_timeout(Instant::now());
        }

        let relayed_addr = relayed_addr?;
        let candidate = CandidateRelayConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: relayed_addr.ip().to_string(),
                port: relayed_addr.port(),
                component: 1,
                ..Default::default()
            },
            rel_addr: local_addr.ip().to_string(),
            rel_port: local_addr.port(),
            url: Some(url),
        }
        .new_candidate_relay()
        .ok()?;
        let init = RTCIceCandidate::from(&candidate).to_json().ok()?;
        tracing::info!(relay = %relayed_addr, "transport: TURN relay candidate allocated");
        Some((
            TurnRelay {
                client,
                server_addr,
                relayed_addr,
                permitted: HashSet::new(),
            },
            init,
        ))
    }

    /// Reset per-viewer routing state for a new session while keeping the (shared)
    /// allocation. Old peer addresses won't match a new viewer, and permissions are
    /// re-created lazily as the engine checks the new viewer's candidates.
    fn reset_session(&mut self) {
        self.permitted.clear();
    }

    /// True if `addr` is coturn (so inbound from it is TURN protocol, not peer media).
    fn is_server(&self, addr: SocketAddr) -> bool {
        addr == self.server_addr
    }

    /// Feed an inbound datagram that came from coturn into the TURN client.
    fn handle_server_input(&mut self, msg: TaggedBytesMut) {
        let _ = self.client.handle_read(msg);
    }

    /// Flush the client's queued protocol datagrams (Allocate refresh, permissions,
    /// ChannelData) to coturn.
    fn pump_out(&mut self, socket: &UdpSocket) {
        while let Some(t) = self.client.poll_write() {
            let _ = socket.send_to(&t.message, t.transport.peer_addr);
        }
    }

    /// Drain TURN events: relayed peer datagrams are handed to the peer connection
    /// as if they'd arrived directly from that peer.
    fn drain_events(&mut self, pc: &mut RTCPeerConnection) {
        while let Some(ev) = self.client.poll_event() {
            match ev {
                TurnEvent::DataIndicationOrChannelData(_, from, data) => {
                    let _ = pc.handle_read(TaggedBytesMut {
                        now: Instant::now(),
                        transport: TransportContext {
                            local_addr: self.relayed_addr,
                            peer_addr: from,
                            ecn: None,
                            transport_protocol: TransportProtocol::UDP,
                        },
                        message: data,
                    });
                }
                TurnEvent::AllocateError(_, e) | TurnEvent::CreatePermissionError(_, e) => {
                    tracing::debug!("transport: TURN event error: {e}");
                }
                TurnEvent::AllocationLost(relayed, e) => {
                    tracing::warn!(%relayed, "transport: TURN allocation lost: {e}");
                }
                TurnEvent::RefreshError(relayed, e) => {
                    tracing::warn!(%relayed, "transport: TURN refresh failed: {e}");
                }
                TurnEvent::PermissionLost(relayed, peer_ip, e) => {
                    tracing::warn!(%relayed, %peer_ip, "transport: TURN permission lost: {e}");
                }
                _ => {}
            }
        }
    }

    /// Ensure coturn will relay to/from `peer`'s IP (install a permission once),
    /// then, if the engine sent this datagram from the relay candidate (`local`),
    /// wrap it through coturn. Returns `true` if the datagram was sent via the
    /// relay (so the caller must NOT also send it directly).
    fn route_out(&mut self, local: SocketAddr, peer: SocketAddr, message: &[u8]) -> bool {
        if self.permitted.insert(peer.ip())
            && let Ok(mut relay) = self.client.relay(self.relayed_addr)
        {
            let _ = relay.create_permission(Instant::now(), peer);
        }
        if local == self.relayed_addr {
            if let Ok(mut relay) = self.client.relay(self.relayed_addr) {
                let _ = relay.send_to(Instant::now(), message, peer);
            }
            return true;
        }
        false
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        self.client.poll_timeout()
    }

    fn handle_timeout(&mut self, now: Instant) {
        let _ = self.client.handle_timeout(now);
    }

    /// Release the allocation on coturn (Refresh with LIFETIME 0, RFC 8656 §8) and
    /// drive the client until it confirms or [`TURN_RELEASE_TIMEOUT`] passes.
    /// Best effort and bounded: the relay is consumed either way. Inbound datagrams
    /// from anyone but coturn are dropped meanwhile (the caller is tearing down).
    /// Returns `true` once `Event::AllocationReleased` reports the release done.
    fn release(mut self, socket: &UdpSocket, local_addr: SocketAddr) -> bool {
        let relayed_addr = self.relayed_addr;
        let start = Instant::now();
        if let Err(e) = self
            .client
            .relay(relayed_addr)
            .and_then(|mut relay| relay.close(start))
        {
            tracing::debug!(relay = %relayed_addr, "transport: TURN release failed to start: {e}");
            return false;
        }
        let deadline = start + TURN_RELEASE_TIMEOUT;
        let mut buf = vec![0u8; 2048];
        loop {
            self.pump_out(socket);
            while let Some(ev) = self.client.poll_event() {
                if let TurnEvent::AllocationReleased(addr) = ev
                    && addr == relayed_addr
                {
                    tracing::info!(relay = %relayed_addr, "transport: TURN allocation released");
                    return true;
                }
            }
            let now = Instant::now();
            if now >= deadline {
                tracing::debug!(relay = %relayed_addr, "transport: TURN release unconfirmed");
                return false;
            }
            let to = self
                .client
                .poll_timeout()
                .unwrap_or(now + Duration::from_millis(100))
                .min(deadline);
            if to <= now {
                let _ = self.client.handle_timeout(now);
                continue;
            }
            let _ = socket.set_read_timeout(Some((to - now).max(Duration::from_millis(1))));
            if let Ok((n, from)) = socket.recv_from(&mut buf)
                && from == self.server_addr
            {
                self.handle_server_input(TaggedBytesMut {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr,
                        peer_addr: from,
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                    message: BytesMut::from(&buf[..n]),
                });
            }
            let _ = self.client.handle_timeout(Instant::now());
        }
    }
}

/// The host's TURN state across sessions: the one allocation (and its candidate)
/// that every session re-advertises, plus the idle retry when the startup
/// allocation failed.
///
/// A restarted host allocates from the same 5-tuple as its predecessor, so while
/// that one's allocation lingers on coturn the Allocate is answered 437
/// (Allocation Mismatch). Without a retry the host would run relay-less for its
/// whole lifetime; instead the event loop retries every [`TURN_RETRY_INTERVAL`]
/// while no session is using the socket (setup blocks and reads it).
struct HostTurn {
    ice_servers: Vec<IceServer>,
    relay: Option<TurnRelay>,
    cand: Option<RTCIceCandidateInit>,
    /// When to retry the allocation; `None` = nothing to retry (allocated, no
    /// credentialed TURN server, or released for exit).
    retry_at: Option<Instant>,
    /// Failed allocation attempts so far, startup included.
    attempts: u32,
}

impl HostTurn {
    /// Allocate at startup; on failure with a credentialed TURN server configured,
    /// schedule the idle retry.
    fn start(socket: &UdpSocket, local_addr: SocketAddr, ice_servers: &[IceServer]) -> Self {
        let mut this = Self {
            ice_servers: ice_servers.to_vec(),
            relay: None,
            cand: None,
            retry_at: None,
            attempts: 0,
        };
        match TurnRelay::setup(socket, local_addr, ice_servers, true) {
            Some((relay, cand)) => {
                this.relay = Some(relay);
                this.cand = Some(cand);
            }
            None if first_turn_server(ice_servers).is_some() => {
                this.attempts = 1;
                this.retry_at = Some(Instant::now() + TURN_FIRST_RETRY);
                tracing::warn!(
                    retry_secs = TURN_FIRST_RETRY.as_secs(),
                    "transport: TURN relay unavailable; retrying while idle"
                );
            }
            None => {}
        }
        this
    }

    fn relay_mut(&mut self) -> Option<&mut TurnRelay> {
        self.relay.as_mut()
    }

    /// The next retry deadline, for the event loop's wake-up.
    fn retry_deadline(&self) -> Option<Instant> {
        self.retry_at
    }

    /// Retry the allocation if one is due. `idle` = no session is using the socket;
    /// a due retry that isn't idle is pushed back a full interval, so `retry_at` is
    /// always in the future afterwards (the loop never spins on it). Returns the new
    /// relay candidate on success, already stored for later sessions.
    fn maybe_retry(
        &mut self,
        socket: &UdpSocket,
        local_addr: SocketAddr,
        now: Instant,
        idle: bool,
    ) -> Option<RTCIceCandidateInit> {
        let due = self.retry_at.is_some_and(|t| t <= now);
        if !due {
            return None;
        }
        if !idle {
            self.retry_at = Some(now + TURN_RETRY_INTERVAL);
            return None;
        }
        match TurnRelay::setup(socket, local_addr, &self.ice_servers, false) {
            Some((relay, cand)) => {
                tracing::info!(
                    attempts = self.attempts,
                    "transport: TURN relay recovered after {} attempts",
                    self.attempts
                );
                self.relay = Some(relay);
                self.cand = Some(cand.clone());
                self.retry_at = None;
                Some(cand)
            }
            None => {
                self.attempts += 1;
                self.retry_at = Some(Instant::now() + TURN_RETRY_INTERVAL);
                tracing::debug!(
                    attempts = self.attempts,
                    "transport: TURN relay retry failed; next in {}s",
                    TURN_RETRY_INTERVAL.as_secs()
                );
                None
            }
        }
    }

    /// Release the allocation (if any) and stop retrying: the process is exiting.
    /// Returns `true` if an allocation was released and the server confirmed it.
    fn release(&mut self, socket: &UdpSocket, local_addr: SocketAddr) -> bool {
        self.retry_at = None;
        self.cand = None;
        self.relay
            .take()
            .is_some_and(|relay| relay.release(socket, local_addr))
    }
}

/// Host: offerer + video sender, with sender-side GCC + TWCC.
fn run_host(
    config: TransportConfig,
    cmd_rx: Receiver<DriverCmd>,
    event_tx: Sender<TransportEvent>,
    bitrate_bps: Arc<AtomicU32>,
) -> anyhow::Result<()> {
    let (socket, local_addr) = bind_socket(config.bind_addr)?;

    // Allocate the TURN relay ONCE for the socket's lifetime, not per session: a
    // second Allocate on the same 5-tuple while the previous allocation still lingers
    // on coturn is rejected (Allocation Mismatch), which would drop reconnects back to
    // relay-less and break cross-NAT rapid reconnects. We keep the one allocation and
    // just re-advertise its candidate (and reset per-viewer routing state) each session.
    // If this first Allocate fails (typically 437 while a restarted predecessor's
    // allocation lingers), the event loop retries it while idle (see `HostTurn`).
    let mut turn = HostTurn::start(&socket, local_addr, &config.ice_servers);

    // One iteration per viewer session: build a fresh peer connection (offer +
    // control data channel), serve it, and rebuild from scratch when it drops so
    // a reconnecting/reloaded viewer always gets clean DTLS + a new data channel.
    loop {
        // Media engine: register the configured send codec (H.264 or AV1).
        let mut media_engine = MediaEngine::default();
        let codec = codec_params(config.video_codec);
        media_engine
            .register_codec(codec.clone(), RtpCodecKind::Video)
            .context("register video codec")?;

        // Interceptor chain: rtci's default set — NACK, RTCP reports, the TWCC /
        // RFC 8888 feedback headers, and per-transport GCC congestion control with
        // its pacer and circuit breaker. The congestion-control handle is polled each
        // tick for the latest target bitrate.
        let (registry, handles) =
            register_default_interceptors_with_handles(Registry::new(), &mut media_engine)
                .context("default interceptors")?;
        let gcc = handles.congestion_control;
        // Cap GCC at the host's configured bitrate (the estimator's own ceiling is far
        // higher), exactly as the fork's `with_max_bitrate` did: GCC still backs off
        // toward its floor on congestion; this only bounds it to what we asked for.
        gcc.set_session_bitrate_limit(Some(f64::from(config.video_bitrate_bps)));

        let mut pc = RTCPeerConnectionBuilder::new()
            .with_configuration(
                RTCConfigurationBuilder::new()
                    .with_ice_servers(ice_servers(&config.ice_servers))
                    .build(),
            )
            .with_setting_engine(app_gathering(SettingEngineBuilder::new()).build())
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .build(Instant::now())
            .context("build host peer connection")?;

        // Add the video send track (its SSRC drives the packetizer) and the reliable
        // ordered control data channel *before* creating the offer, so both are
        // negotiated in the initial SDP.
        let video_ssrc: SSRC = rand::random();
        let track = MediaStreamTrack::new(
            "rmd-video".to_owned(),
            "rmd-video-track".to_owned(),
            "rmd-video-label".to_owned(),
            RtpCodecKind::Video,
            vec![RTCRtpEncodingParameters {
                rtp_coding_parameters: RTCRtpCodingParameters {
                    ssrc: Some(video_ssrc),
                    ..Default::default()
                },
                codec: codec.rtp_codec.clone(),
                ..Default::default()
            }],
        );
        let video_sender_id = pc.add_track(track).context("add video track")?;

        let _ = pc
            .create_data_channel(
                "control",
                Some(RTCDataChannelInit {
                    ordered: true, // reliable + ordered (no lifetime/retransmit limits)
                    ..Default::default()
                }),
            )
            .context("create control data channel")?;

        // Kick off signaling: create + apply the offer and surface it immediately,
        // so the peer can start negotiating while we gather candidates.
        let offer = pc.create_offer(None).context("create offer")?;
        pc.set_local_description(Instant::now(), offer.clone())
            .context("set local offer")?;
        emit_session(&event_tx, &offer)?;

        // Gather host + server-reflexive candidates on the bound socket now (before
        // the driver loop owns it) and trickle each. A local description exists, so
        // they can be added to the agent eagerly.
        for init in gather_local_candidates(&socket, local_addr, &config.ice_servers) {
            pc.add_local_candidate(init.clone())
                .context("add local candidate")?;
            let _ = event_tx.send(TransportEvent::LocalSignal(SignalMsg::Candidate(
                init.candidate,
            )));
        }

        // (Re)advertise the persistent TURN relay candidate on this fresh peer
        // connection and reset its per-viewer routing state. This is what lets a peer
        // behind symmetric NAT / CGNAT connect (the host otherwise offers host+srflx
        // only). The allocation itself was made once above and survives rebuilds.
        if let (Some(relay), Some(cand)) = (turn.relay.as_mut(), turn.cand.as_ref()) {
            relay.reset_session();
            if let Err(e) = pc.add_local_candidate(cand.clone()) {
                tracing::debug!("transport: add relay candidate failed: {e}");
            }
            let _ = event_tx.send(TransportEvent::LocalSignal(SignalMsg::Candidate(
                cand.candidate.clone(),
            )));
        }

        // Packetizer for outbound encoded frames. The payloader is selected from the
        // codec's MIME type (H264Payloader or Av1Payloader) by the fork.
        let packetizer: Box<dyn Packetizer> = Box::new(new_packetizer(
            Instant::now(),
            RTP_OUTBOUND_MTU,
            codec.payload_type,
            video_ssrc,
            codec.rtp_codec.payloader().context("video payloader")?,
            Box::new(rtci::rtp::sequence::new_random_sequencer()),
            VIDEO_CLOCK_RATE,
        ));

        let mut state = RoleState {
            gcc: Some(gcc),
            pli_sender_ssrc: 0,
            video: Some(VideoSend {
                sender_id: video_sender_id,
                ssrc: video_ssrc,
                packetizer,
                last_ts_micros: None,
            }),
            sample_builder: None,
            remote_video_ssrc: None,
            data_channel_id: None,
            pending_local_candidates: Vec::new(), // host adds its own eagerly above
            remote_description_set: false,
            pending_remote_candidates: Vec::new(),
            bitrate_bps: bitrate_bps.clone(),
            is_host: true,
            negotiated_once: false,
            rebuild: false,
            pending_offer: None,
        };

        match event_loop(
            &mut pc,
            &socket,
            local_addr,
            &cmd_rx,
            &event_tx,
            &mut state,
            None,
            Some(&mut turn),
        )? {
            LoopOutcome::Shutdown => return Ok(()),
            LoopOutcome::Reconnect(_) => {
                tracing::info!("transport(host): connection dropped; rebuilding session");
                continue;
            }
        }
    } // end session loop
}

/// Viewer: answerer + video receiver, default interceptors (incl. TWCC receiver).
fn run_viewer(
    config: TransportConfig,
    cmd_rx: Receiver<DriverCmd>,
    event_tx: Sender<TransportEvent>,
    bitrate_bps: Arc<AtomicU32>,
) -> anyhow::Result<()> {
    let (socket, local_addr) = bind_socket(config.bind_addr)?;

    // An offer to apply on the freshly-built PC after a viewer-side rebuild
    // (`None` on the first pass and when we rebuild to await the host's offer).
    let mut pending: Option<SignalMsg> = None;
    loop {
        // The viewer receives H.264 (its SampleBuilder uses the H.264 depacketizer;
        // AV1 has no pure-Rust decoder and is consumed only by the browser viewer).
        let mut media_engine = MediaEngine::default();
        media_engine
            .register_codec(codec_params(VideoCodec::H264), RtpCodecKind::Video)
            .context("register H264 codec")?;

        // Default interceptors give us NACK, RTCP reports, and — crucially for the
        // host's GCC — the TWCC *receiver* that generates congestion feedback.
        // (The congestion-control handles only matter to a sender; the viewer
        // drops them.)
        let (registry, _handles) =
            register_default_interceptors_with_handles(Registry::new(), &mut media_engine)
                .context("default interceptors")?;

        // As the answerer we take the DTLS server role (host becomes the client).
        let setting_engine = app_gathering(SettingEngineBuilder::new())
            .with_answering_dtls_role(RTCDtlsRole::Server)
            .build();

        let mut pc = RTCPeerConnectionBuilder::new()
            .with_configuration(
                RTCConfigurationBuilder::new()
                    .with_ice_servers(ice_servers(&config.ice_servers))
                    .build(),
            )
            .with_setting_engine(setting_engine)
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .build(Instant::now())
            .context("build viewer peer connection")?;

        // Receive one video track.
        pc.add_transceiver_from_kind(
            RtpCodecKind::Video,
            Some(RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Recvonly,
                ..Default::default()
            }),
        )
        .context("add recvonly video transceiver")?;

        // Gather the viewer's own candidates now, on the bound socket, before the
        // driver loop owns it. They can only be added and surfaced once the viewer
        // answers the offer (a local description must exist first), so they are
        // stashed in RoleState and handled in `apply_signal`.
        let pending_local_candidates =
            gather_local_candidates(&socket, local_addr, &config.ice_servers);

        // H.264 depacketizer + sample builder reassemble RTP into Annex-B access
        // units. `H264Packet` defaults to `is_avc = false`, so it emits NAL units
        // delimited by the 0x00000001 Annex-B start code — exactly what a decoder
        // (e.g. openh264) expects.
        let sample_builder = SampleBuilder::new(
            SAMPLE_BUILDER_MAX_LATE,
            H264Packet::default(),
            VIDEO_CLOCK_RATE,
        );

        let mut state = RoleState {
            gcc: None,
            // Our RTCP sender SSRC for PLIs. Never 0: the host treats a 0-sender PLI
            // as its own pacer's discard, not a viewer request.
            pli_sender_ssrc: rand::random::<u32>().max(1),
            video: None,
            sample_builder: Some(sample_builder),
            remote_video_ssrc: None,
            data_channel_id: None,
            pending_local_candidates,
            remote_description_set: false,
            pending_remote_candidates: Vec::new(),
            bitrate_bps: bitrate_bps.clone(),
            is_host: false,
            negotiated_once: false,
            rebuild: false,
            pending_offer: None,
        };

        match event_loop(
            &mut pc,
            &socket,
            local_addr,
            &cmd_rx,
            &event_tx,
            &mut state,
            pending.take(),
            None,
        )? {
            LoopOutcome::Shutdown => return Ok(()),
            LoopOutcome::Reconnect(offer) => {
                tracing::info!("transport(viewer): session ended; rebuilding");
                pending = offer.map(SignalMsg::Offer);
                continue;
            }
        }
    } // end session loop
}

/// Keep the engine's own server-reflexive and relay gathering off: we gather srflx
/// ourselves before the loop starts and run our own TURN client on the shared
/// socket. An engine-run Allocate from the same 5-tuple would collide with ours
/// (437 Allocation Mismatch), and its Binding requests would race our gathering.
fn app_gathering(builder: SettingEngineBuilder) -> SettingEngineBuilder {
    builder
        .with_relay_gathering(RelayGathering::Application)
        .with_server_reflexive_gathering(ReflexiveGathering::Application)
        // Don't resolve the browser's `.local` mDNS host candidates: we can't
        // reach a LAN-only name from a relayed/remote host anyway, and the
        // default (QueryOnly) logs an error per candidate on rtci 0.2.0.
        .with_multicast_dns_mode(MulticastDnsMode::Disabled)
}

/// Outbound H.264 send state (host only).
struct VideoSend {
    sender_id: RTCRtpSenderId,
    ssrc: SSRC,
    packetizer: Box<dyn Packetizer>,
    /// Timestamp of the previous access unit, for computing the 90 kHz delta.
    last_ts_micros: Option<u64>,
}

/// Per-role state threaded through the generic event loop.
struct RoleState {
    /// Congestion-control handle (host only) — polled each tick for the GCC
    /// target bitrate.
    gcc: Option<CongestionControlHandle>,
    /// Sender SSRC of the PLIs we write when the sample builder gives up a gap
    /// (viewer only; non-zero).
    pli_sender_ssrc: SSRC,
    /// Video send path (host only).
    video: Option<VideoSend>,
    /// Video receive reassembly (viewer only).
    sample_builder: Option<SampleBuilder<H264Packet>>,
    /// SSRC of the remote video stream, from its RTP (viewer only) — the media
    /// SSRC of the PLIs we write.
    remote_video_ssrc: Option<SSRC>,
    /// Id of the open `control` data channel, once its `OnOpen` fires.
    data_channel_id: Option<RTCDataChannelId>,
    /// Our own gathered local candidates (host + srflx), added to the local
    /// agent once a local description exists. The host adds them eagerly at
    /// startup and leaves this empty; the viewer adds them when it answers the
    /// offer.
    pending_local_candidates: Vec<RTCIceCandidateInit>,
    /// Whether a remote description has been applied yet. `add_remote_candidate`
    /// is only valid afterwards, so candidates that arrive early are buffered.
    remote_description_set: bool,
    /// Remote candidates received before the remote description was set.
    pending_remote_candidates: Vec<String>,
    /// Shared cell the encoder reads for its bitrate target.
    bitrate_bps: Arc<AtomicU32>,

    // --- reconnect bookkeeping --------------------------------------------
    /// True on the host (offerer). The host rebuilds the session on connection
    /// loss; the viewer rebuilds when a fresh offer / loss is seen.
    is_host: bool,
    /// Whether we've completed a negotiation on this peer connection. A *second*
    /// offer (viewer) then means a new session → rebuild, since a browser reload
    /// (or host rebuild) brings fresh DTLS/SCTP that can't graft onto this PC.
    negotiated_once: bool,
    /// Set when the event loop should tear down this peer connection and rebuild
    /// a fresh one (new DTLS + data channel + offer). See [`LoopOutcome`].
    rebuild: bool,
    /// Viewer only: an offer to apply immediately on the rebuilt PC (the offer
    /// that triggered the rebuild). `None` means "wait for the host's new offer".
    pending_offer: Option<String>,
}

/// What the [`event_loop`] returns to its owner (`run_host` / `run_viewer`).
enum LoopOutcome {
    /// The transport handle was dropped or a shutdown was requested — exit.
    Shutdown,
    /// Rebuild a fresh peer connection and resume. The optional payload is an
    /// offer to apply on the fresh PC (viewer, when a new offer triggered it).
    Reconnect(Option<String>),
}

/// Emit a local offer/answer as a JSON-encoded signaling message.
fn emit_session(
    event_tx: &Sender<TransportEvent>,
    desc: &RTCSessionDescription,
) -> anyhow::Result<()> {
    let json = serde_json::to_string(desc).context("serialize session description")?;
    let msg = if desc.sdp_type == rtci::peer_connection::sdp::RTCSdpType::Offer {
        SignalMsg::Offer(json)
    } else {
        SignalMsg::Answer(json)
    };
    let _ = event_tx.send(TransportEvent::LocalSignal(msg));
    Ok(())
}

/// The shared sans-IO pump, generic over the concrete interceptor chain `I`.
///
/// Each iteration: drain commands, flush pending writes to the socket, service
/// timeouts, read one inbound datagram (bounded wait), then drain events and
/// media/data reads into [`TransportEvent`]s. Publishes the GCC estimate.
#[allow(clippy::too_many_arguments)]
fn event_loop(
    pc: &mut RTCPeerConnection,
    socket: &UdpSocket,
    local_addr: SocketAddr,
    cmd_rx: &Receiver<DriverCmd>,
    event_tx: &Sender<TransportEvent>,
    state: &mut RoleState,
    initial_signal: Option<SignalMsg>,
    mut turn: Option<&mut HostTurn>,
) -> anyhow::Result<LoopOutcome> {
    let mut connected = false;
    let mut read_buf = vec![0u8; 2048];
    // Consecutive immediate timer fires without an intervening blocking read.
    // Reset whenever the next deadline is in the future; capped so a stuck timer
    // can't spin the loop (see `MAX_CONSECUTIVE_REFIRES`).
    let mut refires: u32 = 0;
    let mut local_of = LocalAddrResolver::new(local_addr);

    // On a viewer rebuild, apply the offer that triggered it to the fresh PC.
    if let Some(msg) = initial_signal
        && let Err(e) = apply_signal(pc, event_tx, state, msg)
    {
        tracing::warn!("transport: applying rebuild offer failed: {e:?}");
    }

    loop {
        // 1. Drain application commands. Exiting (or about to `exec`) releases the
        //    TURN allocation so the next process's Allocate isn't refused (437).
        match drain_commands(pc, cmd_rx, event_tx, state) {
            CommandOutcome::Continue => {}
            CommandOutcome::Shutdown => {
                if let Some(t) = turn.as_deref_mut() {
                    t.release(socket, local_addr);
                }
                let _ = pc.close();
                return Ok(LoopOutcome::Shutdown);
            }
            CommandOutcome::ReleaseTurn(ack) => {
                if let Some(t) = turn.as_deref_mut() {
                    t.release(socket, local_addr);
                }
                let _ = ack.send(());
                continue; // drain any commands queued behind it
            }
        }

        // 2. Flush all pending outbound datagrams. With a TURN relay, a datagram to
        //    a peer we only reach via the relay is wrapped through coturn instead of
        //    sent directly (route_out also installs the coturn permission). Peers on
        //    a working direct/srflx path are unaffected — they go straight out.
        while let Some(msg) = pc.poll_write() {
            let peer = msg.transport.peer_addr;
            let relayed = turn
                .as_deref_mut()
                .and_then(HostTurn::relay_mut)
                .map(|t| t.route_out(msg.transport.local_addr, peer, &msg.message))
                .unwrap_or(false);
            if !relayed && let Err(e) = socket.send_to(&msg.message, peer) {
                tracing::debug!("transport: socket send_to error: {e}");
            }
        }

        // 2b. Flush the TURN client's own datagrams (allocation refresh, permission
        //     requests, ChannelData) and surface any relayed peer datagrams into the
        //     peer connection as if they'd arrived directly.
        if let Some(t) = turn.as_deref_mut().and_then(HostTurn::relay_mut) {
            t.pump_out(socket);
            t.drain_events(pc);
        }

        // 3. Surface connection-state and ICE-candidate events.
        drain_events(pc, event_tx, state, &mut connected);

        // 3b. A lost connection (host) or a new-session offer (viewer) asks us to
        //     rebuild a fresh peer connection rather than patch this one.
        if state.rebuild {
            let _ = pc.close();
            return Ok(LoopOutcome::Reconnect(state.pending_offer.take()));
        }

        // 4. Drain inbound media / data.
        drain_reads(pc, event_tx, state);

        // 5. Publish the latest GCC estimate (host only). Like the fork's GccHandle,
        //    hold off until feedback has been processed (the estimator's loss figure
        //    exists only then), so the encoder keeps its configured start rate rather
        //    than dropping to the estimator's initial guess.
        if let Some(gcc) = &state.gcc
            && gcc.stats().packet_loss.is_some()
        {
            let bps = gcc.target_bitrate() as u32;
            let prev = state.bitrate_bps.swap(bps, Ordering::Relaxed);
            if prev != bps {
                tracing::debug!("transport: GCC target bitrate -> {bps} bps");
            }
        }

        // 5b. Host whose startup TURN allocation failed: retry it when due, but only
        //     while no session is on the socket (setup blocks up to
        //     TURN_SETUP_TIMEOUT and consumes the socket's inbound datagrams). On
        //     success advertise the relay on this peer connection exactly as
        //     `run_host` does per session; later sessions pick it up from `HostTurn`.
        if let Some(t) = turn.as_deref_mut() {
            let idle = !connected && !state.remote_description_set;
            if let Some(cand) = t.maybe_retry(socket, local_addr, Instant::now(), idle) {
                if let Some(relay) = t.relay_mut() {
                    relay.reset_session();
                }
                if let Err(e) = pc.add_local_candidate(cand.clone()) {
                    tracing::debug!("transport: add relay candidate failed: {e}");
                }
                let _ = event_tx.send(TransportEvent::LocalSignal(SignalMsg::Candidate(
                    cand.candidate.clone(),
                )));
                continue; // re-pump: setup blocked, so timers and writes are stale
            }
        }

        // 6. Service the sans-IO timer, then wait (bounded) for the next
        //    datagram so both timeouts and commands stay responsive. The TURN
        //    client's refresh timer is driven each pass and folded into the wait so
        //    we never sleep past an allocation/permission refresh.
        let now = Instant::now();
        if let Some(t) = turn.as_deref_mut().and_then(HostTurn::relay_mut) {
            t.handle_timeout(now);
        }
        // The viewer's sample builder gives a gap up after its wait bound; drive its
        // `pop` when that comes due even if no packet arrives.
        let sb_deadline = state
            .sample_builder
            .as_ref()
            .and_then(SampleBuilder::poll_timeout);
        if sb_deadline.is_some_and(|t| t <= now) {
            pop_samples(pc, event_tx, state, now, None);
        }
        let sb_deadline = state
            .sample_builder
            .as_ref()
            .and_then(SampleBuilder::poll_timeout);
        let pc_deadline = pc.poll_timeout();
        if let Some(eto) = pc_deadline {
            if eto <= now {
                pc.handle_timeout(now).context("handle_timeout")?;
                // Normally re-pump at once so datagrams that `handle_timeout`
                // just produced flush without waiting on a read. But a handler
                // stuck at an expired deadline would `continue` forever and peg
                // a core, so bound the streak: once it trips, fall through to a
                // bounded blocking read instead of short-cutting.
                refires += 1;
                if refires < MAX_CONSECUTIVE_REFIRES {
                    continue; // re-run the pump immediately after a fired timer
                }
                if refires == MAX_CONSECUTIVE_REFIRES {
                    tracing::warn!(
                        connected,
                        remote_answered = pc.remote_description().is_some(),
                        deadline_late_ms = now.saturating_duration_since(eto).as_millis(),
                        "transport: sans-IO timer stuck at an expired deadline; \
                         throttling the driver loop to avoid a busy-spin"
                    );
                }
            } else {
                refires = 0;
            }
        } else {
            refires = 0;
        }
        let turn_deadline = turn
            .as_deref_mut()
            .and_then(HostTurn::relay_mut)
            .and_then(TurnRelay::poll_timeout);
        // The idle TURN retry is always scheduled in the future (see `maybe_retry`).
        let retry_deadline = turn.as_deref().and_then(HostTurn::retry_deadline);
        let deadline = [pc_deadline, turn_deadline, sb_deadline, retry_deadline]
            .into_iter()
            .flatten()
            .min();

        let wait = deadline
            .map(|eto| eto.saturating_duration_since(now))
            .unwrap_or(MAX_SOCKET_READ_WAIT)
            .min(MAX_SOCKET_READ_WAIT);
        socket
            .set_read_timeout(Some(wait.max(Duration::from_millis(1))))
            .context("set socket read timeout")?;

        match socket.recv_from(&mut read_buf) {
            Ok((n, peer_addr)) => {
                let msg = TaggedBytesMut {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr: local_of.local_for(peer_addr),
                        peer_addr,
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                    message: BytesMut::from(&read_buf[..n]),
                };
                // Datagrams from coturn are TURN protocol (allocate/permission
                // responses, relayed peer data) — feed them to the TURN client and
                // immediately surface any relayed media. Everything else is direct
                // peer traffic for the peer connection.
                match turn.as_deref_mut().and_then(HostTurn::relay_mut) {
                    Some(t) if t.is_server(peer_addr) => {
                        t.handle_server_input(msg);
                        t.pump_out(socket);
                        t.drain_events(pc);
                    }
                    _ => {
                        pc.handle_read(msg).context("handle_read")?;
                    }
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // Idle read timeout — advance the timer on the next iteration.
            }
            Err(e) => {
                tracing::debug!("transport: socket recv_from error: {e}");
            }
        }
    }
}

/// Whether the command drain asked the loop to keep running or shut down.
enum CommandOutcome {
    Continue,
    Shutdown,
    /// Release the TURN allocation, then ack (see [`DriverCmd::ReleaseTurn`]).
    /// Commands queued behind it are drained on the next pass.
    ReleaseTurn(Sender<()>),
}

/// Apply every currently queued [`DriverCmd`].
fn drain_commands(
    pc: &mut RTCPeerConnection,
    cmd_rx: &Receiver<DriverCmd>,
    event_tx: &Sender<TransportEvent>,
    state: &mut RoleState,
) -> CommandOutcome {
    loop {
        match cmd_rx.try_recv() {
            Ok(DriverCmd::Video {
                annexb,
                is_keyframe,
                ts_micros,
            }) => {
                let _ = is_keyframe; // the packetizer doesn't need the flag
                send_video(pc, state, &annexb, ts_micros);
            }
            Ok(DriverCmd::Data(bytes)) => {
                send_data(pc, state, &bytes);
            }
            Ok(DriverCmd::Signal(msg)) => {
                if let Err(e) = apply_signal(pc, event_tx, state, msg) {
                    tracing::warn!("transport: applying peer signal failed: {e:?}");
                }
            }
            Ok(DriverCmd::IceRestart) => {
                // Host-initiated recovery: rebuild the session with a fresh offer.
                if state.is_host {
                    state.rebuild = true;
                    tracing::info!("transport: session rebuild requested");
                }
            }
            Ok(DriverCmd::ReleaseTurn(ack)) => return CommandOutcome::ReleaseTurn(ack),
            Ok(DriverCmd::Shutdown) => return CommandOutcome::Shutdown,
            Err(TryRecvError::Empty) => return CommandOutcome::Continue,
            // The Transport handle was dropped — tear down cleanly.
            Err(TryRecvError::Disconnected) => return CommandOutcome::Shutdown,
        }
    }
}

/// Packetize and send one Annex-B access unit on the video track (host).
fn send_video(pc: &mut RTCPeerConnection, state: &mut RoleState, annexb: &Bytes, ts_micros: u64) {
    let Some(video) = state.video.as_mut() else {
        return;
    };

    // Advance the RTP timestamp by the real inter-frame gap at 90 kHz. The first
    // frame contributes no advance (the packetizer applies `samples` *after*
    // stamping this frame's packets).
    let samples = match video.last_ts_micros {
        Some(prev) if ts_micros > prev => {
            ((u128::from(ts_micros - prev) * u128::from(VIDEO_CLOCK_RATE)) / 1_000_000) as u32
        }
        _ => 0,
    };
    video.last_ts_micros = Some(ts_micros);

    let packets = match video.packetizer.packetize(Instant::now(), annexb, samples) {
        Ok(p) => p,
        Err(e) => {
            tracing::debug!("transport: packetize failed: {e}");
            return;
        }
    };

    let ssrc = video.ssrc;
    let sender_id = video.sender_id;
    for mut packet in packets {
        packet.header.ssrc = ssrc;
        if let Some(mut sender) = pc.rtp_sender(sender_id)
            && let Err(e) = sender.write_rtp(Instant::now(), packet)
        {
            // Common before negotiation completes; not fatal.
            tracing::trace!("transport: write_rtp dropped: {e}");
        }
    }
}

/// Send bytes on the control data channel (either role, once open).
fn send_data(pc: &mut RTCPeerConnection, state: &mut RoleState, bytes: &Bytes) {
    let Some(id) = state.data_channel_id else {
        tracing::debug!("transport: data channel not open yet, dropping send");
        return;
    };
    if let Some(mut dc) = pc.data_channel(id)
        && let Err(e) = dc.send(Instant::now(), BytesMut::from(bytes.as_ref()))
    {
        tracing::warn!("transport: data channel send error: {e}");
    }
}

/// Apply a peer signaling message (offer/answer/candidate).
fn apply_signal(
    pc: &mut RTCPeerConnection,
    event_tx: &Sender<TransportEvent>,
    state: &mut RoleState,
    msg: SignalMsg,
) -> anyhow::Result<()> {
    match msg {
        SignalMsg::Offer(json) => {
            // A second offer on an already-negotiated viewer PC is a *new* session
            // (the host rebuilt, or the browser reloaded): its fresh DTLS can't be
            // applied to this PC. Defer it to a fresh peer connection via rebuild.
            if state.negotiated_once {
                state.rebuild = true;
                state.pending_offer = Some(json);
                return Ok(());
            }

            // Viewer path: apply the remote offer, answer it (which establishes
            // our local description), then add + trickle our gathered
            // candidates (add_local_candidate requires a local description).
            let offer: RTCSessionDescription =
                serde_json::from_str(&json).context("parse remote offer")?;
            pc.set_remote_description(Instant::now(), offer)
                .context("set remote offer")?;
            state.remote_description_set = true;

            let answer = pc.create_answer(None).context("create answer")?;
            pc.set_local_description(Instant::now(), answer.clone())
                .context("set local answer")?;
            emit_session(event_tx, &answer)?;

            state.negotiated_once = true;
            for init in state.pending_local_candidates.drain(..) {
                pc.add_local_candidate(init.clone())
                    .context("add local candidate")?;
                let _ = event_tx.send(TransportEvent::LocalSignal(SignalMsg::Candidate(
                    init.candidate,
                )));
            }
            flush_remote_candidates(pc, state);
        }
        SignalMsg::Answer(json) => {
            // A second answer on an already-negotiated host PC means the viewer
            // re-announced (its browser PC was rebuilt after idle) and answered a
            // replayed offer. Our PC is already past have-local-offer ("stable"), so
            // this answer can't be applied — it errors with "from stable applying
            // false answer" and the session stalls forever. Rebuild with a fresh
            // offer (new ICE credentials) instead, mirroring the viewer's second-
            // offer path above; the fresh offer is replayed to the viewer and the
            // handshake completes cleanly.
            if state.negotiated_once {
                state.rebuild = true;
                state.pending_offer = None; // the host makes its own fresh offer
                tracing::info!(
                    "transport(host): answer after negotiation (viewer re-announce); \
                     rebuilding with a fresh offer"
                );
                return Ok(());
            }

            // Host path: apply the remote answer.
            let answer: RTCSessionDescription =
                serde_json::from_str(&json).context("parse remote answer")?;
            pc.set_remote_description(Instant::now(), answer)
                .context("set remote answer")?;
            state.remote_description_set = true;
            state.negotiated_once = true;
            flush_remote_candidates(pc, state);
        }
        SignalMsg::Candidate(candidate) => {
            // `add_remote_candidate` requires the remote description to be set.
            // If it hasn't arrived yet, buffer and replay after it does.
            if state.remote_description_set {
                if let Err(e) = pc.add_remote_candidate(RTCIceCandidateInit {
                    candidate,
                    // Signaling carries only the candidate line; rtci (W3C
                    // addIceCandidate) needs a section. Index 0 is the BUNDLE transport.
                    sdp_mline_index: Some(0),
                    ..Default::default()
                }) {
                    tracing::debug!("transport: add_remote_candidate failed: {e}");
                }
            } else {
                state.pending_remote_candidates.push(candidate);
            }
        }
    }
    Ok(())
}

/// Replay any remote candidates buffered before the remote description existed.
fn flush_remote_candidates(pc: &mut RTCPeerConnection, state: &mut RoleState) {
    for candidate in state.pending_remote_candidates.drain(..) {
        if let Err(e) = pc.add_remote_candidate(RTCIceCandidateInit {
            candidate,
            // Signaling carries only the candidate line; rtci (W3C
            // addIceCandidate) needs a section. Index 0 is the BUNDLE transport.
            sdp_mline_index: Some(0),
            ..Default::default()
        }) {
            tracing::debug!("transport: buffered add_remote_candidate failed: {e}");
        }
    }
}

/// Drain connection-state changes and ICE candidates into events.
fn drain_events(
    pc: &mut RTCPeerConnection,
    event_tx: &Sender<TransportEvent>,
    state: &mut RoleState,
    connected: &mut bool,
) {
    while let Some(event) = pc.poll_event() {
        match event {
            RTCPeerConnectionEvent::OnConnectionStateChangeEvent(s) => match s {
                RTCPeerConnectionState::Connected => {
                    if !*connected {
                        *connected = true;
                        let _ = event_tx.send(TransportEvent::Connected);
                    }
                }
                // Connection lost. A browser reload (or any reconnect) brings a
                // fresh DTLS/SCTP association that can't be grafted onto this peer
                // connection, so we tear it down and rebuild rather than ICE-
                // restart. The host emits a fresh offer immediately; the viewer
                // rebuilds and waits for it.
                //
                // `Failed` is terminal (dead ICE), so we rebuild even when the
                // session never reached `Connected` — otherwise a host waiting
                // with no viewer would park on a dead peer connection and its
                // stuck timers would spin the driver loop. `Disconnected` can
                // still recover on its own and `Closed` only happens when we
                // closed it, so those two only rebuild once a session was live.
                RTCPeerConnectionState::Failed
                | RTCPeerConnectionState::Disconnected
                | RTCPeerConnectionState::Closed
                    if *connected || matches!(s, RTCPeerConnectionState::Failed) =>
                {
                    let was_connected = *connected;
                    *connected = false;
                    if was_connected {
                        let _ = event_tx.send(TransportEvent::Disconnected);
                    }
                    state.rebuild = true;
                    tracing::warn!(state = ?s, "transport: session torn down; rebuilding");
                }
                _ => {}
            },
            RTCPeerConnectionEvent::OnIceCandidateEvent(ice) => {
                // `None` = gathering complete; we never signal end-of-candidates.
                let Some(candidate) = ice.candidate else {
                    continue;
                };
                if let Ok(init) = candidate.to_json()
                    && !init.candidate.is_empty()
                {
                    let _ = event_tx.send(TransportEvent::LocalSignal(SignalMsg::Candidate(
                        init.candidate,
                    )));
                }
            }
            RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) => {
                state.data_channel_id = Some(id);
            }
            // Which path the session runs on (host/srflx/relay) — the first thing
            // to know when a remote session is slow or drops.
            RTCPeerConnectionEvent::OnSelectedCandidatePairChange(pair) => {
                tracing::info!(%pair, "transport: selected candidate pair");
            }
            RTCPeerConnectionEvent::OnPacerDiscard {
                frames,
                packets,
                octets,
                target_bitrate,
                ..
            } => {
                tracing::debug!(
                    frames,
                    packets,
                    octets,
                    target_bitrate,
                    "transport: pacer discarded queued video"
                );
            }
            _ => {}
        }
    }
}

/// Drain inbound RTP (→ reassembled video) and data-channel messages.
fn drain_reads(
    pc: &mut RTCPeerConnection,
    event_tx: &Sender<TransportEvent>,
    state: &mut RoleState,
) {
    while let Some(TaggedRTCMessage { now, message }) = pc.poll_read() {
        match message {
            RTCMessage::RtpPacket(_track_id, packet) => {
                if let Some(sb) = state.sample_builder.as_mut() {
                    let ts = packet.header.timestamp;
                    state.remote_video_ssrc = Some(packet.header.ssrc);
                    sb.push(now, packet);
                    // Drain any completed access units.
                    pop_samples(pc, event_tx, state, now, Some(ts));
                }
            }
            RTCMessage::DataChannelMessage(_id, msg) => {
                let _ = event_tx.send(TransportEvent::Data(msg.data.freeze()));
            }
            RTCMessage::RtcpPacket(_, packets) => {
                // Most RTCP (RR/SR/NACK/TWCC) is consumed by interceptors. But a
                // Picture Loss Indication / Full Intra Request is the viewer asking
                // for a fresh keyframe after it lost packets it can't recover via
                // NACK — surface it so the host forces an IDR right away instead of
                // leaving the last frame stale until the ~2s periodic keyframe.
                //
                // rtci's pacer also injects a PLI with sender SSRC 0 when it discards
                // queued video; that is our own over-budget signal, not the viewer
                // asking, so it is skipped here (see `OnPacerDiscard`).
                let wants_keyframe = packets.iter().any(|p| {
                    let any = p.as_any();
                    if let Some(pli) = any.downcast_ref::<PictureLossIndication>() {
                        // Logged so live tests can confirm no browser sends PLI
                        // with sender SSRC 0 (which this filter would drop).
                        tracing::debug!(
                            sender_ssrc = pli.sender_ssrc,
                            media_ssrc = pli.media_ssrc,
                            "transport: PLI received"
                        );
                        return pli.sender_ssrc != 0;
                    }
                    any.is::<FullIntraRequest>()
                });
                if wants_keyframe {
                    let _ = event_tx.send(TransportEvent::KeyframeRequested);
                }
            }
            _ => {}
        }
    }
}

/// Emit every access unit the viewer's sample builder can release at `now`, then,
/// if it gave a gap up (lost packets past its wait bound), ask the host for a key
/// frame with a PLI. `pushed_ts` is the RTP timestamp of the packet just pushed
/// (the `ts_hint` used for samples released by a push); a timer-driven pop uses
/// each sample's own packet timestamp.
fn pop_samples(
    pc: &mut RTCPeerConnection,
    event_tx: &Sender<TransportEvent>,
    state: &mut RoleState,
    now: Instant,
    pushed_ts: Option<u32>,
) {
    let Some(sb) = state.sample_builder.as_mut() else {
        return;
    };
    while let Some(sample) = sb.pop(now) {
        let ts = pushed_ts.unwrap_or(sample.packet_timestamp);
        let _ = event_tx.send(TransportEvent::Video {
            annexb: sample.data,
            ts_hint: u64::from(ts),
        });
    }
    if sb.take_key_frame_request() {
        request_key_frame(pc, state, now);
    }
}

/// Write a PLI for the remote video stream on the (single) receiver.
fn request_key_frame(pc: &mut RTCPeerConnection, state: &RoleState, now: Instant) {
    let Some(media_ssrc) = state.remote_video_ssrc else {
        return;
    };
    let receivers: Vec<_> = pc.get_receivers().collect();
    for id in receivers {
        if let Some(mut receiver) = pc.rtp_receiver(id) {
            let pli = PictureLossIndication {
                sender_ssrc: state.pli_sender_ssrc,
                media_ssrc,
            };
            match receiver.write_rtcp(now, vec![Box::new(pli)]) {
                Ok(()) => tracing::debug!("transport: gap given up; requested a key frame"),
                Err(e) => tracing::debug!("transport: key-frame request failed: {e}"),
            }
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn parse_stun_url_applies_default_port() {
        assert_eq!(
            parse_stun_url("stun:stun.l.google.com:19302").as_deref(),
            Some("stun.l.google.com:19302")
        );
        assert_eq!(
            parse_stun_url("stun:stun.example.com").as_deref(),
            Some("stun.example.com:3478")
        );
        assert_eq!(
            parse_stun_url("stuns:stun.example.com").as_deref(),
            Some("stun.example.com:3478")
        );
        // Query suffix is dropped.
        assert_eq!(
            parse_stun_url("stun:stun.example.com?transport=udp").as_deref(),
            Some("stun.example.com:3478")
        );
        // Non-STUN URLs are ignored here (ICE handles turn:).
        assert_eq!(parse_stun_url("turn:turn.example.com:3478"), None);
    }

    #[test]
    fn host_candidate_ips_concrete_bind_is_itself() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5));
        assert_eq!(host_candidate_ips(ip), vec![ip]);
        // Loopback is a concrete address too, so it maps to itself — this is
        // what lets the loopback test connect without STUN.
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert_eq!(host_candidate_ips(lo), vec![lo]);
    }

    #[test]
    fn host_candidate_ips_wildcard_enumerates_interfaces() {
        // A wildcard bind expands to real interface addresses; there is always
        // at least loopback, and none of them is the wildcard itself.
        let ips = host_candidate_ips(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert!(!ips.is_empty(), "expected at least one interface address");
        assert!(ips.iter().all(|ip| ip.is_ipv4()));
        assert!(ips.iter().all(|ip| !ip.is_unspecified()));
    }

    #[test]
    fn build_host_candidate_serializes_srflx_free_line() {
        let init = build_host_candidate(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000).unwrap();
        assert!(init.candidate.contains("127.0.0.1"));
        assert!(init.candidate.contains("typ host"));
    }

    /// Network-gated: runs the real srflx gathering against Google's public
    /// STUN server and asserts we learn a *public* (non-private, non-loopback)
    /// IPv4 address. Ignored by default so CI doesn't flake on network access;
    /// run with `cargo test -p rmd-transport -- --ignored`.
    #[test]
    #[ignore = "requires outbound UDP to a public STUN server"]
    fn srflx_gathering_finds_public_address() {
        // Bind the wildcard so the OS routes STUN out our default interface.
        let socket = UdpSocket::bind("0.0.0.0:0").expect("bind udp");
        let local_addr = socket.local_addr().expect("local addr");

        let host_port = parse_stun_url("stun:stun.l.google.com:19302").expect("stun url");
        let init = gather_srflx_candidate(
            &socket,
            local_addr,
            &host_port,
            "stun:stun.l.google.com:19302",
        )
        .expect("gather did not error")
        .expect("STUN server produced a srflx candidate");

        // The a-line must announce a server-reflexive candidate.
        assert!(
            init.candidate.contains("typ srflx"),
            "expected srflx candidate, got: {}",
            init.candidate
        );

        // Extract the connection address (token index 4 in the candidate line):
        //   candidate:<foundation> <component> udp <priority> <address> <port> typ srflx ...
        let addr = init
            .candidate
            .split_whitespace()
            .nth(4)
            .expect("candidate has a connection address");
        let ip: Ipv4Addr = addr.parse().expect("srflx address is IPv4");

        assert!(
            !ip.is_private() && !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified(),
            "expected a public IPv4 srflx address, got {ip}"
        );
        eprintln!("discovered public srflx address: {ip}");
    }

    /// A minimal loopback TURN server (UDP, long-term credential, MD5 integrity)
    /// standing in for coturn. It answers the first `reject_first` Allocates with
    /// 437 Allocation Mismatch — what coturn says while a restarted host's previous
    /// allocation on the same 5-tuple is still live — then serves Allocate (401
    /// nonce challenge, then a signed success), Refresh and CreatePermission.
    mod fake_turn {
        use super::*;
        use rtci::stun::attributes::ATTR_MESSAGE_INTEGRITY;
        use rtci::stun::attributes::{ATTR_NONCE, ATTR_REALM};
        use rtci::stun::error_code::{
            CODE_ALLOC_MISMATCH, CODE_UNAUTHORIZED, ErrorCode, ErrorCodeAttribute,
        };
        use rtci::stun::fingerprint::FINGERPRINT;
        use rtci::stun::integrity::MessageIntegrity;
        use rtci::stun::message::{
            CLASS_ERROR_RESPONSE, CLASS_REQUEST, CLASS_SUCCESS_RESPONSE, METHOD_ALLOCATE,
            METHOD_REFRESH, MessageClass, MessageType, Setter,
        };
        use rtci::stun::textattrs::{Nonce, Realm};
        use rtci::turn::proto::lifetime::Lifetime;
        use rtci::turn::proto::relayaddr::RelayedAddress;
        use std::sync::atomic::{AtomicBool, AtomicUsize};

        pub(super) const USERNAME: &str = "user";
        pub(super) const PASSWORD: &str = "pass";
        const REALM: &str = "rmd-test";
        /// The relayed address the fake hands out (TEST-NET-1; never routed).
        pub(super) const RELAYED: &str = "192.0.2.15:50000";

        pub(super) struct FakeTurn {
            pub(super) addr: SocketAddr,
            /// Allocates refused with 437 so far.
            pub(super) rejected: Arc<AtomicUsize>,
            /// Signed Allocates granted so far.
            pub(super) allocated: Arc<AtomicUsize>,
            /// Whether a Refresh with LIFETIME 0 (a release) arrived.
            pub(super) released: Arc<AtomicBool>,
            stop: Arc<AtomicBool>,
            thread: Option<std::thread::JoinHandle<()>>,
        }

        impl FakeTurn {
            pub(super) fn spawn(reject_first: usize) -> Self {
                let socket = UdpSocket::bind("127.0.0.1:0").expect("bind fake TURN");
                socket
                    .set_read_timeout(Some(Duration::from_millis(20)))
                    .expect("read timeout");
                let addr = socket.local_addr().expect("fake TURN addr");
                let rejected = Arc::new(AtomicUsize::new(0));
                let allocated = Arc::new(AtomicUsize::new(0));
                let released = Arc::new(AtomicBool::new(false));
                let stop = Arc::new(AtomicBool::new(false));
                let (r, a, rel, st) = (
                    rejected.clone(),
                    allocated.clone(),
                    released.clone(),
                    stop.clone(),
                );
                let thread = std::thread::spawn(move || {
                    serve(&socket, reject_first, &r, &a, &rel, &st);
                });
                Self {
                    addr,
                    rejected,
                    allocated,
                    released,
                    stop,
                    thread: Some(thread),
                }
            }

            /// ICE config pointing at this server with its credential.
            pub(super) fn ice_servers(&self) -> Vec<IceServer> {
                vec![IceServer {
                    urls: vec![format!("turn:{}?transport=udp", self.addr)],
                    username: Some(USERNAME.to_owned()),
                    credential: Some(PASSWORD.to_owned()),
                }]
            }
        }

        impl Drop for FakeTurn {
            fn drop(&mut self) {
                self.stop.store(true, Ordering::Relaxed);
                if let Some(t) = self.thread.take() {
                    let _ = t.join();
                }
            }
        }

        fn serve(
            socket: &UdpSocket,
            reject_first: usize,
            rejected: &AtomicUsize,
            allocated: &AtomicUsize,
            released: &AtomicBool,
            stop: &AtomicBool,
        ) {
            let provider = rtci::crypto::default_provider().expect("crypto provider");
            let key = MessageIntegrity::long_term_integrity_key(
                USERNAME.to_owned(),
                REALM.to_owned(),
                PASSWORD.to_owned(),
                provider.crypto(),
            )
            .expect("long-term key");
            let relayed: SocketAddr = RELAYED.parse().unwrap();
            let mut buf = vec![0u8; 2048];
            while !stop.load(Ordering::Relaxed) {
                let Ok((n, from)) = socket.recv_from(&mut buf) else {
                    continue;
                };
                let mut req = Message::new();
                if req.write(&buf[..n]).is_err() || req.typ.class != CLASS_REQUEST {
                    continue; // indications / ChannelData / junk
                }
                let signed = req.contains(ATTR_MESSAGE_INTEGRITY);
                let error = |code: ErrorCode, extra: Vec<Box<dyn Setter>>| {
                    let mut attrs: Vec<Box<dyn Setter>> = vec![Box::new(ErrorCodeAttribute {
                        code,
                        reason: b"test".to_vec(),
                    })];
                    attrs.extend(extra);
                    (CLASS_ERROR_RESPONSE, attrs, false)
                };
                let (class, attrs, sign): (MessageClass, Vec<Box<dyn Setter>>, bool) =
                    if req.typ.method == METHOD_ALLOCATE && !signed {
                        if rejected.load(Ordering::Relaxed) < reject_first {
                            rejected.fetch_add(1, Ordering::Relaxed);
                            error(CODE_ALLOC_MISMATCH, vec![])
                        } else {
                            error(
                                CODE_UNAUTHORIZED,
                                vec![
                                    Box::new(Nonce::new(ATTR_NONCE, "nonce".to_owned())),
                                    Box::new(Realm::new(ATTR_REALM, REALM.to_owned())),
                                ],
                            )
                        }
                    } else if req.typ.method == METHOD_ALLOCATE {
                        allocated.fetch_add(1, Ordering::Relaxed);
                        (
                            CLASS_SUCCESS_RESPONSE,
                            vec![
                                Box::new(RelayedAddress {
                                    ip: relayed.ip(),
                                    port: relayed.port(),
                                }),
                                Box::new(XorMappedAddress {
                                    ip: from.ip(),
                                    port: from.port(),
                                }),
                                Box::new(Lifetime(Duration::from_secs(600))),
                            ],
                            true,
                        )
                    } else if req.typ.method == METHOD_REFRESH {
                        let mut lifetime = Lifetime::default();
                        let _ = lifetime.get_from(&req);
                        if lifetime.0.is_zero() {
                            released.store(true, Ordering::Relaxed);
                        }
                        (
                            CLASS_SUCCESS_RESPONSE,
                            vec![Box::new(lifetime) as Box<dyn Setter>],
                            true,
                        )
                    } else {
                        (CLASS_SUCCESS_RESPONSE, vec![], true) // CreatePermission etc.
                    };
                let mut setters: Vec<Box<dyn Setter + '_>> = vec![
                    Box::new(req.transaction_id),
                    Box::new(MessageType::new(req.typ.method, class)),
                ];
                setters.extend(attrs);
                if sign {
                    setters.push(Box::new(MessageIntegrity::new_raw_integrity_with_provider(
                        key.clone(),
                        provider.crypto(),
                    )));
                }
                setters.push(Box::new(FINGERPRINT));
                let mut reply = Message::new();
                if reply.build(&setters).is_ok() {
                    let _ = socket.send_to(&reply.raw, from);
                }
            }
        }
    }

    /// A host whose startup Allocate is refused with 437 schedules an idle retry,
    /// defers it while a session is on the socket, recovers the relay once idle,
    /// and releases the allocation (Refresh lifetime=0, confirmed) at exit.
    #[test]
    fn host_turn_retries_after_437_then_releases() {
        let server = fake_turn::FakeTurn::spawn(1);
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind host socket");
        let local_addr = socket.local_addr().unwrap();

        let mut turn = HostTurn::start(&socket, local_addr, &server.ice_servers());
        assert_eq!(server.rejected.load(Ordering::Relaxed), 1);
        assert!(turn.relay.is_none() && turn.cand.is_none());
        assert_eq!(turn.attempts, 1);
        let due = turn.retry_at.expect("a retry is scheduled after the 437");

        // Not yet due: nothing happens.
        assert!(
            turn.maybe_retry(&socket, local_addr, due - Duration::from_secs(1), true)
                .is_none()
        );
        assert_eq!(turn.retry_at, Some(due));

        // Due but a session is on the socket: pushed back a full interval, no Allocate.
        assert!(turn.maybe_retry(&socket, local_addr, due, false).is_none());
        assert_eq!(turn.retry_at, Some(due + TURN_RETRY_INTERVAL));
        assert_eq!(server.allocated.load(Ordering::Relaxed), 0);

        // Due and idle: recovers, and the relay is stored for later sessions.
        let due = turn.retry_at.unwrap();
        let cand = turn
            .maybe_retry(&socket, local_addr, due, true)
            .expect("relay recovered on the idle retry");
        assert!(cand.candidate.contains("typ relay"), "{}", cand.candidate);
        assert!(
            cand.candidate.contains("192.0.2.15 50000"),
            "{}",
            cand.candidate
        );
        assert_eq!(server.allocated.load(Ordering::Relaxed), 1);
        assert!(turn.relay.is_some());
        assert_eq!(turn.cand.as_ref(), Some(&cand));
        assert_eq!(turn.retry_at, None, "no retry once allocated");

        // Exit: the allocation is released on the server and confirmed.
        assert!(turn.release(&socket, local_addr), "release confirmed");
        assert!(server.released.load(Ordering::Relaxed));
        assert!(turn.relay.is_none() && turn.cand.is_none() && turn.retry_at.is_none());
    }

    /// No credentialed TURN server: nothing to retry.
    #[test]
    fn host_turn_without_turn_server_never_retries() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind host socket");
        let local_addr = socket.local_addr().unwrap();
        let stun_only = vec![IceServer::urls(vec!["stun:127.0.0.1:9".to_owned()])];
        let turn = HostTurn::start(&socket, local_addr, &stun_only);
        assert!(turn.relay.is_none() && turn.retry_at.is_none());
    }

    /// `release_turn_allocations` reaches a live host driver through the global
    /// registry and blocks until its allocation is released on the server.
    #[test]
    fn release_turn_allocations_releases_live_host() {
        let server = fake_turn::FakeTurn::spawn(0);
        let transport = crate::Transport::spawn(TransportConfig {
            role: TransportRole::Host,
            ice_servers: server.ice_servers(),
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            video_bitrate_bps: 1_000_000,
            video_codec: VideoCodec::H264,
        })
        .expect("spawn host transport");
        // The driver allocates during startup; wait for it.
        let deadline = Instant::now() + Duration::from_secs(5);
        while server.allocated.load(Ordering::Relaxed) == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(server.allocated.load(Ordering::Relaxed), 1);
        // Let the event loop take over the socket (the offer is emitted first).
        let _ = transport.recv_event_timeout(Duration::from_secs(2));

        crate::release_turn_allocations(Duration::from_millis(1500));
        assert!(
            server.released.load(Ordering::Relaxed),
            "allocation released"
        );
        drop(transport);
    }
}
