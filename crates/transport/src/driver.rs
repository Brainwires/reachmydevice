//! Sans-IO WebRTC driver loop (runs on the transport thread).
//!
//! Owns the `rtc` `RTCPeerConnection`, the UDP socket, the H.264 RTP
//! packetizer/depacketizer, and the data channel, and pumps the sans-IO state
//! machine: drain [`DriverCmd`]s, `poll_write` → socket, socket → `handle_read`,
//! advance timers, drain `poll_event`/`poll_read` → [`TransportEvent`]s. Also
//! enables GCC (host) and publishes its target bitrate.
//!
//! # Roles
//!
//! - **Host** = offerer + video sender. Adds an H.264 send track and the
//!   reliable/ordered `control` data channel, creates the offer, and runs the
//!   sender-side GCC + TWCC congestion-control interceptors.
//! - **Viewer** = answerer + video receiver. Adds a `recvonly` H.264
//!   transceiver, answers the offer, reassembles the incoming track into
//!   Annex-B access units, and uses the default interceptors (which include the
//!   TWCC *receiver* that feeds the host's GCC).
//!
//! The `rtc` `RTCPeerConnection` is generic over its interceptor chain type
//! `I`, and the host (with GCC) and viewer (defaults) build *different*
//! concrete chains. Rather than unify the types, each role builds its own `pc`
//! locally and hands it to the generic [`event_loop`], which is monomorphised
//! once per role.

use crate::{DriverCmd, SignalMsg, TransportConfig, TransportEvent, TransportRole};
use anyhow::Context;
use bytes::{Bytes, BytesMut};
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rtc::data_channel::{RTCDataChannelId, RTCDataChannelInit};
use rtc::interceptor::{
    GccHandle, GccInterceptorBuilder, Interceptor, Registry, TwccSenderBuilder,
};
use rtc::media::io::sample_builder::SampleBuilder;
use rtc::media_stream::MediaStreamTrack;
use rtc::peer_connection::configuration::interceptor_registry::{
    configure_nack, configure_rtcp_reports, register_default_interceptors,
};
use rtc::peer_connection::configuration::media_engine::{MediaEngine, MIME_TYPE_H264};
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, RTCDtlsRole, RTCIceCandidate, RTCIceCandidateInit,
    RTCIceServer,
};
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::rtp::codec::h264::H264Packet;
use rtc::rtp::packetizer::{new_packetizer, Packetizer};
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    RtpCodecKind,
};
use rtc::rtp_transceiver::{
    RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverInit, SSRC,
};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};

/// H.264 clock rate (Hz) — RTP timestamps advance at 90 kHz.
const VIDEO_CLOCK_RATE: u32 = 90_000;
/// H.264 dynamic payload type used on the wire.
const VIDEO_PAYLOAD_TYPE: u8 = 102;
/// Outbound RTP MTU (bytes) for the packetizer, leaving headroom under 1500.
const RTP_OUTBOUND_MTU: usize = 1200;
/// `SampleBuilder` reorder window, in RTP sequence numbers.
const SAMPLE_BUILDER_MAX_LATE: u16 = 128;
/// Upper bound on how long a single socket read may block, so command and
/// timeout servicing stays responsive without busy-spinning.
const MAX_SOCKET_READ_WAIT: Duration = Duration::from_millis(5);
/// `sdp_fmtp_line` announcing constrained-baseline, packetization-mode 1.
const H264_FMTP: &str = "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f";

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

/// The H.264 codec parameters shared by the send track and the RTP packetizer.
fn h264_codec_params() -> RTCRtpCodecParameters {
    RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: MIME_TYPE_H264.to_owned(),
            clock_rate: VIDEO_CLOCK_RATE,
            channels: 0,
            sdp_fmtp_line: H264_FMTP.to_owned(),
            rtcp_feedback: vec![],
        },
        payload_type: VIDEO_PAYLOAD_TYPE,
    }
}

/// Translate the app's ICE-server URL strings into `rtc`'s config type.
fn ice_servers(urls: &[String]) -> Vec<RTCIceServer> {
    if urls.is_empty() {
        return vec![];
    }
    vec![RTCIceServer {
        urls: urls.to_vec(),
        ..Default::default()
    }]
}

/// Build the local UDP socket and the matching host ICE candidate.
///
/// Returns the socket, its bound local address, and the candidate serialized as
/// a signaling string (the `candidate:` a-line value) to hand to the peer.
fn bind_socket_and_candidate(
    bind_addr: SocketAddr,
) -> anyhow::Result<(UdpSocket, SocketAddr, RTCIceCandidateInit)> {
    let socket = UdpSocket::bind(bind_addr).context("bind transport UDP socket")?;
    let local_addr = socket.local_addr().context("read local addr")?;

    let candidate = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: local_addr.ip().to_string(),
            port: local_addr.port(),
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    }
    .new_candidate_host()
    .context("build host candidate")?;
    let candidate_init = RTCIceCandidate::from(&candidate)
        .to_json()
        .context("serialize host candidate")?;

    Ok((socket, local_addr, candidate_init))
}

/// Host: offerer + video sender, with sender-side GCC + TWCC.
fn run_host(
    config: TransportConfig,
    cmd_rx: Receiver<DriverCmd>,
    event_tx: Sender<TransportEvent>,
    bitrate_bps: Arc<AtomicU32>,
) -> anyhow::Result<()> {
    let (socket, local_addr, local_candidate) = bind_socket_and_candidate(config.bind_addr)?;

    // Media engine: register the H.264 send codec.
    let mut media_engine = MediaEngine::default();
    let codec = h264_codec_params();
    media_engine
        .register_codec(codec.clone(), RtpCodecKind::Video)
        .context("register H264 codec")?;

    // Interceptor chain. NACK + RTCP reports come from the shared helpers; on top
    // of those we stack the congestion-control pair required for GCC:
    //   GCC (innermost) ← TwccSender (outer, stamps the transport-wide seq no.)
    // GccInterceptorBuilder hands back a `GccHandle` we poll each tick for the
    // latest target bitrate. The header extension + feedback that let the viewer
    // reply with TWCC are registered on the media engine below.
    let registry = Registry::new();
    let registry = configure_nack(registry, &mut media_engine);
    let registry = configure_rtcp_reports(registry);
    register_twcc_sender_headers(&mut media_engine).context("register TWCC headers")?;
    let (gcc_builder, gcc_handle) = GccInterceptorBuilder::new();
    let registry = registry
        .with(gcc_builder.build())
        .with(TwccSenderBuilder::new().build());

    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(
            RTCConfigurationBuilder::new()
                .with_ice_servers(ice_servers(&config.ice_servers))
                .build(),
        )
        .with_setting_engine(SettingEngine::default())
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build()
        .context("build host peer connection")?;

    // Add the video send track (its SSRC drives the packetizer) and the reliable
    // ordered control data channel *before* creating the offer, so both are
    // negotiated in the initial SDP.
    let video_ssrc: SSRC = rand::random();
    let track = MediaStreamTrack::new(
        "openreach-video".to_owned(),
        "openreach-video-track".to_owned(),
        "openreach-video-label".to_owned(),
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

    // Kick off signaling: create + apply the offer, then surface it and our host
    // candidate for the app to relay to the peer.
    let offer = pc.create_offer(None).context("create offer")?;
    pc.set_local_description(offer.clone())
        .context("set local offer")?;
    pc.add_local_candidate(local_candidate.clone())
        .context("add local candidate")?;
    emit_session(&event_tx, &offer)?;
    let _ = event_tx.send(TransportEvent::LocalSignal(SignalMsg::Candidate(
        local_candidate.candidate.clone(),
    )));

    // Packetizer for outbound Annex-B access units.
    let packetizer: Box<dyn Packetizer> = Box::new(new_packetizer(
        RTP_OUTBOUND_MTU,
        VIDEO_PAYLOAD_TYPE,
        video_ssrc,
        codec.rtp_codec.payloader().context("h264 payloader")?,
        Box::new(rtc::rtp::sequence::new_random_sequencer()),
        VIDEO_CLOCK_RATE,
    ));

    let mut state = RoleState {
        gcc: Some(gcc_handle),
        video: Some(VideoSend {
            sender_id: video_sender_id,
            ssrc: video_ssrc,
            packetizer,
            last_ts_micros: None,
        }),
        sample_builder: None,
        data_channel_id: None,
        local_candidate: None, // already added above
        remote_description_set: false,
        pending_remote_candidates: Vec::new(),
        bitrate_bps,
    };

    event_loop(&mut pc, &socket, local_addr, &cmd_rx, &event_tx, &mut state)
}

/// Viewer: answerer + video receiver, default interceptors (incl. TWCC receiver).
fn run_viewer(
    config: TransportConfig,
    cmd_rx: Receiver<DriverCmd>,
    event_tx: Sender<TransportEvent>,
    bitrate_bps: Arc<AtomicU32>,
) -> anyhow::Result<()> {
    let (socket, local_addr, local_candidate) = bind_socket_and_candidate(config.bind_addr)?;

    let mut media_engine = MediaEngine::default();
    media_engine
        .register_codec(h264_codec_params(), RtpCodecKind::Video)
        .context("register H264 codec")?;

    // Default interceptors give us NACK, RTCP reports, and — crucially for the
    // host's GCC — the TWCC *receiver* that generates congestion feedback.
    let registry = Registry::new();
    let registry = register_default_interceptors(registry, &mut media_engine)
        .context("default interceptors")?;

    // As the answerer we take the DTLS server role (host becomes the client).
    let mut setting_engine = SettingEngine::default();
    setting_engine
        .set_answering_dtls_role(RTCDtlsRole::Server)
        .context("set answering DTLS role")?;

    let mut pc = RTCPeerConnectionBuilder::new()
        .with_configuration(
            RTCConfigurationBuilder::new()
                .with_ice_servers(ice_servers(&config.ice_servers))
                .build(),
        )
        .with_setting_engine(setting_engine)
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build()
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

    // The viewer's own host candidate is added and surfaced only after it
    // answers the offer (a local description must exist first), so it is stashed
    // in RoleState and handled in `apply_signal`.

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
        video: None,
        sample_builder: Some(sample_builder),
        data_channel_id: None,
        local_candidate: Some(local_candidate),
        remote_description_set: false,
        pending_remote_candidates: Vec::new(),
        bitrate_bps,
    };

    event_loop(&mut pc, &socket, local_addr, &cmd_rx, &event_tx, &mut state)
}

/// Register the RTP header extension + RTCP feedback that TWCC needs on the
/// sender side (video). Mirrors `configure_twcc_sender_only` but is inlined so
/// the GCC/TwccSender interceptor pair can be stacked in the caller's chain.
fn register_twcc_sender_headers(media_engine: &mut MediaEngine) -> anyhow::Result<()> {
    use rtc::rtp_transceiver::rtp_sender::{RTCPFeedback, RTCRtpHeaderExtensionCapability};

    media_engine.register_feedback(
        RTCPFeedback {
            typ: "transport-cc".to_owned(),
            parameter: String::new(),
        },
        RtpCodecKind::Video,
    );
    media_engine
        .register_header_extension(
            RTCRtpHeaderExtensionCapability {
                uri: rtc::sdp::extmap::TRANSPORT_CC_URI.to_owned(),
            },
            RtpCodecKind::Video,
            None,
        )
        .context("register transport-cc extension")?;
    Ok(())
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
    /// GCC handle (host only) — polled each tick for the target bitrate.
    gcc: Option<GccHandle>,
    /// Video send path (host only).
    video: Option<VideoSend>,
    /// Video receive reassembly (viewer only).
    sample_builder: Option<SampleBuilder<H264Packet>>,
    /// Id of the open `control` data channel, once its `OnOpen` fires.
    data_channel_id: Option<RTCDataChannelId>,
    /// Our own host candidate, added to the local agent once a local
    /// description exists. The host adds it eagerly at startup and clears this;
    /// the viewer adds it when it answers the offer.
    local_candidate: Option<RTCIceCandidateInit>,
    /// Whether a remote description has been applied yet. `add_remote_candidate`
    /// is only valid afterwards, so candidates that arrive early are buffered.
    remote_description_set: bool,
    /// Remote candidates received before the remote description was set.
    pending_remote_candidates: Vec<String>,
    /// Shared cell the encoder reads for its bitrate target.
    bitrate_bps: Arc<AtomicU32>,
}

/// Emit a local offer/answer as a JSON-encoded signaling message.
fn emit_session(
    event_tx: &Sender<TransportEvent>,
    desc: &RTCSessionDescription,
) -> anyhow::Result<()> {
    let json = serde_json::to_string(desc).context("serialize session description")?;
    let msg = if desc.sdp_type == rtc::peer_connection::sdp::RTCSdpType::Offer {
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
fn event_loop<I: Interceptor>(
    pc: &mut rtc::peer_connection::RTCPeerConnection<I>,
    socket: &UdpSocket,
    local_addr: SocketAddr,
    cmd_rx: &Receiver<DriverCmd>,
    event_tx: &Sender<TransportEvent>,
    state: &mut RoleState,
) -> anyhow::Result<()> {
    let mut connected = false;
    let mut read_buf = vec![0u8; 2048];

    loop {
        // 1. Drain application commands.
        if let CommandOutcome::Shutdown = drain_commands(pc, cmd_rx, event_tx, state) {
            break;
        }

        // 2. Flush all pending outbound datagrams.
        while let Some(msg) = pc.poll_write() {
            if let Err(e) = socket.send_to(&msg.message, msg.transport.peer_addr) {
                tracing::debug!("transport: socket send_to error: {e}");
            }
        }

        // 3. Surface connection-state and ICE-candidate events.
        drain_events(pc, event_tx, state, &mut connected);

        // 4. Drain inbound media / data.
        drain_reads(pc, event_tx, state);

        // 5. Publish the latest GCC estimate (host only).
        if let Some(gcc) = &state.gcc {
            if let Some(bps) = gcc.target_bitrate_bps() {
                let prev = state.bitrate_bps.swap(bps, Ordering::Relaxed);
                if prev != bps {
                    tracing::debug!("transport: GCC target bitrate -> {bps} bps");
                }
            }
        }

        // 6. Service the sans-IO timer, then wait (bounded) for the next
        //    datagram so both timeouts and commands stay responsive.
        let now = Instant::now();
        let deadline = pc.poll_timeout();
        if let Some(eto) = deadline {
            if eto <= now {
                pc.handle_timeout(now).context("handle_timeout")?;
                continue; // re-run the pump immediately after a fired timer
            }
        }

        let wait = deadline
            .map(|eto| eto.saturating_duration_since(now))
            .unwrap_or(MAX_SOCKET_READ_WAIT)
            .min(MAX_SOCKET_READ_WAIT);
        socket
            .set_read_timeout(Some(wait.max(Duration::from_millis(1))))
            .context("set socket read timeout")?;

        match socket.recv_from(&mut read_buf) {
            Ok((n, peer_addr)) => {
                pc.handle_read(TaggedBytesMut {
                    now: Instant::now(),
                    transport: TransportContext {
                        local_addr,
                        peer_addr,
                        ecn: None,
                        transport_protocol: TransportProtocol::UDP,
                    },
                    message: BytesMut::from(&read_buf[..n]),
                })
                .context("handle_read")?;
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

    let _ = pc.close();
    Ok(())
}

/// Whether the command drain asked the loop to keep running or shut down.
enum CommandOutcome {
    Continue,
    Shutdown,
}

/// Apply every currently queued [`DriverCmd`].
fn drain_commands<I: Interceptor>(
    pc: &mut rtc::peer_connection::RTCPeerConnection<I>,
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
            Ok(DriverCmd::Shutdown) => return CommandOutcome::Shutdown,
            Err(TryRecvError::Empty) => return CommandOutcome::Continue,
            // The Transport handle was dropped — tear down cleanly.
            Err(TryRecvError::Disconnected) => return CommandOutcome::Shutdown,
        }
    }
}

/// Packetize and send one Annex-B access unit on the video track (host).
fn send_video<I: Interceptor>(
    pc: &mut rtc::peer_connection::RTCPeerConnection<I>,
    state: &mut RoleState,
    annexb: &Bytes,
    ts_micros: u64,
) {
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

    let packets = match video.packetizer.packetize(annexb, samples) {
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
        if let Some(mut sender) = pc.rtp_sender(sender_id) {
            if let Err(e) = sender.write_rtp(packet) {
                // Common before negotiation completes; not fatal.
                tracing::trace!("transport: write_rtp dropped: {e}");
            }
        }
    }
}

/// Send bytes on the control data channel (either role, once open).
fn send_data<I: Interceptor>(
    pc: &mut rtc::peer_connection::RTCPeerConnection<I>,
    state: &mut RoleState,
    bytes: &Bytes,
) {
    let Some(id) = state.data_channel_id else {
        tracing::debug!("transport: data channel not open yet, dropping send");
        return;
    };
    if let Some(mut dc) = pc.data_channel(id) {
        if let Err(e) = dc.send(BytesMut::from(bytes.as_ref())) {
            tracing::debug!("transport: data channel send error: {e}");
        }
    }
}

/// Apply a peer signaling message (offer/answer/candidate).
fn apply_signal<I: Interceptor>(
    pc: &mut rtc::peer_connection::RTCPeerConnection<I>,
    event_tx: &Sender<TransportEvent>,
    state: &mut RoleState,
    msg: SignalMsg,
) -> anyhow::Result<()> {
    match msg {
        SignalMsg::Offer(json) => {
            // Viewer path: apply the remote offer, then add our own host
            // candidate (a local description must exist first), answer, and
            // surface the answer + candidate.
            let offer: RTCSessionDescription =
                serde_json::from_str(&json).context("parse remote offer")?;
            pc.set_remote_description(offer)
                .context("set remote offer")?;
            state.remote_description_set = true;

            if let Some(local) = state.local_candidate.take() {
                pc.add_local_candidate(local.clone())
                    .context("add local candidate")?;
                let answer = pc.create_answer(None).context("create answer")?;
                pc.set_local_description(answer.clone())
                    .context("set local answer")?;
                emit_session(event_tx, &answer)?;
                let _ = event_tx.send(TransportEvent::LocalSignal(SignalMsg::Candidate(
                    local.candidate,
                )));
            } else {
                let answer = pc.create_answer(None).context("create answer")?;
                pc.set_local_description(answer.clone())
                    .context("set local answer")?;
                emit_session(event_tx, &answer)?;
            }
            flush_remote_candidates(pc, state);
        }
        SignalMsg::Answer(json) => {
            // Host path: apply the remote answer.
            let answer: RTCSessionDescription =
                serde_json::from_str(&json).context("parse remote answer")?;
            pc.set_remote_description(answer)
                .context("set remote answer")?;
            state.remote_description_set = true;
            flush_remote_candidates(pc, state);
        }
        SignalMsg::Candidate(candidate) => {
            // `add_remote_candidate` requires the remote description to be set.
            // If it hasn't arrived yet, buffer and replay after it does.
            if state.remote_description_set {
                if let Err(e) = pc.add_remote_candidate(RTCIceCandidateInit {
                    candidate,
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
fn flush_remote_candidates<I: Interceptor>(
    pc: &mut rtc::peer_connection::RTCPeerConnection<I>,
    state: &mut RoleState,
) {
    for candidate in state.pending_remote_candidates.drain(..) {
        if let Err(e) = pc.add_remote_candidate(RTCIceCandidateInit {
            candidate,
            ..Default::default()
        }) {
            tracing::debug!("transport: buffered add_remote_candidate failed: {e}");
        }
    }
}

/// Drain connection-state changes and ICE candidates into events.
fn drain_events<I: Interceptor>(
    pc: &mut rtc::peer_connection::RTCPeerConnection<I>,
    event_tx: &Sender<TransportEvent>,
    state: &mut RoleState,
    connected: &mut bool,
) {
    while let Some(event) = pc.poll_event() {
        match event {
            RTCPeerConnectionEvent::OnConnectionStateChangeEvent(s) => match s {
                RTCPeerConnectionState::Connected if !*connected => {
                    *connected = true;
                    let _ = event_tx.send(TransportEvent::Connected);
                }
                RTCPeerConnectionState::Failed
                | RTCPeerConnectionState::Closed
                | RTCPeerConnectionState::Disconnected
                    if *connected =>
                {
                    *connected = false;
                    let _ = event_tx.send(TransportEvent::Disconnected);
                }
                _ => {}
            },
            RTCPeerConnectionEvent::OnIceCandidateEvent(ice) => {
                if let Ok(init) = ice.candidate.to_json() {
                    if !init.candidate.is_empty() {
                        let _ = event_tx.send(TransportEvent::LocalSignal(SignalMsg::Candidate(
                            init.candidate,
                        )));
                    }
                }
            }
            RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) => {
                state.data_channel_id = Some(id);
            }
            _ => {}
        }
    }
}

/// Drain inbound RTP (→ reassembled video) and data-channel messages.
fn drain_reads<I: Interceptor>(
    pc: &mut rtc::peer_connection::RTCPeerConnection<I>,
    event_tx: &Sender<TransportEvent>,
    state: &mut RoleState,
) {
    while let Some(message) = pc.poll_read() {
        match message {
            RTCMessage::RtpPacket(_track_id, packet) => {
                if let Some(sb) = state.sample_builder.as_mut() {
                    let ts = packet.header.timestamp;
                    sb.push(packet);
                    // Drain any completed access units.
                    while let Some(sample) = sb.pop() {
                        let _ = event_tx.send(TransportEvent::Video {
                            annexb: sample.data,
                            ts_hint: u64::from(ts),
                        });
                    }
                }
            }
            RTCMessage::DataChannelMessage(_id, msg) => {
                let _ = event_tx.send(TransportEvent::Data(msg.data.freeze()));
            }
            RTCMessage::RtcpPacket(_, _) => {
                // Processed by interceptors already; nothing app-visible here.
            }
        }
    }
}
