// ReachMyDevice <-> Deno WebRTC interop: the Deno side (a viewer).
//
// A headless viewer built on Deno's own `RTCPeerConnection` (the Brainwires
// Deno fork's `ext/webrtc`, which runs on the same webrtc-rs-rtc engine fork as
// rmd-transport, but through its own peer/ICE/socket layer and the W3C API).
// It is driven by `crates/session/tests/interop_deno.rs`, which runs the host:
// rmd-transport's Host role + rmd-protocol framing + real openh264 encode of
// synthetic frames.
//
// Signaling is one JSON object per line: the host's `SignalMsg`s arrive on
// stdin (`{"type":"offer"|"candidate","data":...}`) and this script writes its
// answer / candidates and its reports to stdout in the same shape. Logs go to
// stderr. Loopback only: the connection's sockets are bound to 127.0.0.1.
//
// What it checks on its side (and reports, so the Rust test asserts too):
//   - ICE + DTLS connect (connectionState "connected");
//   - the `control` data channel carries rmd-protocol `Envelope`s both ways:
//     Hello -> HelloAck(accepted), the host's Ping -> our Pong, our Ping -> the
//     host's Pong (t_micros echoed);
//   - H.264 RTP arrives (Deno.webrtc.readRtp), depacketizes (RFC 6184 single
//     NAL / STAP-A / FU-A) into Annex-B access units, and the first keyframe
//     carries SPS + PPS + IDR whose SPS parses to the expected size; the access
//     units are forwarded to the host side, which decodes them with openh264;
//   - after that keyframe, an RTCP PLI (Deno.webrtc.requestKeyFrame), which the
//     host must surface as a keyframe request;
//   - a clean close: on {"type":"close"} we send Bye, close the data channel
//     (the Bye must arrive before the close), wait for its "close" event, close
//     the connection and exit 0.
//
// Run through the Rust test (see README.md); by hand:
//   deno run --no-config --allow-net=127.0.0.1 --allow-env viewer.ts

const enc = new TextEncoder();
const dec = new TextDecoder();
const log = (...a: unknown[]) => console.error("[deno-viewer]", ...a);
const out = (o: unknown) => Deno.stdout.writeSync(enc.encode(JSON.stringify(o) + "\n"));
const fail = (why: string): never => {
  log("FAIL:", why);
  out({ type: "fail", data: why });
  Deno.exit(1);
};

const TIMEOUT_MS = Number(Deno.env.get("RMD_INTEROP_TIMEOUT_MS") ?? "30000");
const EXPECT_W = Number(Deno.env.get("RMD_INTEROP_WIDTH") ?? "320");
const EXPECT_H = Number(Deno.env.get("RMD_INTEROP_HEIGHT") ?? "240");
const FORWARD_AUS = Number(Deno.env.get("RMD_INTEROP_FORWARD_AUS") ?? "10");
setTimeout(() => fail(`timed out after ${TIMEOUT_MS} ms`), TIMEOUT_MS);

// --- a minimal protobuf codec for rmd.v1.Envelope ----------------------------
// (crates/protocol/proto/rmd.proto). Only what this interop needs.

const PROTOCOL_MAJOR = 1;
const PROTOCOL_MINOR = 7;
const F = { hello: 10, helloAck: 11, ping: 13, pong: 14, bye: 15 } as const;

function varint(n: bigint | number): number[] {
  let v = BigInt(n);
  const b: number[] = [];
  do {
    let byte = Number(v & 0x7fn);
    v >>= 7n;
    if (v > 0n) byte |= 0x80;
    b.push(byte);
  } while (v > 0n);
  return b;
}
const tag = (field: number, wire: number) => varint((field << 3) | wire);
const fVarint = (field: number, v: bigint | number) => [...tag(field, 0), ...varint(v)];
const fBytes = (field: number, b: Uint8Array | number[]) => [
  ...tag(field, 2),
  ...varint(b.length),
  ...b,
];
const fString = (field: number, s: string) => fBytes(field, enc.encode(s));

function envelope(field: number, body: number[]): Uint8Array {
  return new Uint8Array([
    ...fVarint(1, PROTOCOL_MAJOR),
    ...fVarint(2, PROTOCOL_MINOR),
    ...fBytes(field, body),
  ]);
}

type Fields = Map<number, (bigint | Uint8Array)[]>;
function parse(buf: Uint8Array): Fields {
  const m: Fields = new Map();
  let i = 0;
  const rv = (): bigint => {
    let shift = 0n, v = 0n;
    for (;;) {
      if (i >= buf.length) throw new Error("truncated varint");
      const b = buf[i++];
      v |= BigInt(b & 0x7f) << shift;
      if (!(b & 0x80)) return v;
      shift += 7n;
    }
  };
  while (i < buf.length) {
    const key = Number(rv());
    const field = key >> 3, wire = key & 7;
    let val: bigint | Uint8Array;
    if (wire === 0) val = rv();
    else if (wire === 2) {
      const len = Number(rv());
      val = buf.subarray(i, i + len);
      i += len;
    } else if (wire === 1) {
      val = buf.subarray(i, i + 8);
      i += 8;
    } else if (wire === 5) {
      val = buf.subarray(i, i + 4);
      i += 4;
    } else throw new Error(`wire type ${wire}`);
    if (!m.has(field)) m.set(field, []);
    m.get(field)!.push(val);
  }
  return m;
}
const num = (m: Fields, f: number) => (m.get(f)?.[0] as bigint | undefined) ?? 0n;
const bytes = (m: Fields, f: number) => (m.get(f)?.[0] as Uint8Array | undefined);

// --- H.264 depacketization (RFC 6184) and SPS parsing ------------------------

const START = [0, 0, 0, 1];
function depacketize(payload: Uint8Array, fu: { buf: number[] | null }): number[][] {
  const nalType = payload[0] & 0x1f;
  if (nalType >= 1 && nalType <= 23) return [[...payload]];
  if (nalType === 24) { // STAP-A
    const nals: number[][] = [];
    let i = 1;
    while (i + 2 <= payload.length) {
      const size = (payload[i] << 8) | payload[i + 1];
      i += 2;
      if (size === 0 || i + size > payload.length) throw new Error("bad STAP-A");
      nals.push([...payload.subarray(i, i + size)]);
      i += size;
    }
    return nals;
  }
  if (nalType === 28) { // FU-A
    const fuHeader = payload[1];
    const start = fuHeader & 0x80, end = fuHeader & 0x40;
    if (start) fu.buf = [(payload[0] & 0xe0) | (fuHeader & 0x1f)];
    if (!fu.buf) return []; // a fragment without its start: dropped
    fu.buf.push(...payload.subarray(2));
    if (end) {
      const nal = fu.buf;
      fu.buf = null;
      return [nal];
    }
    return [];
  }
  throw new Error(`unsupported NAL packetization type ${nalType}`);
}

// Exp-Golomb reader over an RBSP (emulation-prevention bytes removed).
function rbsp(nal: number[]): number[] {
  const out: number[] = [];
  for (let i = 1; i < nal.length; i++) {
    if (i + 2 < nal.length && nal[i] === 0 && nal[i + 1] === 0 && nal[i + 2] === 3) {
      out.push(0, 0);
      i += 2;
      continue;
    }
    out.push(nal[i]);
  }
  return out;
}
function bitReader(b: number[]) {
  let pos = 0;
  const bit = () => (b[pos >> 3] >> (7 - (pos++ & 7))) & 1;
  const bits = (n: number) => {
    let v = 0;
    for (let k = 0; k < n; k++) v = (v << 1) | bit();
    return v;
  };
  const ue = () => {
    let zeros = 0;
    while (bit() === 0) if (++zeros > 31) throw new Error("bad exp-golomb");
    return (1 << zeros) - 1 + bits(zeros);
  };
  const se = () => {
    const k = ue();
    return k & 1 ? (k + 1) / 2 : -(k / 2);
  };
  return { bit, bits, ue, se };
}
function parseSps(nal: number[]) {
  const r = bitReader(rbsp(nal));
  const profile = r.bits(8);
  r.bits(8); // constraint flags + reserved
  const level = r.bits(8);
  r.ue(); // seq_parameter_set_id
  let chroma = 1;
  if ([100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135].includes(profile)) {
    chroma = r.ue();
    if (chroma === 3) r.bit();
    r.ue();
    r.ue();
    r.bit();
    if (r.bit()) {
      for (let i = 0; i < (chroma !== 3 ? 8 : 12); i++) {
        if (r.bit()) { // scaling list present: skip it
          const size = i < 6 ? 16 : 64;
          let last = 8, next = 8;
          for (let j = 0; j < size; j++) {
            if (next !== 0) next = (last + r.se() + 256) % 256;
            last = next === 0 ? last : next;
          }
        }
      }
    }
  }
  r.ue(); // log2_max_frame_num_minus4
  const pocType = r.ue();
  if (pocType === 0) r.ue();
  else if (pocType === 1) {
    r.bit();
    r.se();
    r.se();
    const n = r.ue();
    for (let i = 0; i < n; i++) r.se();
  }
  r.ue(); // max_num_ref_frames
  r.bit();
  const wMbs = r.ue() + 1, hMapUnits = r.ue() + 1;
  const frameMbsOnly = r.bit();
  if (!frameMbsOnly) r.bit();
  r.bit(); // direct_8x8_inference
  let [cl, cr, ct, cb] = [0, 0, 0, 0];
  if (r.bit()) [cl, cr, ct, cb] = [r.ue(), r.ue(), r.ue(), r.ue()];
  const subW = chroma === 1 || chroma === 2 ? 2 : 1;
  const subH = (chroma === 1 ? 2 : 1) * (2 - frameMbsOnly);
  return {
    profile,
    level,
    width: wMbs * 16 - subW * (cl + cr),
    height: (2 - frameMbsOnly) * hMapUnits * 16 - subH * (ct + cb),
  };
}

const b64 = (a: number[]) => {
  let s = "";
  for (let i = 0; i < a.length; i += 0x8000) {
    s += String.fromCharCode(...a.slice(i, i + 0x8000));
  }
  return btoa(s);
};

// --- the connection -----------------------------------------------------------

const network = Deno.webrtc.createNetwork({
  bindAddresses: ["127.0.0.1"],
  mdns: false,
});
// `denoNetwork` is the fork's non-standard RTCConfiguration member.
const pc = new RTCPeerConnection({ iceServers: [], denoNetwork: network });

let dc: RTCDataChannel | null = null;
let helloAcked = false, hostPingAnswered = false, ourPingEchoed = false;
const ourPingT = BigInt(Date.now()) * 1000n;
const report: Record<string, unknown> = {};

pc.onicecandidate = (e) => {
  if (e.candidate?.candidate) out({ type: "candidate", data: e.candidate.candidate });
};
pc.onconnectionstatechange = () => {
  log("connectionState", pc.connectionState);
  if (pc.connectionState === "connected") {
    const codecs = pc.getTransceivers().map((t) =>
      t.receiver.getParameters().codecs.map((c) => `${c.mimeType}/${c.payloadType}`)
    );
    log("receiver codecs once connected", codecs);
    out({ type: "connected" });
  }
  if (pc.connectionState === "failed") fail("connection failed");
};

const maybeReady = () => {
  if (helloAcked && hostPingAnswered && ourPingEchoed && report.keyframe) {
    out({ type: "ready", data: report });
  }
};

pc.ondatachannel = (e) => {
  dc = e.channel;
  dc.binaryType = "arraybuffer";
  log("data channel", dc.label, "ordered", dc.ordered);
  const sendHello = () => {
    // Hello { device_name, role: VIEWER(2), features: 0, supported_video_codecs: [H264(1)] }
    dc!.send(envelope(F.hello, [
      ...fString(1, "deno-interop-viewer"),
      ...fVarint(2, 2),
      ...fBytes(6, [1]), // packed repeated enum
    ]));
  };
  if (dc.readyState === "open") sendHello();
  else dc.onopen = sendHello;
  dc.onmessage = (m) => {
    const env = parse(new Uint8Array(m.data as ArrayBuffer));
    const major = Number(num(env, 1));
    if (major !== PROTOCOL_MAJOR) fail(`host protocol major ${major}`);
    if (env.has(F.helloAck)) {
      const ack = parse(bytes(env, F.helloAck)!);
      if (num(ack, 1) !== 1n) fail("HelloAck not accepted");
      if (num(ack, 7) !== 1n) fail(`HelloAck video_codec ${num(ack, 7)} != H264`);
      helloAcked = true;
      report.hostName = dec.decode(bytes(ack, 3) ?? new Uint8Array());
      report.hostMinor = Number(num(env, 2));
      log("HelloAck accepted from", report.hostName);
      dc!.send(envelope(F.ping, fVarint(1, ourPingT)));
    } else if (env.has(F.ping)) {
      const t = num(parse(bytes(env, F.ping)!), 1);
      dc!.send(envelope(F.pong, fVarint(1, t)));
      hostPingAnswered = true;
      log("answered host Ping", t);
    } else if (env.has(F.pong)) {
      const t = num(parse(bytes(env, F.pong)!), 1);
      if (t !== ourPingT) fail(`Pong echoed ${t}, sent ${ourPingT}`);
      ourPingEchoed = true;
      log("host echoed our Ping");
    } else {
      log("ignoring envelope fields", [...env.keys()]);
    }
    maybeReady();
  };
  dc.onclose = () => log("data channel close event");
};

pc.ontrack = async (e) => {
  log("track", e.track.kind, "codecs", e.receiver.getParameters().codecs.map((c) => c.mimeType));
  const reader = Deno.webrtc.readRtp(e.receiver).getReader();
  const fu = { buf: null as number[] | null };
  let au: number[][] = [], auTs: number | null = null;
  let packets = 0, forwarded = 0, aus = 0;
  const flush = () => {
    if (au.length === 0) return;
    const types = au.map((n) => n[0] & 0x1f);
    aus++;
    if (!report.keyframe && types.includes(5)) {
      const sps = au.find((n) => (n[0] & 0x1f) === 7);
      if (!sps || !types.includes(8)) {
        fail(`first IDR access unit lacks SPS/PPS (NAL types ${types})`);
      }
      const info = parseSps(sps!);
      log("keyframe access unit, NAL types", types, "SPS", info);
      if (info.width !== EXPECT_W || info.height !== EXPECT_H) {
        fail(`SPS says ${info.width}x${info.height}, expected ${EXPECT_W}x${EXPECT_H}`);
      }
      report.keyframe = { nalTypes: types, ...info };
      // Ask for a fresh keyframe the way a browser does after a loss: RTCP PLI.
      report.pliSent = Deno.webrtc.requestKeyFrame(e.receiver);
      log("requestKeyFrame (RTCP PLI) ->", report.pliSent);
    }
    // Forward from the first keyframe on, so the host-side decoder starts clean.
    if (report.keyframe && forwarded < FORWARD_AUS) {
      const annexb: number[] = [];
      for (const n of au) annexb.push(...START, ...n);
      out({ type: "au", data: b64(annexb) });
      forwarded++;
    }
    au = [];
    report.packets = packets;
    report.accessUnits = aus;
    maybeReady();
  };
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    const pkt = value as Uint8Array;
    packets++;
    // RTP header (RFC 3550): fixed 12 bytes + CSRCs + extension, then payload.
    if ((pkt[0] >> 6) !== 2) fail("not RTP version 2");
    const cc = pkt[0] & 0x0f, x = pkt[0] & 0x10, padding = pkt[0] & 0x20;
    const marker = pkt[1] & 0x80;
    const ts = new DataView(pkt.buffer, pkt.byteOffset).getUint32(4);
    let off = 12 + cc * 4;
    if (x) off += 4 + 4 * ((pkt[off + 2] << 8) | pkt[off + 3]);
    const end = padding ? pkt.length - pkt[pkt.length - 1] : pkt.length;
    if (auTs !== null && ts !== auTs) flush(); // a new timestamp: the last AU ended
    auTs = ts;
    for (const nal of depacketize(pkt.subarray(off, end), fu)) au.push(nal);
    if (marker) flush();
  }
};

// --- signaling from the host (stdin) ------------------------------------------

async function closeCleanly() {
  if (!dc) fail("close requested before the data channel opened");
  const closed = new Promise<void>((r) => dc!.addEventListener("close", () => r()));
  dc!.send(envelope(F.bye, fString(1, "deno-interop done")));
  dc!.close(); // must follow the Bye on the wire, not overtake it
  await closed;
  log("data channel closed; closing the connection");
  pc.close();
  network.close();
  out({ type: "closed", data: { dataChannel: dc!.readyState, connection: pc.connectionState } });
  Deno.exit(0);
}

let pending = "";
let remoteSet = false;
const early: string[] = [];
for await (const chunk of Deno.stdin.readable) {
  pending += dec.decode(chunk, { stream: true });
  let nl;
  while ((nl = pending.indexOf("\n")) >= 0) {
    const line = pending.slice(0, nl).trim();
    pending = pending.slice(nl + 1);
    if (!line) continue;
    const msg = JSON.parse(line);
    if (msg.type === "offer") {
      const desc = JSON.parse(msg.data);
      log("offer received");
      await pc.setRemoteDescription({ type: desc.type, sdp: desc.sdp });
      remoteSet = true;
      for (const c of early.splice(0)) await pc.addIceCandidate({ candidate: c, sdpMLineIndex: 0 });
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      out({
        type: "answer",
        data: JSON.stringify({ type: "answer", sdp: pc.localDescription!.sdp }),
      });
    } else if (msg.type === "candidate") {
      if (remoteSet) await pc.addIceCandidate({ candidate: msg.data, sdpMLineIndex: 0 });
      else early.push(msg.data);
    } else if (msg.type === "close") {
      await closeCleanly();
    }
  }
}
fail("stdin closed before a close was requested");
