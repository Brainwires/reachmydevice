# `unsafe` audit — ReachMyDevice

All `unsafe` in the workspace is confined to **one file**:
`crates/capture/src/mac.rs` (macOS ScreenCaptureKit capture). Every other crate —
`transport`, `input`, `codec`, `session`, and all apps — contains **zero** `unsafe`
(verified by a full-tree grep; input uses safe `core-graphics`/`x11rb` wrappers,
codec's C interop lives inside `openh264`/`audiopus`, audio playback uses `cpal`).

This is the reviewed inventory for `mac.rs`.

## 1. objc2 class plumbing (majority of the lines)
`define_class!` for `StreamOutput` (video) and `AudioStreamOutput` (audio):
`unsafe impl NSObjectProtocol/SCStreamOutput/SCStreamDelegate`, the
`#[unsafe(method(...))]` selectors, and `msg_send![super(this), init]`. These are
ABI-correctness declarations, not memory operations. Low risk; correctness rests on
matching the ScreenCaptureKit protocol signatures, which the `objc2-screen-capture-kit`
bindings type-check.

## 2. `unsafe impl Send for SendContent` (~L233)
Transfers a `Retained<SCShareableContent>` from the completion-handler thread to the
caller over a channel. **Sound because** `SCShareableContent` is an immutable snapshot
that ScreenCaptureKit permits reading (`displays`/`windows`) from any thread; the value
is only read after transfer. Documented at the definition.

## 3. Raw-pointer buffer extraction — the highest-value spots (hardened)
Two `slice::from_raw_parts` over OS-owned memory. Both now **guard the length derived
from OS-supplied values** before constructing the slice, and copy out immediately so
the slice never outlives the lock/retain:

- **Video** (`handle_sample_buffer`): after `CVPixelBufferLockBaseAddress`, the length
  is `bytes_per_row.checked_mul(height)` and the frame is dropped unless the base is
  non-null, dimensions are non-zero, and `len ∈ (0, MAX_FRAME_BYTES]` (512 MiB). The
  matching `CVPixelBufferUnlockBaseAddress` runs on every path (the copy is done before
  unlock; `None` paths skip the copy entirely).
- **Audio** (`handle_audio`): `CMSampleBufferGetAudioBufferListWithRetainedBlockBuffer`
  hands back a +1-retained `CMBlockBuffer`, taken with `Retained::from_raw` so it's
  released on drop. `mData` is read as `byte_size / 4` `f32`s only after checking the
  pointer is non-null and `byte_size ∈ (0, MAX_AUDIO_BYTES]` (8 MiB); the samples are
  copied into an owned `Vec` while `_block` is alive.

## 4. Other FFI (`SCShareableContent`/`SCStream` setup, `Retained::retain`,
`startCaptureWithCompletionHandler`, `error.as_ref()`)
Standard ScreenCaptureKit lifecycle calls with null-checks where the API may return
null. No raw slice/pointer arithmetic.

## Fuzzing
The untrusted-input parsers are fuzzed (libFuzzer targets under `fuzz/`:
`protocol_decode`, `filexfer_handle`, `relay_frame`) and guarded by stable
`fuzz_smoke` / `*_fuzz_smoke` tests that run in normal CI. See `.github/workflows/ci.yml`.

## Residual
The `mac.rs` FFI is the primary target for the external audit (Workstream G). No
`unsafe` exists in the network-facing transport or the parsers themselves.
