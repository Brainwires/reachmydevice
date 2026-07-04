//! OpenReach viewer app.
//!
//! A winit 0.30 + wgpu 30 window that renders decoded remote-desktop frames and
//! forwards local input back to the host. The heavy lifting (transport, decode,
//! signaling) lives behind [`openreach_session::ViewerSession`]; this binary is
//! the UI shell:
//!
//! - [`Gpu`] owns the wgpu surface/device/pipeline and blits the latest RGBA
//!   frame onto a fullscreen quad (aspect-preserving letterbox — see `shader.wgsl`).
//! - [`App`] implements winit's [`ApplicationHandler`]: it creates the window on
//!   `resumed`, drains [`ViewerSession::poll_update`] in `about_to_wait`, and
//!   translates winit `WindowEvent`s into protocol input events.
//!
//! Config comes from the environment: `OPENREACH_SIGNAL_ADDR` (default
//! `127.0.0.1:9000`) and `OPENREACH_NAME` (default from [`ViewerConfig`]).

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use openreach_protocol as proto;
use openreach_protocol::input_event::Event as InputEvent;
use openreach_protocol::{KeyEvent, MouseButton, MouseMove, MouseScroll};
use openreach_session::rendezvous::RendezvousClient;
use openreach_session::{SignalClient, Signaling, ViewerConfig, ViewerSession, ViewerUpdate};

/// Build the signaling backend: rendezvous WebSocket if configured, else LAN relay.
fn build_signaling() -> anyhow::Result<Box<dyn Signaling>> {
    if let Ok(url) = std::env::var("OPENREACH_RENDEZVOUS_URL") {
        let token = std::env::var("OPENREACH_TOKEN")
            .context("OPENREACH_TOKEN is required in rendezvous mode")?;
        let peer = std::env::var("OPENREACH_PEER_DEVICE_ID")
            .context("OPENREACH_PEER_DEVICE_ID (the host's id) is required in rendezvous mode")?;
        tracing::info!(%url, %peer, "signaling via rendezvous");
        Ok(Box::new(RendezvousClient::connect(
            &url,
            &token,
            Some(peer),
        )?))
    } else {
        let addr =
            std::env::var("OPENREACH_SIGNAL_ADDR").unwrap_or_else(|_| "127.0.0.1:9000".to_string());
        tracing::info!(%addr, "signaling via LAN relay");
        Ok(Box::new(SignalClient::connect(&addr)?))
    }
}

use winit::application::ApplicationHandler;
use winit::dpi::PhysicalPosition;
use winit::event::{ElementState, MouseButton as WinitMouseButton, MouseScrollDelta, WindowEvent};
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop};
use winit::keyboard::{KeyCode, PhysicalKey};
use winit::window::{Window, WindowId};

/// How often, when idle, we wake to poll the session for new frames. Small
/// enough to keep latency low, large enough to not spin the CPU.
const POLL_INTERVAL: Duration = Duration::from_millis(4);

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    // Build the viewer config from the environment.
    let mut cfg = ViewerConfig::default();
    if let Ok(name) = std::env::var("OPENREACH_NAME") {
        cfg.device_name = name;
    }
    cfg.ice_servers = std::env::var("OPENREACH_ICE")
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default();
    if let Ok(bind) = std::env::var("OPENREACH_BIND") {
        cfg.bind_addr = bind;
    }
    tracing::info!(name = %cfg.device_name, "starting openreach-viewer");

    // Build the signaling backend (rendezvous if configured, else LAN relay).
    let signaling = match build_signaling() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "signaling setup failed; exiting");
            std::process::exit(1);
        }
    };

    // Start the session up front. If signaling can't be reached we log and exit
    // cleanly rather than opening a dead window.
    let session = match ViewerSession::start(cfg, signaling) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "failed to start viewer session; exiting");
            std::process::exit(1);
        }
    };

    let event_loop = match EventLoop::new() {
        Ok(el) => el,
        Err(e) => {
            tracing::error!(error = %e, "failed to create event loop; exiting");
            std::process::exit(1);
        }
    };
    event_loop.set_control_flow(ControlFlow::Wait);

    let mut app = App::new(session);
    if let Err(e) = event_loop.run_app(&mut app) {
        tracing::error!(error = %e, "event loop terminated with error");
        std::process::exit(1);
    }
}

// --- Application -----------------------------------------------------------

/// The winit application state. Holds the (frozen-API) session for the whole
/// process lifetime, the window/GPU (created lazily on `resumed`), and the input
/// bookkeeping needed to build protocol events.
struct App {
    session: ViewerSession,
    window: Option<Arc<Window>>,
    gpu: Option<Gpu>,
    /// Current keyboard modifier bitmask (`openreach_protocol::modifiers`).
    modifiers: u32,
    /// Last cursor position, normalized to [0, 1] over the window — carried into
    /// button events so click position stays consistent with the last move.
    last_cursor: (f64, f64),
}

impl App {
    fn new(session: ViewerSession) -> Self {
        Self {
            session,
            window: None,
            gpu: None,
            modifiers: 0,
            last_cursor: (0.0, 0.0),
        }
    }
}

impl ApplicationHandler for App {
    /// Create the window and GPU state once the platform is ready. `resumed` can
    /// fire more than once on some platforms, so we guard against re-init.
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.window.is_some() {
            return;
        }

        let attrs = Window::default_attributes().with_title("OpenReach Viewer");
        let window = match event_loop.create_window(attrs) {
            Ok(w) => Arc::new(w),
            Err(e) => {
                tracing::error!(error = %e, "failed to create window; exiting");
                event_loop.exit();
                return;
            }
        };

        // wgpu setup is async (adapter/device requests are futures); block on it.
        match pollster::block_on(Gpu::new(window.clone())) {
            Ok(gpu) => {
                self.gpu = Some(gpu);
                self.window = Some(window);
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to initialize wgpu; exiting");
                event_loop.exit();
            }
        }
    }

    fn window_event(
        &mut self,
        event_loop: &ActiveEventLoop,
        _window_id: WindowId,
        event: WindowEvent,
    ) {
        match event {
            WindowEvent::CloseRequested => {
                tracing::info!("close requested; exiting");
                event_loop.exit();
            }

            WindowEvent::Resized(size) => {
                if let Some(gpu) = self.gpu.as_mut() {
                    gpu.resize(size.width, size.height);
                }
                if let Some(win) = self.window.as_ref() {
                    win.request_redraw();
                }
            }

            WindowEvent::RedrawRequested => {
                if let Some(gpu) = self.gpu.as_mut() {
                    gpu.render();
                }
            }

            // --- Input translation (viewer -> host) ------------------------
            WindowEvent::CursorMoved { position, .. } => {
                let (x, y) = self.normalize_cursor(position);
                self.last_cursor = (x, y);
                self.session
                    .send_input(InputEvent::MouseMove(MouseMove { x, y }));
            }

            WindowEvent::MouseInput { state, button, .. } => {
                if let Some(btn) = map_mouse_button(button) {
                    let (x, y) = self.last_cursor;
                    self.session
                        .send_input(InputEvent::MouseButton(MouseButton {
                            button: btn,
                            pressed: state == ElementState::Pressed,
                            x,
                            y,
                        }));
                }
            }

            WindowEvent::MouseWheel { delta, .. } => {
                let (dx, dy) = match delta {
                    // Line deltas are unit-less "clicks"; scale to something the
                    // host can treat like pixels.
                    MouseScrollDelta::LineDelta(x, y) => (f64::from(x) * 10.0, f64::from(y) * 10.0),
                    MouseScrollDelta::PixelDelta(p) => (p.x, p.y),
                };
                self.session
                    .send_input(InputEvent::MouseScroll(MouseScroll { dx, dy }));
            }

            WindowEvent::ModifiersChanged(mods) => {
                self.modifiers = map_modifiers(mods.state());
            }

            WindowEvent::KeyboardInput { event, .. } => {
                if let PhysicalKey::Code(code) = event.physical_key {
                    if let Some(hid_usage) = winit_keycode_to_hid(code) {
                        self.session.send_input(InputEvent::Key(KeyEvent {
                            hid_usage,
                            pressed: event.state == ElementState::Pressed,
                            modifiers: self.modifiers,
                        }));
                    }
                }
            }

            _ => {}
        }
    }

    /// Drain decoded frames / connection updates and keep the poll loop alive.
    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        while let Some(update) = self.session.poll_update() {
            match update {
                ViewerUpdate::Frame(frame) => {
                    if let Some(gpu) = self.gpu.as_mut() {
                        gpu.upload_frame(&frame);
                    }
                    if let Some(win) = self.window.as_ref() {
                        win.request_redraw();
                    }
                }
                ViewerUpdate::Connected => tracing::info!("connected to host"),
                ViewerUpdate::Paired(true) => tracing::info!("paired: host accepted this viewer"),
                ViewerUpdate::Paired(false) => {
                    tracing::warn!("pairing rejected by host (version mismatch)");
                }
                ViewerUpdate::Disconnected => tracing::warn!("disconnected from host"),
            }
        }

        // Wake again shortly to poll for the next frame without busy-spinning.
        event_loop.set_control_flow(ControlFlow::WaitUntil(Instant::now() + POLL_INTERVAL));
    }
}

impl App {
    /// Normalize a cursor position to [0, 1] over the current window inner size.
    fn normalize_cursor(&self, position: PhysicalPosition<f64>) -> (f64, f64) {
        let (w, h) = self.window.as_ref().map_or((1.0, 1.0), |win| {
            let s = win.inner_size();
            (f64::from(s.width.max(1)), f64::from(s.height.max(1)))
        });
        let x = (position.x / w).clamp(0.0, 1.0);
        let y = (position.y / h).clamp(0.0, 1.0);
        (x, y)
    }
}

// --- GPU / renderer --------------------------------------------------------

/// A single uploaded frame texture plus its bind group and dimensions.
struct FrameTexture {
    width: u32,
    height: u32,
    texture: wgpu::Texture,
    bind_group: wgpu::BindGroup,
}

/// The wgpu renderer: surface, device/queue, the blit pipeline, and (once a
/// frame arrives) the frame texture. Until the first frame the window simply
/// clears to black.
struct Gpu {
    surface: wgpu::Surface<'static>,
    device: wgpu::Device,
    queue: wgpu::Queue,
    config: wgpu::SurfaceConfiguration,
    pipeline: wgpu::RenderPipeline,
    bind_group_layout: wgpu::BindGroupLayout,
    sampler: wgpu::Sampler,
    uniform_buf: wgpu::Buffer,
    frame: Option<FrameTexture>,
}

/// Scale uniform consumed by the vertex shader for aspect-preserving letterbox.
#[repr(C)]
#[derive(Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
struct Uniforms {
    scale: [f32; 2],
    _pad: [f32; 2],
}

impl Gpu {
    /// Build the instance -> surface -> adapter -> device/queue chain and the
    /// blit pipeline. wgpu 30 shape: `Instance::new(&desc)`, `create_surface`
    /// returns a `Result`, and both `request_adapter` and `request_device`
    /// resolve to `Result` futures (adapter is no longer an `Option`).
    async fn new(window: Arc<Window>) -> anyhow::Result<Self> {
        let size = window.inner_size();
        let (width, height) = (size.width.max(1), size.height.max(1));

        let instance = wgpu::Instance::default();
        let surface = instance.create_surface(window)?;

        let adapter = instance
            .request_adapter(&wgpu::RequestAdapterOptions {
                compatible_surface: Some(&surface),
                ..Default::default()
            })
            .await?;

        let (device, queue) = adapter
            .request_device(&wgpu::DeviceDescriptor {
                label: Some("openreach-viewer device"),
                required_features: wgpu::Features::empty(),
                required_limits: wgpu::Limits::default(),
                experimental_features: wgpu::ExperimentalFeatures::disabled(),
                memory_hints: wgpu::MemoryHints::default(),
                trace: wgpu::Trace::Off,
            })
            .await?;

        // Prefer an sRGB surface format: paired with an `Rgba8UnormSrgb` frame
        // texture the sample (sRGB->linear) and present (linear->sRGB) cancel, so
        // colours round-trip correctly.
        let caps = surface.get_capabilities(&adapter);
        let format = caps
            .formats
            .iter()
            .copied()
            .find(wgpu::TextureFormat::is_srgb)
            .unwrap_or(caps.formats[0]);

        let config = wgpu::SurfaceConfiguration {
            usage: wgpu::TextureUsages::RENDER_ATTACHMENT,
            format,
            color_space: wgpu::SurfaceColorSpace::Auto,
            width,
            height,
            present_mode: caps.present_modes[0],
            alpha_mode: caps.alpha_modes[0],
            view_formats: vec![],
            desired_maximum_frame_latency: 2,
        };
        surface.configure(&device, &config);

        // Bind group layout: scale uniform (vertex) + texture & sampler (fragment).
        let bind_group_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("openreach-viewer bind group layout"),
            entries: &[
                wgpu::BindGroupLayoutEntry {
                    binding: 0,
                    visibility: wgpu::ShaderStages::VERTEX,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Uniform,
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 1,
                    visibility: wgpu::ShaderStages::FRAGMENT,
                    ty: wgpu::BindingType::Texture {
                        sample_type: wgpu::TextureSampleType::Float { filterable: true },
                        view_dimension: wgpu::TextureViewDimension::D2,
                        multisampled: false,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 2,
                    visibility: wgpu::ShaderStages::FRAGMENT,
                    ty: wgpu::BindingType::Sampler(wgpu::SamplerBindingType::Filtering),
                    count: None,
                },
            ],
        });

        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("openreach-viewer blit shader"),
            source: wgpu::ShaderSource::Wgsl(include_str!("shader.wgsl").into()),
        });

        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("openreach-viewer pipeline layout"),
            bind_group_layouts: &[Some(&bind_group_layout)],
            immediate_size: 0,
        });

        let pipeline = device.create_render_pipeline(&wgpu::RenderPipelineDescriptor {
            label: Some("openreach-viewer blit pipeline"),
            layout: Some(&pipeline_layout),
            vertex: wgpu::VertexState {
                module: &shader,
                entry_point: Some("vs_main"),
                buffers: &[],
                compilation_options: wgpu::PipelineCompilationOptions::default(),
            },
            fragment: Some(wgpu::FragmentState {
                module: &shader,
                entry_point: Some("fs_main"),
                targets: &[Some(wgpu::ColorTargetState {
                    format,
                    blend: Some(wgpu::BlendState::REPLACE),
                    write_mask: wgpu::ColorWrites::ALL,
                })],
                compilation_options: wgpu::PipelineCompilationOptions::default(),
            }),
            primitive: wgpu::PrimitiveState::default(),
            depth_stencil: None,
            multisample: wgpu::MultisampleState::default(),
            multiview_mask: None,
            cache: None,
        });

        let sampler = device.create_sampler(&wgpu::SamplerDescriptor {
            label: Some("openreach-viewer sampler"),
            mag_filter: wgpu::FilterMode::Linear,
            min_filter: wgpu::FilterMode::Linear,
            ..Default::default()
        });

        let uniform_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("openreach-viewer uniforms"),
            size: std::mem::size_of::<Uniforms>() as u64,
            usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        Ok(Self {
            surface,
            device,
            queue,
            config,
            pipeline,
            bind_group_layout,
            sampler,
            uniform_buf,
            frame: None,
        })
    }

    /// Reconfigure the surface at the current config size (after Lost/Outdated).
    fn reconfigure(&mut self) {
        self.surface.configure(&self.device, &self.config);
    }

    /// Handle a window resize: update the config and reconfigure the surface.
    fn resize(&mut self, width: u32, height: u32) {
        self.config.width = width.max(1);
        self.config.height = height.max(1);
        self.surface.configure(&self.device, &self.config);
    }

    /// Upload a decoded RGBA frame, (re)creating the texture and bind group when
    /// the incoming dimensions change.
    fn upload_frame(&mut self, frame: &openreach_codec::DecodedFrame) {
        let (w, h) = (frame.width.max(1), frame.height.max(1));

        // (Re)create the texture + bind group only on a dimension change;
        // otherwise reuse the existing texture and just overwrite its contents.
        let needs_new = self
            .frame
            .as_ref()
            .is_none_or(|f| f.width != w || f.height != h);

        if needs_new {
            let texture = self.device.create_texture(&wgpu::TextureDescriptor {
                label: Some("openreach-viewer frame texture"),
                size: wgpu::Extent3d {
                    width: w,
                    height: h,
                    depth_or_array_layers: 1,
                },
                mip_level_count: 1,
                sample_count: 1,
                dimension: wgpu::TextureDimension::D2,
                format: wgpu::TextureFormat::Rgba8UnormSrgb,
                usage: wgpu::TextureUsages::TEXTURE_BINDING | wgpu::TextureUsages::COPY_DST,
                view_formats: &[],
            });
            let view = texture.create_view(&wgpu::TextureViewDescriptor::default());
            let bind_group = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
                label: Some("openreach-viewer bind group"),
                layout: &self.bind_group_layout,
                entries: &[
                    wgpu::BindGroupEntry {
                        binding: 0,
                        resource: self.uniform_buf.as_entire_binding(),
                    },
                    wgpu::BindGroupEntry {
                        binding: 1,
                        resource: wgpu::BindingResource::TextureView(&view),
                    },
                    wgpu::BindGroupEntry {
                        binding: 2,
                        resource: wgpu::BindingResource::Sampler(&self.sampler),
                    },
                ],
            });
            self.frame = Some(FrameTexture {
                width: w,
                height: h,
                texture,
                bind_group,
            });
        }

        // Upload the tightly-packed RGBA bytes (stride == width * 4).
        let Some(frame_tex) = self.frame.as_ref() else {
            return;
        };
        self.queue.write_texture(
            wgpu::TexelCopyTextureInfo {
                texture: &frame_tex.texture,
                mip_level: 0,
                origin: wgpu::Origin3d::ZERO,
                aspect: wgpu::TextureAspect::All,
            },
            &frame.data,
            wgpu::TexelCopyBufferLayout {
                offset: 0,
                bytes_per_row: Some(w * 4),
                rows_per_image: Some(h),
            },
            wgpu::Extent3d {
                width: w,
                height: h,
                depth_or_array_layers: 1,
            },
        );
    }

    /// Draw the current frame (or clear to black if none yet).
    ///
    /// wgpu 30's `get_current_texture` returns a [`wgpu::CurrentSurfaceTexture`]
    /// enum (not a `Result`); we reconfigure on Outdated/Lost and skip on
    /// transient Timeout/Occluded.
    fn render(&mut self) {
        let surface_tex = match self.surface.get_current_texture() {
            wgpu::CurrentSurfaceTexture::Success(t) => t,
            // Usable this frame; reconfigure so the next one is optimal.
            wgpu::CurrentSurfaceTexture::Suboptimal(t) => {
                self.reconfigure();
                t
            }
            wgpu::CurrentSurfaceTexture::Outdated | wgpu::CurrentSurfaceTexture::Lost => {
                self.reconfigure();
                return;
            }
            wgpu::CurrentSurfaceTexture::Timeout | wgpu::CurrentSurfaceTexture::Occluded => return,
            wgpu::CurrentSurfaceTexture::Validation => {
                tracing::warn!("surface texture acquisition failed validation");
                return;
            }
        };
        let view = surface_tex
            .texture
            .create_view(&wgpu::TextureViewDescriptor::default());

        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("openreach-viewer encoder"),
            });

        {
            let mut pass = encoder.begin_render_pass(&wgpu::RenderPassDescriptor {
                label: Some("openreach-viewer blit pass"),
                color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                    view: &view,
                    resolve_target: None,
                    depth_slice: None,
                    ops: wgpu::Operations {
                        load: wgpu::LoadOp::Clear(wgpu::Color::BLACK),
                        store: wgpu::StoreOp::Store,
                    },
                })],
                depth_stencil_attachment: None,
                timestamp_writes: None,
                occlusion_query_set: None,
                multiview_mask: None,
            });

            if let Some(frame) = self.frame.as_ref() {
                // Update the letterbox scale for the current window/frame aspect.
                let uniforms = Uniforms {
                    scale: letterbox_scale(
                        self.config.width,
                        self.config.height,
                        frame.width,
                        frame.height,
                    ),
                    _pad: [0.0, 0.0],
                };
                self.queue
                    .write_buffer(&self.uniform_buf, 0, bytemuck::bytes_of(&uniforms));

                pass.set_pipeline(&self.pipeline);
                pass.set_bind_group(0, &frame.bind_group, &[]);
                pass.draw(0..6, 0..1);
            }
        }

        self.queue.submit(std::iter::once(encoder.finish()));
        // wgpu 30 presents via the queue, consuming the surface texture.
        self.queue.present(surface_tex);
    }
}

/// Per-axis NDC scale that fits `img` inside `win` while preserving aspect ratio.
fn letterbox_scale(win_w: u32, win_h: u32, img_w: u32, img_h: u32) -> [f32; 2] {
    let win_aspect = win_w as f32 / win_h.max(1) as f32;
    let img_aspect = img_w as f32 / img_h.max(1) as f32;
    if win_aspect > img_aspect {
        // Window wider than image: bars on the left/right.
        [img_aspect / win_aspect, 1.0]
    } else {
        // Window taller than image: bars on the top/bottom.
        [1.0, win_aspect / img_aspect]
    }
}

// --- Input mapping helpers -------------------------------------------------

/// winit mouse button -> protocol button code (1=Left, 2=Right, 3=Middle).
fn map_mouse_button(button: WinitMouseButton) -> Option<i32> {
    match button {
        WinitMouseButton::Left => Some(1),
        WinitMouseButton::Right => Some(2),
        WinitMouseButton::Middle => Some(3),
        _ => None,
    }
}

/// winit modifier state -> protocol modifier bitmask.
fn map_modifiers(state: winit::keyboard::ModifiersState) -> u32 {
    use proto::modifiers as m;
    let mut bits = 0;
    if state.shift_key() {
        bits |= m::SHIFT;
    }
    if state.control_key() {
        bits |= m::CONTROL;
    }
    if state.alt_key() {
        bits |= m::ALT;
    }
    if state.super_key() {
        bits |= m::META;
    }
    bits
}

/// Map a winit physical [`KeyCode`] to a USB HID usage code (Keyboard page 0x07).
///
/// Covers the common set the host supports: letters, digits, whitespace/edit
/// keys, punctuation, CapsLock, F1-F12, arrows, navigation, and the left/right
/// modifier keys. Unmapped keys return `None` (dropped rather than mis-sent).
fn winit_keycode_to_hid(code: KeyCode) -> Option<u32> {
    use KeyCode as K;
    let hid = match code {
        // Letters a-z -> 0x04..=0x1D
        K::KeyA => 0x04,
        K::KeyB => 0x05,
        K::KeyC => 0x06,
        K::KeyD => 0x07,
        K::KeyE => 0x08,
        K::KeyF => 0x09,
        K::KeyG => 0x0A,
        K::KeyH => 0x0B,
        K::KeyI => 0x0C,
        K::KeyJ => 0x0D,
        K::KeyK => 0x0E,
        K::KeyL => 0x0F,
        K::KeyM => 0x10,
        K::KeyN => 0x11,
        K::KeyO => 0x12,
        K::KeyP => 0x13,
        K::KeyQ => 0x14,
        K::KeyR => 0x15,
        K::KeyS => 0x16,
        K::KeyT => 0x17,
        K::KeyU => 0x18,
        K::KeyV => 0x19,
        K::KeyW => 0x1A,
        K::KeyX => 0x1B,
        K::KeyY => 0x1C,
        K::KeyZ => 0x1D,
        // Digits: 1-9 -> 0x1E..=0x26, 0 -> 0x27
        K::Digit1 => 0x1E,
        K::Digit2 => 0x1F,
        K::Digit3 => 0x20,
        K::Digit4 => 0x21,
        K::Digit5 => 0x22,
        K::Digit6 => 0x23,
        K::Digit7 => 0x24,
        K::Digit8 => 0x25,
        K::Digit9 => 0x26,
        K::Digit0 => 0x27,
        // Whitespace / editing
        K::Enter => 0x28,
        K::Escape => 0x29,
        K::Backspace => 0x2A,
        K::Tab => 0x2B,
        K::Space => 0x2C,
        // Punctuation
        K::Minus => 0x2D,
        K::Equal => 0x2E,
        K::BracketLeft => 0x2F,
        K::BracketRight => 0x30,
        K::Backslash => 0x31,
        K::Semicolon => 0x33,
        K::Quote => 0x34,
        K::Backquote => 0x35,
        K::Comma => 0x36,
        K::Period => 0x37,
        K::Slash => 0x38,
        K::CapsLock => 0x39,
        // Function keys F1-F12 -> 0x3A..=0x45
        K::F1 => 0x3A,
        K::F2 => 0x3B,
        K::F3 => 0x3C,
        K::F4 => 0x3D,
        K::F5 => 0x3E,
        K::F6 => 0x3F,
        K::F7 => 0x40,
        K::F8 => 0x41,
        K::F9 => 0x42,
        K::F10 => 0x43,
        K::F11 => 0x44,
        K::F12 => 0x45,
        // Navigation
        K::Home => 0x4A,
        K::PageUp => 0x4B,
        K::Delete => 0x4C,
        K::End => 0x4D,
        K::PageDown => 0x4E,
        K::ArrowRight => 0x4F,
        K::ArrowLeft => 0x50,
        K::ArrowDown => 0x51,
        K::ArrowUp => 0x52,
        // Modifiers (left/right)
        K::ControlLeft => 0xE0,
        K::ShiftLeft => 0xE1,
        K::AltLeft => 0xE2,
        K::SuperLeft => 0xE3,
        K::ControlRight => 0xE4,
        K::ShiftRight => 0xE5,
        K::AltRight => 0xE6,
        K::SuperRight => 0xE7,
        _ => return None,
    };
    Some(hid)
}
