// Fullscreen quad that samples one RGBA texture (the decoded remote frame).
//
// The quad is a letterbox: `u.scale` shrinks it along one axis so the streamed
// image keeps its aspect ratio inside the window. Whatever the quad does not
// cover is left as the render pass's black clear colour (the letterbox bars).

struct Uniforms {
    // Per-axis scale in NDC. One component is 1.0, the other <= 1.0.
    scale: vec2<f32>,
    _pad: vec2<f32>,
};

@group(0) @binding(0) var<uniform> u: Uniforms;
@group(0) @binding(1) var frame_tex: texture_2d<f32>;
@group(0) @binding(2) var frame_sampler: sampler;

struct VsOut {
    @builtin(position) clip_pos: vec4<f32>,
    @location(0) uv: vec2<f32>,
};

@vertex
fn vs_main(@builtin(vertex_index) vi: u32) -> VsOut {
    // Two triangles (6 vertices) forming a quad over NDC [-1, 1].
    var corners = array<vec2<f32>, 6>(
        vec2<f32>(-1.0, -1.0), vec2<f32>( 1.0, -1.0), vec2<f32>( 1.0,  1.0),
        vec2<f32>(-1.0, -1.0), vec2<f32>( 1.0,  1.0), vec2<f32>(-1.0,  1.0),
    );
    let c = corners[vi];

    var out: VsOut;
    // UV from the *unscaled* corner: image top (uv.y = 0) maps to NDC top (+1),
    // matching the top-to-bottom row order of the decoded RGBA buffer.
    out.uv = vec2<f32>((c.x + 1.0) * 0.5, (1.0 - c.y) * 0.5);
    out.clip_pos = vec4<f32>(c * u.scale, 0.0, 1.0);
    return out;
}

@fragment
fn fs_main(in: VsOut) -> @location(0) vec4<f32> {
    return textureSample(frame_tex, frame_sampler, in.uv);
}
