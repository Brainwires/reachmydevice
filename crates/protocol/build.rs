use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // Recompile the schema whenever it changes.
    println!("cargo:rerun-if-changed=proto/rmd.proto");

    // Compile the schema with `protox` (pure Rust) into a FileDescriptorSet, then
    // hand that to prost-build for codegen. This avoids shelling out to the
    // `protoc` C++ binary, so a default build needs no external toolchain.
    let file_descriptors = protox::compile(["proto/rmd.proto"], ["proto/"])?;
    prost_build::Config::new().compile_fds(file_descriptors)?;
    Ok(())
}
