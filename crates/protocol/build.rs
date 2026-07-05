use std::io::Result;

fn main() -> Result<()> {
    // Recompile the schema whenever it changes.
    println!("cargo:rerun-if-changed=proto/rmd.proto");
    prost_build::compile_protos(&["proto/rmd.proto"], &["proto/"])?;
    Ok(())
}
