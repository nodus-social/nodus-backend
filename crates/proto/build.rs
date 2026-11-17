fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The build machines have no protoc, and asking every contributor to install one is a
    // worse trade than vendoring it.
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc);
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(
            &["proto/telemetry.proto", "proto/control.proto"],
            &["proto"],
        )?;
    println!("cargo:rerun-if-changed=proto/telemetry.proto");
    println!("cargo:rerun-if-changed=proto/control.proto");
    Ok(())
}
