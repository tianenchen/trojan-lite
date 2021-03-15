fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir_path = "proto/output";
    if !std::path::Path::new(dir_path).exists() {
        std::fs::create_dir(dir_path).unwrap();
    }
    tonic_build::configure()
        .build_server(true)
        .build_client(false)
        .out_dir(dir_path)
        .compile(&["proto/api/api.proto"], &["proto"])?;
    Ok(())
}