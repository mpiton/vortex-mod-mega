//! WASM-boundary check: folder URLs are refused like file URLs until the
//! host can decrypt MEGA payloads (MAT-136 R-04). The synthetic folder
//! fixture that exercised in-wasm decryption lives in git history, ready to
//! restore when the download exports are rewired.
//!
//! Requires the WASM artifact at
//! `target/wasm32-wasip1/release/vortex_mod_mega.wasm`.

use std::path::PathBuf;

use extism::{Function, UserData, Val, PTR};

const WASM_REL_PATH: &str = "target/wasm32-wasip1/release/vortex_mod_mega.wasm";

fn wasm_path() -> PathBuf {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(WASM_REL_PATH);
    assert!(
        path.is_file(),
        "missing release WASM artifact at {}; run `cargo build --target wasm32-wasip1 --release` first",
        path.display()
    );
    path
}

fn stub_http_request() -> Function {
    Function::new(
        "http_request",
        [PTR],
        [PTR],
        UserData::<()>::default(),
        |plugin, _inputs, outputs, _user_data: UserData<()>| {
            let response = r#"{"status":200,"headers":{},"body":"[]"}"#;
            let handle = plugin.memory_new(response)?;
            outputs[0] = Val::I64(handle.offset() as i64);
            Ok(())
        },
    )
}

#[test]
fn wasm_extract_links_refuses_folder_url_until_decryption_ships() {
    let path = wasm_path();
    let manifest = extism::Manifest::new([extism::Wasm::file(&path)]);
    let mut plugin =
        extism::Plugin::new(&manifest, [stub_http_request()], true).expect("load wasm");

    let folder_url = "https://mega.nz/folder/Fld1d2EF#AAAAAAAAAAAAAAAAAAAAAA";
    let err = plugin
        .call::<&str, String>("extract_links", folder_url)
        .expect_err("extract_links must refuse folder URLs");
    assert!(
        err.to_string().contains("not supported yet"),
        "unexpected extract_links error: {err}"
    );
}
