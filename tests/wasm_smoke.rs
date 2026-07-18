//! Real ABI smoke tests for every runtime export of the release WASM artifact.
//! A MEGA `g` response fixture exercises extraction and resolution through the
//! same Extism `http_request` boundary as Vortex.
//!
//! Requires the WASM artifact at
//! `target/wasm32-wasip1/release/vortex_mod_mega.wasm`. To produce it:
//!
//! ```bash
//! cargo build --target wasm32-wasip1 --release
//! ```

use std::path::PathBuf;

use extism::{Function, UserData, Val, PTR};
use serde_json::json;

const WASM_REL_PATH: &str = "target/wasm32-wasip1/release/vortex_mod_mega.wasm";
const FILE_URL: &str = "https://mega.nz/file/AbCdEfGh#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const DIRECT_URL: &str = "https://gfs.example.test/download/archive.bin";

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
            let api_body = json!([{ "g": DIRECT_URL, "s": 4_194_304, "at": "AAAAAA" }]);
            let response =
                json!({ "status": 200, "headers": {}, "body": api_body.to_string() }).to_string();
            let handle = plugin.memory_new(&response)?;
            outputs[0] = Val::I64(handle.offset() as i64);
            Ok(())
        },
    )
}

fn load_plugin(path: &PathBuf) -> extism::Plugin {
    let manifest = extism::Manifest::new([extism::Wasm::file(path)]);
    extism::Plugin::new(&manifest, [stub_http_request()], true).expect("load wasm")
}

macro_rules! require_wasm {
    () => {
        wasm_path()
    };
}

#[test]
fn wasm_can_handle_recognises_mega_file_url() {
    let path = require_wasm!();
    let mut plugin = load_plugin(&path);
    let result: String = plugin
        .call("can_handle", FILE_URL)
        .expect("can_handle call");
    assert_eq!(result.trim(), "true");
}

#[test]
fn wasm_can_handle_rejects_unrelated_url() {
    let path = require_wasm!();
    let mut plugin = load_plugin(&path);
    let result: String = plugin
        .call("can_handle", "https://example.com/file/abc")
        .expect("can_handle call");
    assert_eq!(result.trim(), "false");
}

#[test]
fn wasm_supports_playlist_true_for_folder() {
    let path = require_wasm!();
    let mut plugin = load_plugin(&path);
    let result: String = plugin
        .call(
            "supports_playlist",
            "https://mega.nz/folder/aBcDeFg#0123456789ABCDEFabcdef",
        )
        .expect("supports_playlist call");
    assert_eq!(result.trim(), "true");
}

#[test]
fn wasm_supports_playlist_false_for_file() {
    let path = require_wasm!();
    let mut plugin = load_plugin(&path);
    let result: String = plugin
        .call("supports_playlist", FILE_URL)
        .expect("supports_playlist call");
    assert_eq!(result.trim(), "false");
}

#[test]
fn wasm_extraction_and_resolution_exports_refuse_until_decryption_ships() {
    let path = require_wasm!();
    let mut plugin = load_plugin(&path);

    // MAT-136 R-04: both download-facing exports must refuse for a valid MEGA
    // URL instead of handing the host an encrypted CDN URL.
    let err = plugin
        .call::<&str, String>("extract_links", FILE_URL)
        .expect_err("extract_links must refuse");
    assert!(
        err.to_string().contains("not supported yet"),
        "unexpected extract_links error: {err}"
    );

    let err = plugin
        .call::<String, String>("resolve_stream_url", json!({ "url": FILE_URL }).to_string())
        .expect_err("resolve_stream_url must refuse");
    assert!(
        err.to_string().contains("not supported yet"),
        "unexpected resolve_stream_url error: {err}"
    );
}
