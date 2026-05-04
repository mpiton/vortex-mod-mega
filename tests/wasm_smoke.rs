//! Smoke test: load the compiled `.wasm` via Extism and call the pure
//! `can_handle` / `supports_playlist` exports. `extract_links` and
//! `resolve_stream_url` need real `http_request` round-trips and are
//! exercised by the Vortex host's own integration tests.
//!
//! Skipped unless the WASM artifact is present at
//! `target/wasm32-wasip1/release/vortex_mod_mega.wasm`. To produce it:
//!
//! ```bash
//! cargo build --target wasm32-wasip1 --release
//! ```

use std::path::PathBuf;

use extism::{Function, UserData, Val, PTR};

const WASM_REL_PATH: &str = "target/wasm32-wasip1/release/vortex_mod_mega.wasm";

fn wasm_path() -> Option<PathBuf> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(WASM_REL_PATH);
    p.exists().then_some(p)
}

fn stub_http_request() -> Function {
    Function::new(
        "http_request",
        [PTR],
        [PTR],
        UserData::<()>::default(),
        |plugin, _inputs, outputs, _user_data: UserData<()>| {
            let body = r#"{"status":200,"headers":{},"body":""}"#;
            let handle = plugin.memory_new(body)?;
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
        match wasm_path() {
            Some(p) => p,
            None => {
                eprintln!(
                    "skipping: build with `cargo build --target wasm32-wasip1 --release` first"
                );
                return;
            }
        }
    };
}

#[test]
fn wasm_can_handle_recognises_mega_file_url() {
    let path = require_wasm!();
    let mut plugin = load_plugin(&path);
    let result: String = plugin
        .call(
            "can_handle",
            "https://mega.nz/file/AbCdEfGh#0123456789ABCDEFabcdef0123456789ABCDEFabcde",
        )
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
        .call(
            "supports_playlist",
            "https://mega.nz/file/AbCdEfGh#0123456789ABCDEFabcdef0123456789ABCDEFabcde",
        )
        .expect("supports_playlist call");
    assert_eq!(result.trim(), "false");
}
