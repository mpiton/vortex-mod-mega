//! End-to-end folder enumeration test: load the WASM artefact via Extism,
//! stub `http_request` to return a synthetic `f` command response built
//! with real AES-128-ECB key wrapping + AES-128-CBC attribute encryption,
//! then assert `extract_links` decrypts it back into a single child file
//! with the expected handle, filename and size.
//!
//! Skipped unless the WASM artifact is present at
//! `target/wasm32-wasip1/release/vortex_mod_mega.wasm`.

use std::path::PathBuf;

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use extism::{Function, UserData, Val, PTR};

const WASM_REL_PATH: &str = "target/wasm32-wasip1/release/vortex_mod_mega.wasm";

fn wasm_path() -> Option<PathBuf> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(WASM_REL_PATH);
    p.exists().then_some(p)
}

fn xor_fold_aes_key(raw: &[u8; 32]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = raw[i] ^ raw[i + 16];
    }
    out
}

/// Build a fake `f` response that ships a single file child whose name is
/// "holiday.mp4", size 12345, encrypted under `master_key`.
fn build_folder_response_body(master_key: &[u8; 16], handle: &str) -> String {
    let raw_file_key: [u8; 32] = std::array::from_fn(|i| (i + 1) as u8);

    // ECB-encrypt raw key with master key.
    let mut enc_key = raw_file_key;
    let aes_master = Aes128::new(master_key.into());
    for block in enc_key.chunks_exact_mut(16) {
        aes_master.encrypt_block(GenericArray::from_mut_slice(block));
    }
    let enc_key_b64 = URL_SAFE_NO_PAD.encode(enc_key);

    // Recover node AES key (XOR fold of raw key) for attribute encryption.
    let node_aes_key = xor_fold_aes_key(&raw_file_key);
    let aes_node = Aes128::new(&node_aes_key.into());

    // Build "MEGA{...}" attribute plaintext, NUL-pad to 16-byte alignment, CBC encrypt with IV=0.
    let attr_json = "MEGA{\"n\":\"holiday.mp4\"}";
    let mut attr = attr_json.as_bytes().to_vec();
    while !attr.len().is_multiple_of(16) {
        attr.push(0);
    }
    let mut prev = [0u8; 16];
    for block in attr.chunks_exact_mut(16) {
        for (b, p) in block.iter_mut().zip(prev.iter()) {
            *b ^= *p;
        }
        aes_node.encrypt_block(GenericArray::from_mut_slice(block));
        prev = block.try_into().unwrap();
    }
    let attr_b64 = URL_SAFE_NO_PAD.encode(&attr);

    let folder_root = "RootRoot";
    let payload = serde_json::json!({
        "f": [
            { "h": folder_root, "p": folder_root, "t": 2 },
            {
                "h": handle, "p": folder_root, "t": 0,
                "s": 12345_u64,
                "k": format!("{folder_root}:{enc_key_b64}"),
                "a": attr_b64,
            }
        ]
    });
    payload.to_string()
}

fn http_envelope(body: &str) -> String {
    let body_json = serde_json::Value::String(body.to_string());
    format!(r#"{{"status":200,"headers":{{}},"body":{body_json}}}"#)
}

fn stub_http_returning(body_static: &'static str) -> Function {
    Function::new(
        "http_request",
        [PTR],
        [PTR],
        UserData::<()>::default(),
        move |plugin, _inputs, outputs, _user_data: UserData<()>| {
            let envelope = http_envelope(body_static);
            let handle = plugin.memory_new(&envelope)?;
            outputs[0] = Val::I64(handle.offset() as i64);
            Ok(())
        },
    )
}

fn load_plugin_with_stub(path: &PathBuf, stub: Function) -> extism::Plugin {
    let manifest = extism::Manifest::new([extism::Wasm::file(path)]);
    extism::Plugin::new(&manifest, [stub], true).expect("load wasm")
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
fn wasm_extract_links_decrypts_folder_listing_with_one_child() {
    let path = require_wasm!();
    let master_key: [u8; 16] = std::array::from_fn(|i| (i as u8).wrapping_mul(7));
    let folder_key_b64 = URL_SAFE_NO_PAD.encode(master_key);
    assert_eq!(
        folder_key_b64.len(),
        22,
        "16-byte folder key → 22 b64url chars"
    );
    let folder_id = "Fld1d2EF";
    let folder_url = format!("https://mega.nz/folder/{folder_id}#{folder_key_b64}");
    let child_handle = "ChildHnd";

    // Box::leak: test-only; the synthetic body must outlive the static
    // closure required by extism's Function::new.
    let body: &'static str =
        Box::leak(build_folder_response_body(&master_key, child_handle).into_boxed_str());
    let stub = stub_http_returning(body);
    let mut plugin = load_plugin_with_stub(&path, stub);

    let result: String = plugin
        .call("extract_links", folder_url.as_str())
        .expect("extract_links call");

    let v: serde_json::Value = serde_json::from_str(&result).expect("plugin returned JSON");
    assert_eq!(v["kind"], "folder");
    let files = v["files"].as_array().expect("files array");
    assert_eq!(files.len(), 1, "exactly one decrypted file child");
    let f = &files[0];
    assert_eq!(f["id"], child_handle);
    assert_eq!(f["filename"], "holiday.mp4");
    assert_eq!(f["size_bytes"].as_u64(), Some(12345));
    assert!(f["url"]
        .as_str()
        .unwrap()
        .starts_with("https://mega.nz/file/ChildHnd#"));
    assert!(
        f["direct_url"].is_null(),
        "folder children carry no resolved CDN URL"
    );
    assert_eq!(f["encryption"]["scheme"], "mega-aes128-ctr");
}
