//! MEGA folder listing parser.
//!
//! Given the JSON body returned by the `f` command and the folder master
//! key (decoded from the URL fragment), produce a flat list of child
//! file metadata: handle, filename, size, and the per-file
//! [`crate::key_parser::MegaFileKey`] needed to decrypt the eventual
//! ciphertext.
//!
//! Each node carries:
//! - `h`: 8-char base64url handle (file id)
//! - `p`: parent handle
//! - `t`: type discriminator (`0` = file, `1` = folder, `2` = root, …)
//! - `s`: size in bytes (file only)
//! - `k`: encrypted key blob, format `"<sharerHandle>:<base64url-encryptedKey>"`
//! - `a`: encrypted attribute blob (base64url, AES-128-CBC ciphertext, IV=0)
//!
//! The encrypted key blob is AES-128-ECB encrypted with the master key:
//! 32 bytes (2 blocks) for files, 16 bytes (1 block) for folders. After
//! ECB decryption, a file's 32-byte raw key XOR-folds into the same
//! `(aes_key, iv, meta_mac)` shape as a file URL key (see
//! [`crate::key_parser::parse_file_key`]). Attributes decrypt with the
//! recovered AES key and fixed IV `0₁₂₈`; the plaintext is `"MEGA"` +
//! JSON `{"n":"filename"}` + NUL padding.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;

use crate::crypto::{aes128_cbc_decrypt, aes128_ecb_decrypt};
use crate::error::PluginError;
use crate::key_parser::MegaFileKey;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MegaFolderChild {
    pub handle: String,
    pub filename: Option<String>,
    pub size: u64,
    pub key: MegaFileKey,
    /// Original 32-byte file key (post-ECB-decrypt, pre-XOR-fold). Kept so
    /// the host can rebuild a synthetic `mega.nz/file/<handle>#<base64url>`
    /// URL for each child and feed it back through `extract_links` /
    /// `resolve_stream_url` like a regular file URL.
    pub raw_key: [u8; 32],
}

#[derive(Debug, Deserialize)]
struct FolderResponse {
    f: Vec<RawNode>,
}

#[derive(Debug, Deserialize)]
struct RawNode {
    h: String,
    t: u8,
    #[serde(default)]
    s: Option<u64>,
    #[serde(default)]
    k: Option<String>,
    #[serde(default)]
    a: Option<String>,
}

/// Parse the body of an `f` command response. Returns one entry per file
/// child (`t == 0`) whose encrypted key + attributes were decryptable.
/// Folder children (`t == 1`) and the root marker (`t == 2`) are skipped.
pub fn parse_folder_listing(
    body: &str,
    master_key: &[u8; 16],
) -> Result<Vec<MegaFolderChild>, PluginError> {
    let parsed: FolderResponse = serde_json::from_str(body).map_err(|e| {
        PluginError::ParseApi(format!("malformed folder response (top-level shape): {e}"))
    })?;

    let mut children = Vec::with_capacity(parsed.f.len());
    for node in parsed.f {
        if node.t != 0 {
            continue;
        }
        let Some(child) = decrypt_file_node(&node, master_key)? else {
            continue;
        };
        children.push(child);
    }
    Ok(children)
}

fn decrypt_file_node(
    node: &RawNode,
    master_key: &[u8; 16],
) -> Result<Option<MegaFolderChild>, PluginError> {
    let Some(k_field) = node.k.as_deref() else {
        return Ok(None);
    };
    let Some(enc_key_b64) = split_key_blob(k_field) else {
        return Ok(None);
    };
    let mut enc_key = URL_SAFE_NO_PAD
        .decode(enc_key_b64)
        .map_err(|e| PluginError::InvalidKey(format!("node key base64: {e}")))?;
    if enc_key.len() != 32 {
        // File node keys must be 32 bytes (2 ECB blocks). Folder children
        // (16 bytes) are handled by the t == 1 branch which we skipped.
        return Ok(None);
    }
    aes128_ecb_decrypt(master_key, &mut enc_key)?;
    let raw_key: [u8; 32] = enc_key.as_slice().try_into().expect("len checked");
    let file_key = file_key_from_raw(&raw_key);

    let filename = node
        .a
        .as_deref()
        .and_then(|attr| decrypt_attribute(attr, &file_key.aes_key));

    Ok(Some(MegaFolderChild {
        handle: node.h.clone(),
        filename,
        size: node.s.unwrap_or(0),
        key: file_key,
        raw_key,
    }))
}

/// Split `"<sharer>:<encryptedKey>"`, returning only the second half.
/// Some shares omit the prefix and ship just the encrypted key — that
/// case falls through with the input returned as-is.
fn split_key_blob(blob: &str) -> Option<&str> {
    match blob.split_once(':') {
        Some((_, enc)) => (!enc.is_empty()).then_some(enc),
        None => (!blob.is_empty()).then_some(blob),
    }
}

/// XOR-fold a 32-byte raw file key the same way [`crate::key_parser::parse_file_key`]
/// does. Kept here so this module doesn't depend on the URL parsing path.
fn file_key_from_raw(raw: &[u8; 32]) -> MegaFileKey {
    let words = bytes_to_words_8(raw);
    let aes_words = [
        words[0] ^ words[4],
        words[1] ^ words[5],
        words[2] ^ words[6],
        words[3] ^ words[7],
    ];
    let mut aes_key = [0u8; 16];
    for (i, w) in aes_words.iter().enumerate() {
        aes_key[i * 4..(i + 1) * 4].copy_from_slice(&w.to_be_bytes());
    }
    let mut iv = [0u8; 8];
    iv[..4].copy_from_slice(&words[4].to_be_bytes());
    iv[4..].copy_from_slice(&words[5].to_be_bytes());
    let mut meta_mac = [0u8; 8];
    meta_mac[..4].copy_from_slice(&words[6].to_be_bytes());
    meta_mac[4..].copy_from_slice(&words[7].to_be_bytes());
    MegaFileKey {
        aes_key,
        iv,
        meta_mac,
    }
}

fn bytes_to_words_8(b: &[u8; 32]) -> [u32; 8] {
    let mut out = [0u32; 8];
    for (i, w) in out.iter_mut().enumerate() {
        let off = i * 4;
        *w = u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]);
    }
    out
}

/// Decrypt a base64url-encoded MEGA attribute blob with the node's AES key
/// and IV = 0₁₂₈. Returns the filename if the plaintext is well-formed
/// ("MEGA" magic + JSON `{"n":"..."}` + NUL pad). Any failure (bad b64,
/// bad magic, malformed JSON, missing `n`) returns `None` so the caller
/// can fall back to the handle as filename.
fn decrypt_attribute(b64: &str, aes_key: &[u8; 16]) -> Option<String> {
    let mut bytes = URL_SAFE_NO_PAD.decode(b64).ok()?;
    if bytes.is_empty() || !bytes.len().is_multiple_of(16) {
        return None;
    }
    aes128_cbc_decrypt(aes_key, &[0u8; 16], &mut bytes).ok()?;
    if !bytes.starts_with(b"MEGA") {
        return None;
    }
    let json_zone = &bytes[4..];
    let trimmed_end = json_zone
        .iter()
        .rposition(|&b| b != 0)
        .map(|i| i + 1)
        .unwrap_or(0);
    let json_str = core::str::from_utf8(&json_zone[..trimmed_end]).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(json_str).ok()?;
    parsed.get("n")?.as_str().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
    use aes::Aes128;

    /// Build a folder-listing fixture by encrypting a known per-node key
    /// + filename so the decryption path is exercised end-to-end.
    fn build_fixture() -> (String, [u8; 16], [u8; 32], String) {
        let master_key = [0x11u8; 16];
        // Construct a deterministic 32-byte raw file key.
        let raw_file_key: [u8; 32] = std::array::from_fn(|i| (i + 1) as u8);

        // Encrypt raw_file_key with master_key (AES-128-ECB).
        let mut enc_key = raw_file_key;
        let aes_master = Aes128::new(&master_key.into());
        for block in enc_key.chunks_exact_mut(16) {
            aes_master.encrypt_block(GenericArray::from_mut_slice(block));
        }
        let enc_key_b64 = URL_SAFE_NO_PAD.encode(enc_key);

        // Compute the node's AES key (XOR fold) so we can encrypt attrs with it.
        let file_key = file_key_from_raw(&raw_file_key);

        // Build attribute plaintext: "MEGA" + JSON + NUL pad to 32 bytes.
        let attr_json = "MEGA{\"n\":\"holiday.mp4\"}";
        let mut attr_plain = attr_json.as_bytes().to_vec();
        while !attr_plain.len().is_multiple_of(16) {
            attr_plain.push(0);
        }
        // CBC encrypt with IV=0.
        let aes_node = Aes128::new(&file_key.aes_key.into());
        let mut prev = [0u8; 16];
        for block in attr_plain.chunks_exact_mut(16) {
            for (b, p) in block.iter_mut().zip(prev.iter()) {
                *b ^= *p;
            }
            aes_node.encrypt_block(GenericArray::from_mut_slice(block));
            prev = block.try_into().unwrap();
        }
        let attr_b64 = URL_SAFE_NO_PAD.encode(&attr_plain);

        let json = serde_json::json!({
            "f": [
                { "h": "AbCdEfGh", "p": "RootRoot", "t": 2 },
                { "h": "ChildOne", "p": "AbCdEfGh", "t": 0,
                  "s": 12345, "k": format!("AbCdEfGh:{enc_key_b64}"),
                  "a": attr_b64 }
            ]
        });
        (
            json.to_string(),
            master_key,
            raw_file_key,
            "ChildOne".into(),
        )
    }

    #[test]
    fn parse_folder_listing_returns_decrypted_file_child() {
        let (body, master_key, raw_file_key, expected_handle) = build_fixture();
        let children = parse_folder_listing(&body, &master_key).unwrap();
        assert_eq!(children.len(), 1, "exactly one file child expected");
        let c = &children[0];
        assert_eq!(c.handle, expected_handle);
        assert_eq!(c.size, 12345);
        assert_eq!(c.filename.as_deref(), Some("holiday.mp4"));
        // Recovered file key matches XOR-folded raw key.
        let expected = file_key_from_raw(&raw_file_key);
        assert_eq!(c.key, expected);
    }

    #[test]
    fn parse_folder_listing_skips_non_file_nodes() {
        let body = r#"{"f":[
            {"h":"R","p":"R","t":2},
            {"h":"F1","p":"R","t":1,"k":"R:AAAAAAAAAAAAAAAAAAAAAA"}
        ]}"#;
        let master_key = [0u8; 16];
        let children = parse_folder_listing(body, &master_key).unwrap();
        assert!(children.is_empty(), "no t==0 nodes → empty list");
    }

    #[test]
    fn parse_folder_listing_ignores_file_with_short_key() {
        // 16-byte enc_key (1 block) is invalid for a file node and should
        // be silently skipped rather than aborting the whole listing.
        let one_block_enc = URL_SAFE_NO_PAD.encode([0u8; 16]);
        let body = format!(r#"{{"f":[{{"h":"X","p":"R","t":0,"s":1,"k":"R:{one_block_enc}"}}]}}"#);
        let children = parse_folder_listing(&body, &[0u8; 16]).unwrap();
        assert!(children.is_empty());
    }

    #[test]
    fn parse_folder_listing_falls_back_to_no_filename_on_corrupted_attrs() {
        // Build a fixture but corrupt the attribute base64 — the child
        // is still surfaced (with `filename = None`) so the host can show
        // the handle as a placeholder.
        let (mut body, master_key, _, _) = build_fixture();
        // Replace the value of `"a":"<...>"` with garbage.
        body = body.replace(r#""a":"#, r#""a":"!!!not%base64!!!","_a":"#);
        let children = parse_folder_listing(&body, &master_key).unwrap();
        assert_eq!(children.len(), 1);
        assert!(children[0].filename.is_none());
    }

    #[test]
    fn parse_folder_listing_garbage_body_returns_parse_api() {
        let err = parse_folder_listing("not json", &[0u8; 16]).unwrap_err();
        assert!(matches!(err, PluginError::ParseApi(_)));
    }

    #[test]
    fn split_key_blob_strips_sharer_prefix() {
        assert_eq!(split_key_blob("AAAA:BBBB"), Some("BBBB"));
        assert_eq!(split_key_blob("BBBB"), Some("BBBB"));
        assert_eq!(split_key_blob(""), None);
        assert_eq!(split_key_blob("AAAA:"), None);
    }
}
