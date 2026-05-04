//! Vortex MEGA WASM plugin.
//!
//! Implements the plugin contract used by the Vortex plugin host:
//! - `can_handle(url)` → `"true"` / `"false"`
//! - `supports_playlist(url)` → `"true"` for folder URLs, `"false"` otherwise
//! - `extract_links(url)` → JSON metadata for a single MEGA file
//! - `resolve_stream_url(input)` → encrypted CDN URL (host fetches + decrypts)
//!
//! Network access is delegated to the host via `http_request`. All parsing
//! and crypto is pure (`url_matcher.rs`, `key_parser.rs`, `crypto.rs`,
//! `api_client.rs`) so it can be exercised natively without WASM.

pub mod api_client;
pub mod crypto;
pub mod error;
pub mod key_parser;
pub mod url_matcher;

#[cfg(target_family = "wasm")]
mod plugin_api;

use serde::Serialize;

use crate::api_client::MegaFileResolution;
use crate::error::PluginError;
use crate::key_parser::MegaFileKey;
use crate::url_matcher::UrlKind;

// ── IPC DTOs ─────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ExtractLinksResponse {
    pub kind: &'static str,
    pub files: Vec<FileLink>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct FileLink {
    pub id: String,
    pub url: String,
    pub filename: Option<String>,
    pub size_bytes: Option<u64>,
    pub direct_url: String,
    pub resumable: bool,
    pub encryption: EncryptionInfo,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct EncryptionInfo {
    /// Always `"mega-aes128-ctr"` for MEGA. Hosts unaware of this scheme
    /// must refuse the download — the bytes from `direct_url` are ciphertext.
    pub scheme: &'static str,
    /// Hex-encoded 16-byte AES key.
    pub aes_key_hex: String,
    /// Hex-encoded 8-byte CTR IV / MAC seed.
    pub iv_hex: String,
    /// Hex-encoded 8-byte expected file MAC.
    pub meta_mac_hex: String,
}

// ── Routing helpers ──────────────────────────────────────────────────────────

pub fn handle_can_handle(url: &str) -> String {
    bool_to_string(matches!(
        url_matcher::classify_url(url),
        UrlKind::File { .. } | UrlKind::Folder { .. }
    ))
}

pub fn handle_supports_playlist(url: &str) -> String {
    bool_to_string(matches!(
        url_matcher::classify_url(url),
        UrlKind::Folder { .. }
    ))
}

fn bool_to_string(b: bool) -> String {
    if b {
        "true".into()
    } else {
        "false".into()
    }
}

pub fn ensure_supported_url(url: &str) -> Result<UrlKind, PluginError> {
    match url_matcher::classify_url(url) {
        UrlKind::Unknown => Err(PluginError::UnsupportedUrl(url.to_string())),
        kind => Ok(kind),
    }
}

// ── Response builders ────────────────────────────────────────────────────────

pub fn build_file_extract_links(
    source_url: &str,
    file_id: &str,
    key: &MegaFileKey,
    resolution: MegaFileResolution,
    filename: Option<String>,
) -> ExtractLinksResponse {
    let link = FileLink {
        id: file_id.to_string(),
        url: source_url.to_string(),
        filename,
        size_bytes: Some(resolution.size_bytes),
        direct_url: resolution.direct_url,
        resumable: true,
        encryption: EncryptionInfo {
            scheme: "mega-aes128-ctr",
            aes_key_hex: hex_lower(&key.aes_key),
            iv_hex: hex_lower(&key.iv),
            meta_mac_hex: hex_lower(&key.meta_mac),
        },
    };
    ExtractLinksResponse {
        kind: "file",
        files: vec![link],
    }
}

fn hex_lower(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push(nibble(byte >> 4));
        s.push(nibble(byte & 0x0f));
    }
    s
}

fn nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + n - 10) as char,
        _ => unreachable!("nibble out of range"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_client::MegaFileResolution;

    fn sample_key() -> MegaFileKey {
        MegaFileKey {
            aes_key: [0xAA; 16],
            iv: [0xBB; 8],
            meta_mac: [0xCC; 8],
        }
    }

    fn sample_resolution() -> MegaFileResolution {
        MegaFileResolution {
            direct_url: "https://gfs.example/dl/abc".into(),
            size_bytes: 1_048_576,
            encrypted_attrs: "AAAAAA".into(),
        }
    }

    #[test]
    fn can_handle_recognises_file_url() {
        assert_eq!(
            handle_can_handle(
                "https://mega.nz/file/AbCdEfGh#0123456789ABCDEFabcdef0123456789ABCDEFabcde"
            ),
            "true"
        );
    }

    #[test]
    fn can_handle_recognises_folder_url() {
        assert_eq!(
            handle_can_handle("https://mega.nz/folder/aBcDeFg#0123456789ABCDEFabcdef"),
            "true"
        );
    }

    #[test]
    fn can_handle_rejects_other() {
        assert_eq!(handle_can_handle("https://example.com/file/abc"), "false");
    }

    #[test]
    fn supports_playlist_true_for_folder() {
        assert_eq!(
            handle_supports_playlist("https://mega.nz/folder/aBcDeFg#0123456789ABCDEFabcdef"),
            "true"
        );
    }

    #[test]
    fn supports_playlist_false_for_file() {
        assert_eq!(
            handle_supports_playlist(
                "https://mega.nz/file/AbCdEfGh#0123456789ABCDEFabcdef0123456789ABCDEFabcde"
            ),
            "false"
        );
    }

    #[test]
    fn ensure_supported_url_returns_kind() {
        let kind = ensure_supported_url(
            "https://mega.nz/file/AbCdEfGh#0123456789ABCDEFabcdef0123456789ABCDEFabcde",
        )
        .unwrap();
        assert!(matches!(kind, UrlKind::File { .. }));
    }

    #[test]
    fn ensure_supported_url_rejects_unknown() {
        let err = ensure_supported_url("https://example.com/foo").unwrap_err();
        assert!(matches!(err, PluginError::UnsupportedUrl(_)));
    }

    #[test]
    fn build_file_extract_links_carries_encryption() {
        let r = build_file_extract_links(
            "https://mega.nz/file/AbCdEfGh#abc",
            "AbCdEfGh",
            &sample_key(),
            sample_resolution(),
            Some("video.mp4".into()),
        );
        assert_eq!(r.kind, "file");
        assert_eq!(r.files.len(), 1);
        let f = &r.files[0];
        assert_eq!(f.id, "AbCdEfGh");
        assert_eq!(f.size_bytes, Some(1_048_576));
        assert_eq!(f.direct_url, "https://gfs.example/dl/abc");
        assert_eq!(f.encryption.scheme, "mega-aes128-ctr");
        assert_eq!(f.encryption.aes_key_hex.len(), 32);
        assert_eq!(f.encryption.iv_hex.len(), 16);
        assert_eq!(f.encryption.meta_mac_hex.len(), 16);
        assert!(f
            .encryption
            .aes_key_hex
            .chars()
            .all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn extract_links_response_serialises_with_encryption() {
        let r = build_file_extract_links(
            "https://mega.nz/file/AbCdEfGh#abc",
            "AbCdEfGh",
            &sample_key(),
            sample_resolution(),
            None,
        );
        let json = serde_json::to_string(&r).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["kind"], "file");
        assert_eq!(
            parsed["files"][0]["encryption"]["scheme"],
            "mega-aes128-ctr"
        );
        assert!(parsed["files"][0]["resumable"].as_bool().unwrap());
    }

    #[test]
    fn hex_lower_known_vector() {
        assert_eq!(hex_lower(&[0xab, 0xcd, 0x01, 0xff]), "abcd01ff");
    }
}
