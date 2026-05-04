//! MEGA URL classification + id/key extraction.
//!
//! Modern format:
//! - `https://mega.nz/file/<fileId>#<fileKey>` — fileId 8 chars base64url, fileKey 43 chars (32 bytes).
//! - `https://mega.nz/folder/<folderId>#<folderKey>` — folderKey 22 chars (16 bytes).
//!
//! Legacy format (still served by mega.co.nz redirects):
//! - `https://mega.co.nz/#!<fileId>!<fileKey>`
//! - `https://mega.co.nz/#F!<folderId>!<folderKey>`

use std::sync::OnceLock;

use regex::Regex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlKind {
    File { id: String, key_b64: String },
    Folder { id: String, key_b64: String },
    Unknown,
}

pub fn classify_url(url: &str) -> UrlKind {
    if let Some(c) = file_modern_regex().captures(url) {
        return UrlKind::File {
            id: c[1].to_string(),
            key_b64: c[2].to_string(),
        };
    }
    if let Some(c) = file_legacy_regex().captures(url) {
        return UrlKind::File {
            id: c[1].to_string(),
            key_b64: c[2].to_string(),
        };
    }
    if let Some(c) = folder_modern_regex().captures(url) {
        return UrlKind::Folder {
            id: c[1].to_string(),
            key_b64: c[2].to_string(),
        };
    }
    if let Some(c) = folder_legacy_regex().captures(url) {
        return UrlKind::Folder {
            id: c[1].to_string(),
            key_b64: c[2].to_string(),
        };
    }
    UrlKind::Unknown
}

fn file_modern_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"^https?://mega\.(?:nz|co\.nz)/file/([A-Za-z0-9_-]{6,12})#([A-Za-z0-9_-]{43})$")
            .expect("file_modern_regex must compile")
    })
}

fn file_legacy_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"^https?://mega\.(?:nz|co\.nz)/#!([A-Za-z0-9_-]{6,12})!([A-Za-z0-9_-]{43})$")
            .expect("file_legacy_regex must compile")
    })
}

fn folder_modern_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"^https?://mega\.(?:nz|co\.nz)/folder/([A-Za-z0-9_-]{6,12})#([A-Za-z0-9_-]{22})$",
        )
        .expect("folder_modern_regex must compile")
    })
}

fn folder_legacy_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"^https?://mega\.(?:nz|co\.nz)/#F!([A-Za-z0-9_-]{6,12})!([A-Za-z0-9_-]{22})$")
            .expect("folder_legacy_regex must compile")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_modern_file_url() {
        let url = "https://mega.nz/file/AbCdEfGh#0123456789ABCDEFabcdef0123456789ABCDEFabcde";
        assert_eq!(
            classify_url(url),
            UrlKind::File {
                id: "AbCdEfGh".into(),
                key_b64: "0123456789ABCDEFabcdef0123456789ABCDEFabcde".into(),
            }
        );
    }

    #[test]
    fn classify_legacy_file_url() {
        let url = "https://mega.co.nz/#!AbCdEfGh!0123456789ABCDEFabcdef0123456789ABCDEFabcde";
        assert!(matches!(classify_url(url), UrlKind::File { .. }));
    }

    #[test]
    fn classify_modern_folder_url() {
        let url = "https://mega.nz/folder/aBcDeFg#0123456789ABCDEFabcdef";
        assert_eq!(
            classify_url(url),
            UrlKind::Folder {
                id: "aBcDeFg".into(),
                key_b64: "0123456789ABCDEFabcdef".into(),
            }
        );
    }

    #[test]
    fn classify_legacy_folder_url() {
        let url = "https://mega.nz/#F!aBcDeFg!0123456789ABCDEFabcdef";
        assert!(matches!(classify_url(url), UrlKind::Folder { .. }));
    }

    #[test]
    fn classify_rejects_non_mega() {
        assert_eq!(
            classify_url("https://example.com/file/abc"),
            UrlKind::Unknown
        );
    }

    #[test]
    fn classify_rejects_short_key() {
        assert_eq!(
            classify_url("https://mega.nz/file/AbCdEfGh#tooShort"),
            UrlKind::Unknown
        );
    }

    #[test]
    fn classify_rejects_missing_fragment() {
        assert_eq!(
            classify_url("https://mega.nz/file/AbCdEfGh"),
            UrlKind::Unknown
        );
    }

    #[test]
    fn classify_rejects_oversized_id() {
        let oversized = "AbCdEfGhIjKlMnOp";
        let url =
            format!("https://mega.nz/file/{oversized}#0123456789ABCDEFabcdef0123456789ABCDEFabcde");
        assert_eq!(classify_url(&url), UrlKind::Unknown);
    }
}
