//! MEGA JSON-RPC client.
//!
//! Two endpoints matter for public file resolution:
//! - `g` command: `POST /cs?id=<seq>` body `[{"a":"g","g":1,"p":"<fileId>"}]` →
//!   `[{"g":"<cdnUrl>","s":<size>,"at":"<encryptedAttrs>","msd":1}]` or `[<errCode>]`.
//! - `f` command (folder root): `POST /cs?id=<seq>&n=<folderId>` body
//!   `[{"a":"f","c":1,"r":1}]` → `{"f":[<node>...], ...}`.
//!
//! HTTP I/O is delegated to the host via `http_request`. Pure parsing
//! lives here so it can be exercised natively without WASM.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};

use serde::{Deserialize, Serialize};

use crate::error::PluginError;

const USER_AGENT: &str = "Mozilla/5.0 (Vortex/1.0; +https://vortex-app.com) MegaPlugin/1.0";
const API_BASE: &str = "https://g.api.mega.co.nz/cs";

#[derive(Debug, Serialize)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct HttpResponse {
    pub status: u16,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body: String,
}

/// Reject responses larger than this so the host can't be coerced into
/// returning a multi-megabyte JSON body. Real `g` payloads are < 1 KB,
/// folder listings rarely exceed a few hundred KB; 1 MB is a generous
/// ceiling without leaving the door open to memory abuse.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

impl HttpResponse {
    pub fn into_success_body(self) -> Result<String, PluginError> {
        if (200..300).contains(&self.status) {
            if self.body.len() > MAX_BODY_BYTES {
                return Err(PluginError::HttpStatus {
                    status: self.status,
                    message: format!("body exceeds {MAX_BODY_BYTES} bytes"),
                });
            }
            Ok(self.body)
        } else if self.status == 404 || self.status == 410 {
            Err(PluginError::Offline(format!("HTTP {}", self.status)))
        } else if self.status == 429 || self.status == 509 {
            Err(PluginError::RateLimited)
        } else {
            Err(PluginError::HttpStatus {
                status: self.status,
                message: truncate(&self.body, 256),
            })
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let mut cut = max;
        while !s.is_char_boundary(cut) && cut > 0 {
            cut -= 1;
        }
        format!("{}…", &s[..cut])
    }
}

pub fn parse_http_response(raw: &str) -> Result<HttpResponse, PluginError> {
    serde_json::from_str(raw).map_err(|e| PluginError::HostResponse(e.to_string()))
}

// ── Request builders ─────────────────────────────────────────────────────────

static SEQ: AtomicU32 = AtomicU32::new(1);

pub fn next_seq() -> u32 {
    SEQ.fetch_add(1, Ordering::Relaxed)
}

pub fn build_g_request(file_id: &str) -> Result<String, PluginError> {
    let url = format!("{API_BASE}?id={}", next_seq());
    let body = serde_json::to_string(&serde_json::json!([{
        "a": "g",
        "g": 1,
        "p": file_id,
    }]))?;
    let mut headers = HashMap::new();
    headers.insert("User-Agent".to_string(), USER_AGENT.to_string());
    headers.insert("Content-Type".to_string(), "application/json".to_string());
    let req = HttpRequest {
        method: "POST".into(),
        url,
        headers,
        body: Some(body),
    };
    serde_json::to_string(&req).map_err(PluginError::SerdeJson)
}

pub fn build_folder_request(folder_id: &str) -> Result<String, PluginError> {
    let url = format!("{API_BASE}?id={}&n={}", next_seq(), folder_id);
    let body = serde_json::to_string(&serde_json::json!([{
        "a": "f",
        "c": 1,
        "r": 1,
    }]))?;
    let mut headers = HashMap::new();
    headers.insert("User-Agent".to_string(), USER_AGENT.to_string());
    headers.insert("Content-Type".to_string(), "application/json".to_string());
    let req = HttpRequest {
        method: "POST".into(),
        url,
        headers,
        body: Some(body),
    };
    serde_json::to_string(&req).map_err(PluginError::SerdeJson)
}

// ── Response parsing ─────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub struct MegaFileResolution {
    pub direct_url: String,
    pub size_bytes: u64,
    pub encrypted_attrs: String,
}

pub fn parse_g_response(body: &str) -> Result<MegaFileResolution, PluginError> {
    let v: serde_json::Value = serde_json::from_str(body).map_err(PluginError::SerdeJson)?;
    if let Some(arr) = v.as_array() {
        if arr.len() == 1 {
            if let Some(code) = arr[0].as_i64() {
                return Err(map_api_error(code as i32));
            }
            if let Some(obj) = arr[0].as_object() {
                let direct_url = obj
                    .get("g")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        PluginError::ParseApi("missing 'g' (CDN URL) in response".into())
                    })?
                    .to_string();
                let size_bytes = obj.get("s").and_then(|v| v.as_u64()).ok_or_else(|| {
                    PluginError::ParseApi("missing 's' (size) in response".into())
                })?;
                let encrypted_attrs = obj
                    .get("at")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                return Ok(MegaFileResolution {
                    direct_url,
                    size_bytes,
                    encrypted_attrs,
                });
            }
        }
    } else if let Some(code) = v.as_i64() {
        // MEGA sometimes returns a bare integer at top-level for errors.
        return Err(map_api_error(code as i32));
    }
    Err(PluginError::ParseApi(format!(
        "unexpected response shape (len={})",
        body.len()
    )))
}

fn map_api_error(code: i32) -> PluginError {
    match code {
        -9 => PluginError::Offline(format!("MEGA ENOENT (code {code})")),
        -3 | -6 => PluginError::RateLimited,
        c => PluginError::ApiError(c),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_g_request_emits_post_with_body() {
        let json = build_g_request("AbCdEfGh").unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["method"], "POST");
        assert!(v["url"].as_str().unwrap().starts_with(API_BASE));
        let body = v["body"].as_str().unwrap();
        assert!(body.contains("\"a\":\"g\""));
        assert!(body.contains("\"AbCdEfGh\""));
    }

    #[test]
    fn build_folder_request_includes_node_id() {
        let json = build_folder_request("FolderId").unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v["url"].as_str().unwrap().contains("&n=FolderId"));
        assert!(v["body"].as_str().unwrap().contains("\"a\":\"f\""));
    }

    #[test]
    fn parse_g_response_extracts_url_and_size() {
        let body = include_str!("../tests/fixtures/api_g_response.json");
        let r = parse_g_response(body).unwrap();
        assert!(r.direct_url.starts_with("https://"));
        assert_eq!(r.size_bytes, 4_194_304);
        assert_eq!(r.encrypted_attrs, "AAAAAA");
    }

    #[test]
    fn parse_g_response_maps_offline_code() {
        let err = parse_g_response("[-9]").unwrap_err();
        assert!(matches!(err, PluginError::Offline(_)));
    }

    #[test]
    fn parse_g_response_maps_rate_limit() {
        assert!(matches!(
            parse_g_response("[-3]").unwrap_err(),
            PluginError::RateLimited
        ));
        assert!(matches!(
            parse_g_response("[-6]").unwrap_err(),
            PluginError::RateLimited
        ));
    }

    #[test]
    fn parse_g_response_unknown_negative_is_api_error() {
        let err = parse_g_response("[-99]").unwrap_err();
        assert!(matches!(err, PluginError::ApiError(-99)));
    }

    #[test]
    fn parse_g_response_garbage_is_parse_api() {
        let err = parse_g_response("\"nope\"").unwrap_err();
        assert!(matches!(err, PluginError::ParseApi(_)));
    }

    #[test]
    fn into_success_body_maps_429_to_rate_limited() {
        let resp = HttpResponse {
            status: 429,
            headers: HashMap::new(),
            body: "".into(),
        };
        assert!(matches!(
            resp.into_success_body().unwrap_err(),
            PluginError::RateLimited
        ));
    }

    #[test]
    fn into_success_body_maps_404_to_offline() {
        let resp = HttpResponse {
            status: 404,
            headers: HashMap::new(),
            body: "".into(),
        };
        assert!(matches!(
            resp.into_success_body().unwrap_err(),
            PluginError::Offline(_)
        ));
    }

    #[test]
    fn into_success_body_rejects_oversized_payload() {
        let resp = HttpResponse {
            status: 200,
            headers: HashMap::new(),
            body: "x".repeat(MAX_BODY_BYTES + 1),
        };
        assert!(matches!(
            resp.into_success_body().unwrap_err(),
            PluginError::HttpStatus { .. }
        ));
    }

    #[test]
    fn parse_http_response_round_trips_success() {
        let raw = r#"{"status":200,"headers":{},"body":"ok"}"#;
        let resp = parse_http_response(raw).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, "ok");
    }

    #[test]
    fn next_seq_is_strictly_increasing() {
        let a = next_seq();
        let b = next_seq();
        assert!(b > a);
    }
}
