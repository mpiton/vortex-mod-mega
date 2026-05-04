//! Plugin error type.

use thiserror::Error;

/// Errors raised by the MEGA plugin.
#[derive(Debug, Error)]
pub enum PluginError {
    #[error("URL is not a recognised MEGA resource: {0}")]
    UnsupportedUrl(String),

    #[error("MEGA file key is malformed: {0}")]
    InvalidKey(String),

    #[error("MEGA API returned status {status}: {message}")]
    HttpStatus { status: u16, message: String },

    #[error("MEGA file is offline or removed: {0}")]
    Offline(String),

    #[error("MEGA API rate-limited (EAGAIN); retry after backoff")]
    RateLimited,

    #[error("MEGA API JSON-RPC error code {0}")]
    ApiError(i32),

    #[error("MEGA API response invalid: {0}")]
    ParseApi(String),

    #[error("host function response invalid: {0}")]
    HostResponse(String),

    #[error("JSON error: {0}")]
    SerdeJson(#[from] serde_json::Error),

    #[error("MAC mismatch: file integrity check failed")]
    MacMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_url_renders_with_input() {
        let e = PluginError::UnsupportedUrl("https://example.com".into());
        assert!(e.to_string().contains("https://example.com"));
    }

    #[test]
    fn rate_limited_has_stable_message() {
        assert_eq!(
            PluginError::RateLimited.to_string(),
            "MEGA API rate-limited (EAGAIN); retry after backoff"
        );
    }

    #[test]
    fn api_error_includes_code() {
        assert!(PluginError::ApiError(-9).to_string().contains("-9"));
    }

    #[test]
    fn mac_mismatch_message_stable() {
        assert_eq!(
            PluginError::MacMismatch.to_string(),
            "MAC mismatch: file integrity check failed"
        );
    }

    #[test]
    fn serde_json_blanket_from() {
        let raw = "{not json";
        let err: PluginError = serde_json::from_str::<serde_json::Value>(raw)
            .unwrap_err()
            .into();
        assert!(matches!(err, PluginError::SerdeJson(_)));
    }
}
