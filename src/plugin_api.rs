//! WASM-only entry points: `#[plugin_fn]` exports.

use extism_pdk::*;

use crate::error::PluginError;
use crate::{ensure_supported_url, handle_can_handle, handle_supports_playlist};

#[plugin_fn]
pub fn can_handle(url: String) -> FnResult<String> {
    Ok(handle_can_handle(&url))
}

#[plugin_fn]
pub fn supports_playlist(url: String) -> FnResult<String> {
    Ok(handle_supports_playlist(&url))
}

// MAT-136 R-04: MEGA CDN bytes are AES-128-CTR ciphertext and the Vortex host
// has no decryption pipeline yet, so a "successful" download would write
// unreadable bytes to disk. Both download-facing exports refuse with an
// explicit error until host-side decryption ships; the resolution and crypto
// code stays in the library (api_client, crypto, key_parser, node_parser)
// ready to rewire — see git history for the previous wiring.

#[plugin_fn]
pub fn extract_links(url: String) -> FnResult<String> {
    ensure_supported_url(&url).map_err(error_to_fn_error)?;
    Err(error_to_fn_error(PluginError::DecryptionNotSupported))
}

#[plugin_fn]
pub fn resolve_stream_url(input: String) -> FnResult<String> {
    #[derive(serde::Deserialize)]
    struct Input {
        url: String,
    }
    let params: Input =
        serde_json::from_str(&input).map_err(|e| error_to_fn_error(PluginError::SerdeJson(e)))?;
    ensure_supported_url(&params.url).map_err(error_to_fn_error)?;
    Err(error_to_fn_error(PluginError::DecryptionNotSupported))
}

fn error_to_fn_error(err: PluginError) -> WithReturnCode<extism_pdk::Error> {
    extism_pdk::Error::msg(err.to_string()).into()
}
