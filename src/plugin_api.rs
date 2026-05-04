//! WASM-only entry points: `#[plugin_fn]` exports + `#[host_fn]` imports.

use extism_pdk::*;

use crate::api_client::{
    build_folder_request, build_g_request, parse_g_response, parse_http_response, HttpResponse,
};
use crate::error::PluginError;
use crate::key_parser::{parse_file_key, parse_folder_key};
use crate::node_parser::parse_folder_listing;
use crate::url_matcher::UrlKind;
use crate::{
    build_file_extract_links, build_folder_extract_links, ensure_supported_url, handle_can_handle,
    handle_supports_playlist,
};

#[host_fn]
extern "ExtismHost" {
    fn http_request(req: String) -> String;
}

#[plugin_fn]
pub fn can_handle(url: String) -> FnResult<String> {
    Ok(handle_can_handle(&url))
}

#[plugin_fn]
pub fn supports_playlist(url: String) -> FnResult<String> {
    Ok(handle_supports_playlist(&url))
}

#[plugin_fn]
pub fn extract_links(url: String) -> FnResult<String> {
    let kind = ensure_supported_url(&url).map_err(error_to_fn_error)?;
    let response_json = match kind {
        UrlKind::File { id, key_b64 } => {
            let key = parse_file_key(&key_b64).map_err(error_to_fn_error)?;
            let resolution = call_g_command(&id)?;
            let response = build_file_extract_links(&url, &id, &key, resolution, None);
            serde_json::to_string(&response)
                .map_err(|e| error_to_fn_error(PluginError::SerdeJson(e)))?
        }
        UrlKind::Folder { id, key_b64 } => {
            let folder_key = parse_folder_key(&key_b64).map_err(error_to_fn_error)?;
            let body = call_f_command(&id)?;
            let children =
                parse_folder_listing(&body, &folder_key.aes_key).map_err(error_to_fn_error)?;
            let response = build_folder_extract_links(children);
            serde_json::to_string(&response)
                .map_err(|e| error_to_fn_error(PluginError::SerdeJson(e)))?
        }
        UrlKind::Unknown => unreachable!("ensure_supported_url filtered Unknown"),
    };
    Ok(response_json)
}

#[plugin_fn]
pub fn resolve_stream_url(input: String) -> FnResult<String> {
    #[derive(serde::Deserialize)]
    struct Input {
        url: String,
    }
    let params: Input =
        serde_json::from_str(&input).map_err(|e| error_to_fn_error(PluginError::SerdeJson(e)))?;
    let kind = ensure_supported_url(&params.url).map_err(error_to_fn_error)?;
    match kind {
        UrlKind::File { id, .. } => {
            let resolution = call_g_command(&id)?;
            Ok(resolution.direct_url)
        }
        _ => Err(error_to_fn_error(PluginError::UnsupportedUrl(params.url))),
    }
}

fn call_g_command(file_id: &str) -> FnResult<crate::api_client::MegaFileResolution> {
    let req = build_g_request(file_id).map_err(error_to_fn_error)?;
    // SAFETY: see invariants in vortex-mod-mediafire's plugin_api.rs.
    let raw = unsafe { http_request(req)? };
    let resp: HttpResponse = parse_http_response(&raw).map_err(error_to_fn_error)?;
    let body = resp.into_success_body().map_err(error_to_fn_error)?;
    parse_g_response(&body).map_err(error_to_fn_error)
}

fn call_f_command(folder_id: &str) -> FnResult<String> {
    let req = build_folder_request(folder_id).map_err(error_to_fn_error)?;
    // SAFETY: same invariants as `call_g_command` — host-resolved import,
    // String-marshalled JSON envelope, http capability checked at load.
    let raw = unsafe { http_request(req)? };
    let resp: HttpResponse = parse_http_response(&raw).map_err(error_to_fn_error)?;
    resp.into_success_body().map_err(error_to_fn_error)
}

fn error_to_fn_error(err: PluginError) -> WithReturnCode<extism_pdk::Error> {
    extism_pdk::Error::msg(err.to_string()).into()
}
