# vortex-mod-mega

MEGA WASM plugin for [Vortex](https://github.com/vortex-app/vortex) — recognises `mega.nz` file and folder URLs. Downloads are refused until the Vortex host can decrypt MEGA payloads: MEGA CDN bytes are AES-128-CTR ciphertext, and without a host-side decryption pipeline a "successful" download would write unreadable bytes to disk (MAT-136 R-04).

## Status

- URL recognition (`can_handle` / `supports_playlist`) — active
- Downloads (`extract_links` / `resolve_stream_url`) — refused with `DecryptionNotSupported` until host-side decryption ships
- Library machinery, tested and ready to rewire (see git history for the previous export wiring):
  - File URL resolution (`https://mega.nz/file/<id>#<key>`)
  - AES-128-CTR streaming decryption (memory-bounded, native-tested)
  - Per-chunk CBC-MAC accumulator + final file-MAC fold, MAC mismatch detection (`PluginError::MacMismatch`)
  - Folder URL enumeration, AES-128-ECB unwrap of per-node keys + AES-128-CBC decrypt of attribute blobs

## Plugin contract

| Plugin function       | Behaviour                                                              |
|----------------------|-----------------------------------------------------------------------|
| `can_handle`         | `"true"` for any `mega.nz/file/...` or `mega.nz/folder/...` URL.       |
| `supports_playlist`  | `"true"` for folder URLs, `"false"` otherwise.                         |
| `extract_links`      | Validates the URL, then refuses with an explicit "MEGA downloads are not supported yet" error. |
| `resolve_stream_url` | Same refusal after URL validation.                                     |

The `MegaDecryptor` (AES-128-CTR + chunk-MAC) stays in the library for the release that wires host-side decryption; no export hands out an encrypted CDN URL in the meantime.

## Build

```bash
rustup target add wasm32-wasip1
cargo build --target wasm32-wasip1 --release
sha256sum target/wasm32-wasip1/release/vortex_mod_mega.wasm
sha256sum plugin.toml
```

## Test

```bash
cargo test                   # native unit + mandatory WASM smoke
cargo test --lib crypto      # crypto round-trip + memory-bounded streaming
```

## License

GPL-3.0
