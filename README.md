# vortex-mod-mega

MEGA WASM plugin for [Vortex](https://github.com/vortex-app/vortex) — resolves `mega.nz` public file URLs and exposes the AES-128-CTR + chunk-MAC machinery the Vortex core engine needs to decrypt downloaded bytes and verify integrity.

## Status

- File URL resolution (`https://mega.nz/file/<id>#<key>`) — done
- AES-128-CTR streaming decryption (memory-bounded, native-tested) — done
- Per-chunk CBC-MAC accumulator + final file-MAC fold — done
- MAC mismatch detection (`PluginError::MacMismatch`) — done
- Folder URL enumeration (`https://mega.nz/folder/<id>#<key>`) — done
- AES-128-ECB unwrap of per-node keys + AES-128-CBC decrypt of attribute blobs — done

## Plugin contract

| Plugin function       | Behaviour                                                              |
|----------------------|-----------------------------------------------------------------------|
| `can_handle`         | `"true"` for any `mega.nz/file/...` or `mega.nz/folder/...` URL.       |
| `supports_playlist`  | `"true"` for folder URLs, `"false"` otherwise.                         |
| `extract_links`      | File URL → JSON `{ kind: "file", files: [FileLink] }` with `EncryptionInfo`. Folder URL → `{ kind: "folder", files: [FileLink, ...] }` where each child carries a synthetic `https://mega.nz/file/<h>#<k>` URL and `direct_url = null` (host calls `resolve_stream_url` per child). |
| `resolve_stream_url` | File URL → encrypted CDN URL (host fetches + decrypts in-stream).      |

`FileLink.encryption.scheme = "mega-aes128-ctr"` carries the per-file AES key, IV and `metaMac` (all hex-encoded). Hosts must run the bytes from `direct_url` through `MegaDecryptor::process` and verify with `MegaDecryptor::verify_against(meta_mac)`.

## Build

```bash
rustup target add wasm32-wasip1
cargo build --target wasm32-wasip1 --release
sha256sum target/wasm32-wasip1/release/vortex_mod_mega.wasm
sha256sum plugin.toml
```

## Test

```bash
cargo test                   # native unit + WASM smoke (smoke skipped if .wasm absent)
cargo test --lib crypto      # crypto round-trip + memory-bounded streaming
```

## License

GPL-3.0
