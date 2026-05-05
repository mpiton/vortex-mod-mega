# Contributing to vortex-mod-mega

First off, thanks for considering contributing! Every contribution matters, whether it's a bug report, a feature request, or a pull request.

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/mpiton/vortex-mod-mega/issues)
2. If not, create a new issue using the **Bug Report** template
3. Include steps to reproduce, expected behavior, and actual behavior

### Suggesting Features

1. Check existing [Feature Requests](https://github.com/mpiton/vortex-mod-mega/issues?q=label%3Aenhancement)
2. Open a new issue using the **Feature Request** template
3. Describe the problem and your proposed solution

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/your-feature`)
3. Make your changes following the project's coding standards
4. Write or update tests as needed
5. Commit using [Conventional Commits](https://www.conventionalcommits.org/) format
6. Push to your fork and open a Pull Request

### Commit Message Format

```
<type>(<scope>): <description>

[optional body]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`, `ci`

### Development Setup

```bash
# Clone the repo
git clone https://github.com/mpiton/vortex-mod-mega.git
cd vortex-mod-mega

# Install the WASM toolchain (one-time)
rustup target add wasm32-wasip1

# Build native lib (fast, runs unit tests)
cargo build
cargo test --lib

# Build the WASM artefact (release, used by the host plugin loader)
cargo build --target wasm32-wasip1 --release

# Run all tests including the WASM smoke + folder e2e suites
cargo test

# Lint + format
cargo fmt
cargo clippy --all-targets -- -D warnings
```

### Project Layout

- `src/error.rs` — `PluginError` enum (thiserror)
- `src/url_matcher.rs` — recognise `mega.nz/file/...` and `mega.nz/folder/...` URLs (modern + legacy formats)
- `src/key_parser.rs` — base64url decode + XOR fold to `MegaFileKey` (AES-128 + IV + metaMac)
- `src/crypto.rs` — `MegaDecryptor` (AES-128-CTR streaming + chunk-MAC fold), `aes128_ecb_decrypt`, `aes128_cbc_decrypt`
- `src/api_client.rs` — JSON-RPC client for `g` and `f` commands, error code mapping
- `src/node_parser.rs` — folder listing parser: ECB unwrap of node keys + CBC attribute decryption
- `src/lib.rs` — IPC DTOs (`ExtractLinksResponse`, `FileLink`, `EncryptionInfo`) + response builders
- `src/plugin_api.rs` — WASM-only `#[plugin_fn]` exports + `#[host_fn]` import (`http_request`)
- `tests/wasm_smoke.rs` — load the compiled `.wasm` via Extism and exercise pure exports
- `tests/folder_e2e.rs` — end-to-end folder decryption via WASM with synthetic AES fixtures

### Hard Rules

- No `.unwrap()` outside tests — use `?` + `thiserror`
- No `unsafe` outside the `http_request` host-fn boundary, which carries a SAFETY block documenting the host-side invariants
- No `#[allow(dead_code)]` or other suppression attributes — fix the root cause
- Domain logic stays in pure modules (`crypto`, `key_parser`, `node_parser`, `url_matcher`, `api_client`, `lib`) so it can be exercised natively without a WASM toolchain

## Code of Conduct

This project follows a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold it.

## Questions?

Open a [Discussion](https://github.com/mpiton/vortex-mod-mega/discussions) or file an issue using the **Question** template.
