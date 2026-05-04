//! Parse MEGA base64url-encoded file/folder keys.
//!
//! File key (32 bytes / 8 × u32 big-endian) folds via XOR into a 128-bit
//! AES key + 64-bit IV + 64-bit metaMac. Folder key (16 bytes / 4 × u32)
//! is the AES-128 key directly with no IV/MAC.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::error::PluginError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MegaFileKey {
    /// AES-128 key (16 bytes) used for both CTR and CBC-MAC.
    pub aes_key: [u8; 16],
    /// CTR initial nonce (top 8 bytes of 16-byte counter; bottom 8 = 0).
    pub iv: [u8; 8],
    /// Expected file-MAC (compared after streaming all chunk MACs).
    pub meta_mac: [u8; 8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MegaFolderKey {
    /// AES-128 key (16 bytes) decrypts child node attributes/keys.
    pub aes_key: [u8; 16],
}

pub fn parse_file_key(b64: &str) -> Result<MegaFileKey, PluginError> {
    let raw = decode_b64_strict(b64, 32)?;
    let words = bytes_to_words::<8>(&raw);
    let aes_words = [
        words[0] ^ words[4],
        words[1] ^ words[5],
        words[2] ^ words[6],
        words[3] ^ words[7],
    ];
    let aes_key = words_to_bytes_16(&aes_words);
    let iv = u32_pair_to_bytes(words[4], words[5]);
    let meta_mac = u32_pair_to_bytes(words[6], words[7]);
    Ok(MegaFileKey {
        aes_key,
        iv,
        meta_mac,
    })
}

pub fn parse_folder_key(b64: &str) -> Result<MegaFolderKey, PluginError> {
    let raw = decode_b64_strict(b64, 16)?;
    let aes_key: [u8; 16] = raw.as_slice().try_into().expect("len checked");
    Ok(MegaFolderKey { aes_key })
}

fn decode_b64_strict(input: &str, expected_len: usize) -> Result<Vec<u8>, PluginError> {
    let raw = URL_SAFE_NO_PAD
        .decode(input.trim())
        .map_err(|e| PluginError::InvalidKey(format!("base64url decode: {e}")))?;
    if raw.len() != expected_len {
        return Err(PluginError::InvalidKey(format!(
            "expected {expected_len} bytes, got {}",
            raw.len()
        )));
    }
    Ok(raw)
}

fn bytes_to_words<const N: usize>(b: &[u8]) -> [u32; N] {
    let mut out = [0u32; N];
    for (i, w) in out.iter_mut().enumerate() {
        let off = i * 4;
        *w = u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]);
    }
    out
}

fn words_to_bytes_16(w: &[u32; 4]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, word) in w.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn u32_pair_to_bytes(hi: u32, lo: u32) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&hi.to_be_bytes());
    out[4..].copy_from_slice(&lo.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_file_key_xor_folds_correctly() {
        let raw: [u8; 32] = std::array::from_fn(|i| i as u8);
        let b64 = URL_SAFE_NO_PAD.encode(raw);
        let k = parse_file_key(&b64).unwrap();

        // word0 = 0x00010203, word4 = 0x10111213 → xor = 0x10101010
        // word1 = 0x04050607, word5 = 0x14151617 → xor = 0x10101010
        // word2 = 0x08090a0b, word6 = 0x18191a1b → xor = 0x10101010
        // word3 = 0x0c0d0e0f, word7 = 0x1c1d1e1f → xor = 0x10101010
        let expected_key = [0x10u8; 16];
        assert_eq!(k.aes_key, expected_key);
        assert_eq!(k.iv, [16, 17, 18, 19, 20, 21, 22, 23]);
        assert_eq!(k.meta_mac, [24, 25, 26, 27, 28, 29, 30, 31]);
    }

    #[test]
    fn parse_file_key_rejects_wrong_length() {
        let raw = [0u8; 24];
        let b64 = URL_SAFE_NO_PAD.encode(raw);
        let err = parse_file_key(&b64).unwrap_err();
        assert!(matches!(err, PluginError::InvalidKey(_)));
    }

    #[test]
    fn parse_file_key_rejects_invalid_b64() {
        let err = parse_file_key("!!!not-base64!!!").unwrap_err();
        assert!(matches!(err, PluginError::InvalidKey(_)));
    }

    #[test]
    fn parse_folder_key_returns_16_bytes() {
        let raw: [u8; 16] = std::array::from_fn(|i| (i * 2) as u8);
        let b64 = URL_SAFE_NO_PAD.encode(raw);
        let k = parse_folder_key(&b64).unwrap();
        assert_eq!(k.aes_key, raw);
    }

    #[test]
    fn parse_folder_key_rejects_file_length() {
        let raw = [0u8; 32];
        let b64 = URL_SAFE_NO_PAD.encode(raw);
        let err = parse_folder_key(&b64).unwrap_err();
        assert!(matches!(err, PluginError::InvalidKey(_)));
    }
}
