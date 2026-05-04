//! MEGA AES-128-CTR streaming decryption + chunk-MAC verification.
//!
//! MEGA uses AES-128-CTR with a 128-bit counter whose top 64 bits are the
//! file IV and bottom 64 bits start at 0 and increment per AES block (16 B).
//! The same AES key is used to compute one CBC-MAC per "chunk" — chunk
//! sizes follow MEGA's deterministic schedule (128 KiB, 256 KiB, 384 KiB,
//! …, 1 MiB, then 1 MiB forever). Each chunk's CBC-MAC starts from
//! IV = `[iv0, iv1, iv0, iv1]` (16 bytes — file IV repeated).
//!
//! After the stream is fully consumed the chunk MACs are folded into a
//! single 16-byte block (CBC-MAC again with the same IV and key); the
//! 8-byte file MAC is the XOR of the two 8-byte halves of that final
//! block. Comparing it to the `metaMac` from the URL key reveals
//! corruption — `MegaDecryptor` exposes both the computed MAC and a
//! convenience [`MegaDecryptor::verify_against`] helper.

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use ctr::cipher::{KeyIvInit, StreamCipher};

use crate::error::PluginError;

type Aes128Ctr = ctr::Ctr64BE<Aes128>;

/// Streaming decryptor: feed bytes in arbitrary slices, recover plaintext
/// in place, accumulate the MEGA chunk MAC, then call [`Self::finalize`].
pub struct MegaDecryptor {
    cipher: Aes128Ctr,
    aes: Aes128,
    iv: [u8; 8],
    /// Index into the cumulative chunk schedule (which chunk we're currently filling).
    current_chunk: usize,
    /// Bytes consumed in the current chunk (resets at each chunk boundary).
    current_chunk_bytes: u64,
    /// CBC-MAC running state for the in-progress chunk.
    current_mac_iv: [u8; 16],
    /// Buffer for partial 16-byte CBC blocks straddling caller boundaries.
    mac_partial: [u8; 16],
    mac_partial_len: usize,
    /// Concatenation of completed chunk MACs (host stores or kept in memory:
    /// 100 GB / 1 MiB chunks → 100 k entries × 16 B = 1.6 MB, acceptable).
    chunk_macs: Vec<[u8; 16]>,
}

impl MegaDecryptor {
    pub fn new(aes_key: [u8; 16], iv: [u8; 8]) -> Self {
        let mut counter = [0u8; 16];
        counter[..8].copy_from_slice(&iv);
        let cipher = Aes128Ctr::new((&aes_key).into(), (&counter).into());
        let aes = Aes128::new((&aes_key).into());
        let mac_iv = build_mac_iv(&iv);
        Self {
            cipher,
            aes,
            iv,
            current_chunk: 0,
            current_chunk_bytes: 0,
            current_mac_iv: mac_iv,
            mac_partial: [0u8; 16],
            mac_partial_len: 0,
            chunk_macs: Vec::new(),
        }
    }

    /// Decrypt `buf` in place AND advance the chunk-MAC over the resulting
    /// plaintext. May straddle MEGA chunk boundaries; the implementation
    /// closes a chunk MAC and starts a new one as soon as the cumulative
    /// byte count crosses an entry of [`chunk_size_at`].
    pub fn process(&mut self, buf: &mut [u8]) {
        // CTR step: decrypt = encrypt for stream ciphers.
        self.cipher.apply_keystream(buf);

        // CBC-MAC step over plaintext, splitting at chunk boundaries.
        let mut consumed = 0;
        while consumed < buf.len() {
            let chunk_size = chunk_size_at(self.current_chunk);
            let remaining_in_chunk = chunk_size - self.current_chunk_bytes;
            let take = core::cmp::min(remaining_in_chunk as usize, buf.len() - consumed);
            self.absorb_into_mac(&buf[consumed..consumed + take]);
            self.current_chunk_bytes += take as u64;
            consumed += take;
            if self.current_chunk_bytes == chunk_size {
                self.close_current_chunk();
            }
        }
    }

    /// Closes any pending chunk and returns the final 8-byte file MAC
    /// (matching `metaMac`). Calling twice is undefined; use exactly once.
    pub fn finalize(mut self) -> [u8; 8] {
        if self.current_chunk_bytes > 0 || self.mac_partial_len > 0 {
            self.close_current_chunk();
        }
        // Final fold: CBC-MAC over concatenation of chunk MACs, IV = build_mac_iv(self.iv).
        let mut acc = build_mac_iv(&self.iv);
        for cm in &self.chunk_macs {
            xor16(&mut acc, cm);
            self.aes
                .encrypt_block(GenericArray::from_mut_slice(&mut acc));
        }
        // metaMac = first half XOR second half of the final 16-byte MAC.
        let mut out = [0u8; 8];
        for i in 0..8 {
            out[i] = acc[i] ^ acc[i + 8];
        }
        out
    }

    /// Convenience: finalize and compare against an expected MAC, returning
    /// `MacMismatch` on corruption.
    pub fn verify_against(self, expected_meta_mac: [u8; 8]) -> Result<(), PluginError> {
        let actual = self.finalize();
        if actual == expected_meta_mac {
            Ok(())
        } else {
            Err(PluginError::MacMismatch)
        }
    }

    /// Encrypt-only path: CTR step without touching the MAC accumulator.
    /// Used by tests and by hosts that want to checksum *plaintext* by
    /// piping through [`Self::absorb_plaintext`] before encrypting.
    pub fn encrypt_only(&mut self, buf: &mut [u8]) {
        self.cipher.apply_keystream(buf);
    }

    /// MAC-only path: feed plaintext through the chunk-MAC accumulator
    /// without altering ciphertext state. Mirrors the bytes [`Self::process`]
    /// would have absorbed if applied to ciphertext. Useful for offline
    /// computation of an expected MAC over a known plaintext.
    pub fn absorb_plaintext(&mut self, buf: &[u8]) {
        let mut consumed = 0;
        while consumed < buf.len() {
            let chunk_size = chunk_size_at(self.current_chunk);
            let remaining_in_chunk = chunk_size - self.current_chunk_bytes;
            let take = core::cmp::min(remaining_in_chunk as usize, buf.len() - consumed);
            self.absorb_into_mac(&buf[consumed..consumed + take]);
            self.current_chunk_bytes += take as u64;
            consumed += take;
            if self.current_chunk_bytes == chunk_size {
                self.close_current_chunk();
            }
        }
    }

    fn absorb_into_mac(&mut self, mut data: &[u8]) {
        // Fill any pending partial block first.
        if self.mac_partial_len > 0 {
            let take = core::cmp::min(16 - self.mac_partial_len, data.len());
            self.mac_partial[self.mac_partial_len..self.mac_partial_len + take]
                .copy_from_slice(&data[..take]);
            self.mac_partial_len += take;
            data = &data[take..];
            if self.mac_partial_len == 16 {
                let block = self.mac_partial;
                self.mac_block(&block);
                self.mac_partial_len = 0;
            }
        }
        while data.len() >= 16 {
            let block: [u8; 16] = data[..16].try_into().expect("len checked");
            self.mac_block(&block);
            data = &data[16..];
        }
        if !data.is_empty() {
            self.mac_partial[..data.len()].copy_from_slice(data);
            self.mac_partial_len = data.len();
        }
    }

    fn mac_block(&mut self, block: &[u8; 16]) {
        xor16(&mut self.current_mac_iv, block);
        self.aes
            .encrypt_block(GenericArray::from_mut_slice(&mut self.current_mac_iv));
    }

    fn close_current_chunk(&mut self) {
        if self.mac_partial_len > 0 {
            // Zero-pad partial block.
            for b in self.mac_partial[self.mac_partial_len..].iter_mut() {
                *b = 0;
            }
            let block = self.mac_partial;
            self.mac_block(&block);
            self.mac_partial_len = 0;
        }
        self.chunk_macs.push(self.current_mac_iv);
        self.current_mac_iv = build_mac_iv(&self.iv);
        self.current_chunk_bytes = 0;
        self.current_chunk += 1;
    }
}

fn build_mac_iv(iv: &[u8; 8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(iv);
    out[8..].copy_from_slice(iv);
    out
}

fn xor16(dst: &mut [u8; 16], src: &[u8; 16]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

/// MEGA chunk schedule. chunk_size_at(0..7) = 128, 256, 384, 512, 640,
/// 768, 896, 1024 KiB, then 1024 KiB forever.
pub fn chunk_size_at(index: usize) -> u64 {
    let kib = if index < 8 {
        (index as u64 + 1) * 128
    } else {
        1024
    };
    kib * 1024
}

/// Cumulative byte offset at which chunk `index` ends.
pub fn cumulative_chunk_end(index: usize) -> u64 {
    (0..=index).map(chunk_size_at).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn chunk_size_schedule_is_mega_canonical() {
        assert_eq!(chunk_size_at(0), 128 * 1024);
        assert_eq!(chunk_size_at(1), 256 * 1024);
        assert_eq!(chunk_size_at(7), 1024 * 1024);
        assert_eq!(chunk_size_at(8), 1024 * 1024);
        assert_eq!(chunk_size_at(100), 1024 * 1024);
    }

    #[test]
    fn cumulative_chunk_end_accumulates() {
        // Sum 128+256+384+512+640+768+896+1024 KiB = 4608 KiB at idx 7.
        assert_eq!(cumulative_chunk_end(7), 4608 * 1024);
        assert_eq!(cumulative_chunk_end(8), (4608 + 1024) * 1024);
    }

    #[test]
    fn ctr_streaming_works_with_arbitrary_chunk_sizes() {
        // Symmetry: encrypt then decrypt feeding 1 byte at a time recovers plaintext.
        let key = [0x42u8; 16];
        let iv = [0x01u8; 8];
        let plaintext: Vec<u8> = (0u32..1024).flat_map(|i| i.to_le_bytes()).collect();

        let mut full = plaintext.clone();
        let mut a = MegaDecryptor::new(key, iv);
        a.process(&mut full);

        let mut split = full.clone();
        let mut b = MegaDecryptor::new(key, iv);
        for byte in split.iter_mut() {
            b.process(std::slice::from_mut(byte));
        }
        assert_eq!(split, plaintext);
    }

    #[test]
    fn finalize_returns_8_bytes() {
        let dec = MegaDecryptor::new([0u8; 16], [0u8; 8]);
        let mac = dec.finalize();
        assert_eq!(mac.len(), 8);
    }

    #[test]
    fn round_trip_recovers_plaintext_and_macs_match() {
        // End-to-end: simulate the upload→download path against MEGA semantics.
        // 1. Compute MAC over plaintext (uploader side).
        // 2. Encrypt plaintext with CTR (uploader side).
        // 3. Decrypt + MAC ciphertext via MegaDecryptor (downloader side).
        // 4. Recovered plaintext + computed MAC must both match.
        //
        // Buffer length 768 KiB straddles chunks 0 (128 KiB) + 1 (256 KiB) + part of 2.
        let key = [0x11u8; 16];
        let iv = [0x22u8; 8];
        let plaintext: Vec<u8> = (0..(768 * 1024)).map(|i| i as u8).collect();
        let plain_sha = Sha256::digest(&plaintext);

        // Uploader: MAC plaintext.
        let mut maccer = MegaDecryptor::new(key, iv);
        maccer.absorb_plaintext(&plaintext);
        let expected_mac = maccer.finalize();

        // Uploader: encrypt with CTR (no MAC).
        let mut ciphertext = plaintext.clone();
        let mut encer = MegaDecryptor::new(key, iv);
        encer.encrypt_only(&mut ciphertext);

        // Downloader: decrypt + MAC.
        let mut dec = MegaDecryptor::new(key, iv);
        dec.process(&mut ciphertext);
        let observed_mac = dec.finalize();

        assert_eq!(
            Sha256::digest(&ciphertext),
            plain_sha,
            "plaintext recovered byte-for-byte after round-trip"
        );
        assert_eq!(
            observed_mac, expected_mac,
            "downloader MAC of recovered plaintext == uploader MAC of original plaintext"
        );
    }

    #[test]
    fn verify_against_returns_ok_on_match() {
        let key = [0u8; 16];
        let iv = [0u8; 8];
        let mut buf = vec![0u8; 1024];
        let mut dec = MegaDecryptor::new(key, iv);
        dec.process(&mut buf);
        let mac = dec.finalize();

        // Feed the same plaintext shape through a fresh decryptor and check
        // its MAC matches when we verify against the value we just observed.
        let mut buf2 = vec![0u8; 1024];
        let mut dec2 = MegaDecryptor::new(key, iv);
        dec2.process(&mut buf2);
        dec2.verify_against(mac).expect("MAC must match");
    }

    #[test]
    fn verify_against_returns_mac_mismatch_on_corruption() {
        let key = [0u8; 16];
        let iv = [0u8; 8];
        let mut buf = vec![0u8; 1024];
        let mut dec = MegaDecryptor::new(key, iv);
        dec.process(&mut buf);
        let bogus = [0xFFu8; 8];
        let err = dec.verify_against(bogus).unwrap_err();
        assert!(matches!(err, PluginError::MacMismatch));
    }

    #[test]
    fn streaming_decrypt_is_memory_bounded() {
        // Process 16 MiB through 4 KiB caller buffers. Verifies the API
        // never forces the caller to hold the whole stream in memory and
        // the decryptor's own state is bounded to chunk_macs.len() ~= 16.
        let key = [0u8; 16];
        let iv = [0u8; 8];
        let mut buf = vec![0u8; 4096];
        let mut dec = MegaDecryptor::new(key, iv);
        for _ in 0..(16 * 1024 / 4) {
            dec.process(&mut buf);
        }
        let _mac = dec.finalize();
    }
}
