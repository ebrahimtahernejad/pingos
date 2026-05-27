use anyhow::{anyhow, bail, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;

use crate::proto::{
    Compression, Frame, Op, COMPRESS_MIN, FF_COMPRESSED, FLAG_ENCRYPTED, MAGIC, MAX_DATA_PAYLOAD,
    MAX_WIRE_SIZE, VERSION,
};

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
// version(1) op(1) flags(1) conn_id(8) seq(4) ack(4) win(2) plen(2)
const INNER_HEADER_LEN: usize = 1 + 1 + 1 + 8 + 4 + 4 + 2 + 2;

#[derive(Clone)]
pub struct Codec {
    cipher: Option<ChaCha20Poly1305>,
    compression: Compression,
}

impl Codec {
    /// Build a codec. Empty password = no encryption (frames flow in cleartext).
    pub fn new(password: &str, compression: Compression) -> Self {
        let cipher = if password.is_empty() {
            None
        } else {
            // BLAKE3 keyed-hash to derive a 32-byte ChaCha20-Poly1305 key.
            let key_bytes =
                blake3::derive_key("pingos v1 chacha20-poly1305", password.as_bytes());
            let key = Key::from_slice(&key_bytes);
            Some(ChaCha20Poly1305::new(key))
        };
        Codec { cipher, compression }
    }

    pub fn is_encrypted(&self) -> bool {
        self.cipher.is_some()
    }

    pub fn compression(&self) -> Compression {
        self.compression
    }

    /// Encode a `Frame` into a single on-the-wire packet (ICMP echo payload).
    pub fn encode(&self, frame: &Frame) -> Result<Bytes> {
        // Maybe compress the payload.
        let (payload, compressed) = self.maybe_compress(&frame.payload);

        if payload.len() > MAX_DATA_PAYLOAD {
            bail!(
                "frame payload too large after framing: {} > {}",
                payload.len(),
                MAX_DATA_PAYLOAD
            );
        }

        let mut frame_flags = 0u8;
        if compressed {
            frame_flags |= FF_COMPRESSED;
        }

        let inner_len = INNER_HEADER_LEN + payload.len();
        let mut inner = BytesMut::with_capacity(inner_len);
        inner.put_u8(VERSION);
        inner.put_u8(frame.op as u8);
        inner.put_u8(frame_flags);
        inner.put_u64(frame.conn_id);
        inner.put_u32(frame.seq);
        inner.put_u32(frame.ack);
        inner.put_u16(frame.win);
        inner.put_u16(payload.len() as u16);
        inner.extend_from_slice(&payload);

        let mut out = BytesMut::with_capacity(4 + 1 + NONCE_LEN + inner.len() + TAG_LEN);
        out.extend_from_slice(&MAGIC);

        match &self.cipher {
            None => {
                out.put_u8(0);
                out.extend_from_slice(&inner);
            }
            Some(cipher) => {
                let mut nonce_bytes = [0u8; NONCE_LEN];
                rand::thread_rng().fill_bytes(&mut nonce_bytes);
                let nonce = Nonce::from_slice(&nonce_bytes);
                let ciphertext = cipher
                    .encrypt(nonce, inner.as_ref())
                    .map_err(|_| anyhow!("encryption failed"))?;
                out.put_u8(FLAG_ENCRYPTED);
                out.extend_from_slice(&nonce_bytes);
                out.extend_from_slice(&ciphertext);
            }
        }

        Ok(out.freeze())
    }

    /// Decode a single on-the-wire packet into a `Frame`.
    pub fn decode(&self, mut bytes: &[u8]) -> Result<Frame> {
        if bytes.len() > MAX_WIRE_SIZE {
            bail!("packet too large: {}", bytes.len());
        }
        if bytes.len() < 4 + 1 {
            bail!("packet too short");
        }
        if bytes[..4] != MAGIC {
            bail!("bad magic");
        }
        bytes = &bytes[4..];

        let flags = bytes[0];
        bytes = &bytes[1..];
        let encrypted = (flags & FLAG_ENCRYPTED) != 0;

        let inner: Vec<u8> = if encrypted {
            let cipher = self
                .cipher
                .as_ref()
                .ok_or_else(|| anyhow!("received encrypted frame but codec has no key"))?;
            if bytes.len() < NONCE_LEN + TAG_LEN {
                bail!("encrypted packet too short");
            }
            let (nonce_bytes, ct) = bytes.split_at(NONCE_LEN);
            let nonce = Nonce::from_slice(nonce_bytes);
            cipher
                .decrypt(nonce, ct)
                .map_err(|_| anyhow!("decryption / auth failed"))?
        } else {
            if self.cipher.is_some() {
                bail!("received plaintext frame but codec requires encryption");
            }
            bytes.to_vec()
        };

        if inner.len() < INNER_HEADER_LEN {
            bail!("inner frame too short");
        }
        let mut cursor: &[u8] = &inner;
        let version = cursor.get_u8();
        if version != VERSION {
            bail!("unsupported version {}", version);
        }
        let op_raw = cursor.get_u8();
        let op = Op::from_u8(op_raw).ok_or_else(|| anyhow!("bad op {}", op_raw))?;
        let frame_flags = cursor.get_u8();
        let conn_id = cursor.get_u64();
        let seq = cursor.get_u32();
        let ack = cursor.get_u32();
        let win = cursor.get_u16();

        if cursor.remaining() < 2 {
            bail!("plen field truncated");
        }
        let plen = cursor.get_u16() as usize;
        if cursor.remaining() != plen {
            bail!(
                "payload length mismatch: declared {}, got {}",
                plen,
                cursor.remaining()
            );
        }

        let raw_payload = Bytes::copy_from_slice(cursor);
        let payload = if frame_flags & FF_COMPRESSED != 0 {
            let decompressed = lz4_flex::decompress_size_prepended(&raw_payload)
                .map_err(|e| anyhow!("lz4 decompress: {}", e))?;
            Bytes::from(decompressed)
        } else {
            raw_payload
        };

        Ok(Frame {
            op,
            conn_id,
            seq,
            ack,
            win,
            payload,
        })
    }

    fn maybe_compress(&self, payload: &Bytes) -> (Bytes, bool) {
        match self.compression {
            Compression::None => (payload.clone(), false),
            Compression::Lz4 => {
                if payload.len() < COMPRESS_MIN {
                    return (payload.clone(), false);
                }
                let compressed = lz4_flex::compress_prepend_size(payload);
                if compressed.len() + 4 < payload.len() {
                    // ~4 bytes is roughly the savings threshold to be worth it.
                    (Bytes::from(compressed), true)
                } else {
                    (payload.clone(), false)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_frame(op: Op, payload: &[u8]) -> Frame {
        Frame {
            op,
            conn_id: 0xDEAD_BEEF_CAFE_F00D,
            seq: 42,
            ack: 17,
            win: 200,
            payload: Bytes::copy_from_slice(payload),
        }
    }

    #[test]
    fn roundtrip_plaintext() {
        let c = Codec::new("", Compression::None);
        let f = sample_frame(Op::Data, b"hello world");
        let bytes = c.encode(&f).unwrap();
        let g = c.decode(&bytes).unwrap();
        assert_eq!(g.op, Op::Data);
        assert_eq!(g.conn_id, f.conn_id);
        assert_eq!(g.seq, f.seq);
        assert_eq!(g.ack, f.ack);
        assert_eq!(g.win, f.win);
        assert_eq!(g.payload, f.payload);
    }

    #[test]
    fn roundtrip_encrypted() {
        let c = Codec::new("hunter2", Compression::None);
        let f = sample_frame(Op::Syn, b"example.com:443");
        let bytes = c.encode(&f).unwrap();
        let g = c.decode(&bytes).unwrap();
        assert_eq!(g.op, Op::Syn);
        assert_eq!(g.payload, f.payload);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let a = Codec::new("alpha", Compression::None);
        let b = Codec::new("beta", Compression::None);
        let f = sample_frame(Op::Data, b"secret");
        let bytes = a.encode(&f).unwrap();
        assert!(b.decode(&bytes).is_err());
    }

    #[test]
    fn plaintext_to_encrypted_fails() {
        let p = Codec::new("", Compression::None);
        let e = Codec::new("k", Compression::None);
        let f = sample_frame(Op::Ping, &[]);
        let bytes = p.encode(&f).unwrap();
        assert!(e.decode(&bytes).is_err());
    }

    #[test]
    fn roundtrip_lz4_large_payload() {
        let c = Codec::new("", Compression::Lz4);
        // Compressible payload (repeating pattern).
        let payload: Vec<u8> = (0..800).map(|i| (i % 7) as u8).collect();
        let f = sample_frame(Op::Data, &payload);
        let bytes = c.encode(&f).unwrap();
        // Should have shrunk significantly: encoded should be much smaller than 800 + header.
        assert!(bytes.len() < 400, "encoded {} bytes", bytes.len());
        let g = c.decode(&bytes).unwrap();
        assert_eq!(g.payload.as_ref(), payload.as_slice());
    }

    #[test]
    fn lz4_skips_short_payload() {
        let c = Codec::new("", Compression::Lz4);
        // Below COMPRESS_MIN — should not be compressed.
        let f = sample_frame(Op::Data, b"short");
        let bytes = c.encode(&f).unwrap();
        let g = c.decode(&bytes).unwrap();
        assert_eq!(g.payload.as_ref(), b"short");
    }

    #[test]
    fn lz4_skips_incompressible_payload() {
        let c = Codec::new("", Compression::Lz4);
        // Random-ish bytes (poly hash) don't compress.
        let payload: Vec<u8> = (0u32..1000).map(|i| (i.wrapping_mul(2654435761) >> 23) as u8).collect();
        let f = sample_frame(Op::Data, &payload);
        let bytes = c.encode(&f).unwrap();
        let g = c.decode(&bytes).unwrap();
        assert_eq!(g.payload.as_ref(), payload.as_slice());
    }

    #[test]
    fn one_side_compressed_other_side_unaware_still_decodes() {
        // The flag travels on the wire, so a Codec with Compression::None can
        // still decode frames that came in compressed.
        let sender = Codec::new("", Compression::Lz4);
        let receiver = Codec::new("", Compression::None);
        let payload: Vec<u8> = (0..800).map(|i| (i % 11) as u8).collect();
        let f = sample_frame(Op::Data, &payload);
        let bytes = sender.encode(&f).unwrap();
        let g = receiver.decode(&bytes).unwrap();
        assert_eq!(g.payload.as_ref(), payload.as_slice());
    }
}
