//! Wire protocol constants and the in-memory `Frame` representation.
//!
//! All multi-byte integers are big-endian. Two outer formats coexist on the
//! wire — selected by sender per packet based on whether FEC is enabled:
//!
//! Non-FEC outer (magic = "PNG1"):
//!
//! ```text
//! magic[4]   = "PNG1"
//! flags[1]   = bit0: encrypted
//! nonce[12]  (only when flags.encrypted)
//! ciphertext (inner frame; with 16-byte Poly1305 tag when encrypted)
//! ```
//!
//! FEC outer (magic = "PNG2") — see `fec` module:
//!
//! ```text
//! magic[4]      = "PNG2"
//! fec_group[4]
//! fec_index[1]
//! fec_n[1]
//! fec_k[1]
//! shard_payload[..]   (variable; data shards or parity bytes)
//! ```
//!
//! Inner (v=2 — same regardless of outer):
//!
//! ```text
//! version[1]    = 2
//! op[1]         (see `Op`)
//! frame_flags[1] bit0=payload_compressed
//! conn_id[8]
//! seq[4]
//! ack[4]
//! win[2]
//! plen[2]
//! payload[plen]
//! ```

/// Outer magic for direct (non-FEC) encoded frames.
pub const MAGIC: [u8; 4] = *b"PNG1";
/// Outer magic for FEC-wrapped shards (data or parity).
pub const FEC_MAGIC: [u8; 4] = *b"PNG2";
pub const VERSION: u8 = 2;

pub const FLAG_ENCRYPTED: u8 = 0b0000_0001;

// Inner-frame `frame_flags` bits.
pub const FF_COMPRESSED: u8 = 0b0000_0001;

/// Minimum payload size before LZ4 compression is attempted. Below this we
/// skip compression — overhead would likely exceed savings.
pub const COMPRESS_MIN: usize = 96;

/// Max TCP payload bytes per DATA frame. Conservative to fit inside the smallest
/// likely path MTU after IPv4 + ICMP + outer + tag overheads.
pub const MAX_DATA_PAYLOAD: usize = 1200;

/// Maximum on-the-wire frame size we will ever receive. Allows headroom for
/// outer header, nonce, inner header, payload, and tag.
pub const MAX_WIRE_SIZE: usize = MAX_DATA_PAYLOAD + 256;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Op {
    Ping = 1,
    Pong = 2,
    Syn = 3,
    SynAck = 4,
    Data = 5,
    Ack = 6,
    Fin = 7,
    Rst = 8,
}

impl Op {
    pub fn from_u8(v: u8) -> Option<Op> {
        Some(match v {
            1 => Op::Ping,
            2 => Op::Pong,
            3 => Op::Syn,
            4 => Op::SynAck,
            5 => Op::Data,
            6 => Op::Ack,
            7 => Op::Fin,
            8 => Op::Rst,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub op: Op,
    pub conn_id: u64,
    pub seq: u32,
    pub ack: u32,
    pub win: u16,
    pub payload: bytes::Bytes,
}

impl Frame {
    pub fn control(op: Op, conn_id: u64) -> Self {
        Frame {
            op,
            conn_id,
            seq: 0,
            ack: 0,
            win: 0,
            payload: bytes::Bytes::new(),
        }
    }
}

/// On-wire compression scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Compression {
    None,
    Lz4,
}

/// FEC configuration. `n` data shards + `k` parity shards per group.
/// `n == 0` means FEC is disabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FecConfig {
    pub data_shards: u8,
    pub parity_shards: u8,
}

impl FecConfig {
    pub fn disabled() -> Self {
        FecConfig { data_shards: 0, parity_shards: 0 }
    }
    pub fn is_enabled(&self) -> bool {
        self.data_shards > 0 && self.parity_shards > 0
    }
}
