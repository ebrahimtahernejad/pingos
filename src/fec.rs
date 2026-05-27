//! Forward-Error-Correction at the transport (post-codec) layer.
//!
//! When enabled, every codec-encoded frame becomes a "data shard" wrapped in
//! a `PNG2` envelope. After N data shards in a group, the encoder emits K
//! parity shards (also wrapped in PNG2). The receiver:
//!
//!   - delivers every data shard to the codec immediately (no group delay);
//!   - stores all received shards (data + parity);
//!   - once it has >= N shards total AND at least one parity, runs Reed-Solomon
//!     reconstruct to recover any missing data shards, then runs them through
//!     the codec and delivers as if they had arrived normally.
//!
//! Bandwidth overhead is approximately K/N. Latency overhead is zero for
//! received data shards. Parity emission is batched at group boundary.
//!
//! Wire format of a PNG2 packet:
//!
//! ```text
//! magic[4]   = "PNG2"
//! group[4]
//! index[1]   (0..N = data, N..N+K = parity)
//! n[1]
//! k[1]
//! body[..]   data: codec-encoded frame bytes; parity: RS parity bytes
//! ```
//!
//! Padding/length: data shards on the wire carry only their codec-encoded
//! bytes (no padding). RS needs equal-size shards; the encoder internally
//! builds `[u32 actual_len BE][bytes][zero pad]` rows of size `shard_len`,
//! where `shard_len = max(len+4)` across the group's data shards. The receiver
//! learns `shard_len` from the size of any received parity shard.

use std::collections::HashMap;

use anyhow::{anyhow, bail, Result};
use bytes::{BufMut, Bytes, BytesMut};
use reed_solomon_erasure::galois_8::ReedSolomon;

use crate::proto::{FecConfig, FEC_MAGIC};

pub const FEC_ENVELOPE_LEN: usize = 4 + 4 + 1 + 1 + 1;

#[derive(Debug)]
pub enum Shard {
    Data {
        group: u32,
        index: u8,
        frame_bytes: Bytes,
    },
    Parity {
        group: u32,
        index: u8,
        payload: Bytes,
    },
}

pub struct FecEncoder {
    cfg: FecConfig,
    next_group: u32,
    pending: Vec<Bytes>,
}

impl FecEncoder {
    pub fn new(cfg: FecConfig) -> Result<Self> {
        ReedSolomon::new(cfg.data_shards as usize, cfg.parity_shards as usize)
            .map_err(|e| anyhow!("invalid RS config: {:?}", e))?;
        Ok(Self {
            cfg,
            next_group: 0,
            pending: Vec::with_capacity(cfg.data_shards as usize),
        })
    }

    pub fn cfg(&self) -> FecConfig {
        self.cfg
    }

    /// Submit one codec-encoded frame; returns the data shard and any parity
    /// shards if this submission completed a group.
    pub fn submit(&mut self, frame_bytes: Bytes) -> Vec<Shard> {
        let group = self.next_group;
        let index = self.pending.len() as u8;
        self.pending.push(frame_bytes.clone());
        let mut out = vec![Shard::Data {
            group,
            index,
            frame_bytes,
        }];

        if self.pending.len() == self.cfg.data_shards as usize {
            let n = self.cfg.data_shards as usize;
            let k = self.cfg.parity_shards as usize;
            let shard_len = self.pending.iter().map(|b| b.len() + 4).max().unwrap_or(4);
            let mut shards: Vec<Vec<u8>> = Vec::with_capacity(n + k);
            for b in &self.pending {
                let mut v = vec![0u8; shard_len];
                v[0..4].copy_from_slice(&(b.len() as u32).to_be_bytes());
                v[4..4 + b.len()].copy_from_slice(b);
                shards.push(v);
            }
            for _ in 0..k {
                shards.push(vec![0u8; shard_len]);
            }
            let rs = ReedSolomon::new(n, k).expect("validated in new()");
            rs.encode(&mut shards).expect("rs encode");
            for (i, parity_shard) in shards.iter().enumerate().skip(n) {
                out.push(Shard::Parity {
                    group,
                    index: i as u8,
                    payload: Bytes::copy_from_slice(parity_shard),
                });
            }
            self.pending.clear();
            self.next_group = self.next_group.wrapping_add(1);
        }
        out
    }
}

/// Serialize a shard with its PNG2 envelope. `cfg` provides the n/k fields.
pub fn wrap_shard(s: &Shard, cfg: FecConfig) -> Bytes {
    let body: &[u8] = match s {
        Shard::Data { frame_bytes, .. } => frame_bytes,
        Shard::Parity { payload, .. } => payload,
    };
    let (group, index) = match s {
        Shard::Data { group, index, .. } => (*group, *index),
        Shard::Parity { group, index, .. } => (*group, *index),
    };
    let mut out = BytesMut::with_capacity(FEC_ENVELOPE_LEN + body.len());
    out.extend_from_slice(&FEC_MAGIC);
    out.put_u32(group);
    out.put_u8(index);
    out.put_u8(cfg.data_shards);
    out.put_u8(cfg.parity_shards);
    out.extend_from_slice(body);
    out.freeze()
}

#[derive(Debug)]
pub enum WireKind {
    /// Direct (non-FEC) codec-encoded frame.
    Plain(Bytes),
    Data {
        group: u32,
        index: u8,
        n: u8,
        k: u8,
        frame_bytes: Bytes,
    },
    Parity {
        group: u32,
        index: u8,
        n: u8,
        k: u8,
        payload: Bytes,
    },
}

pub fn parse_outer(bytes: &[u8]) -> Result<WireKind> {
    if bytes.len() < 4 {
        bail!("too short");
    }
    if bytes[..4] != FEC_MAGIC {
        return Ok(WireKind::Plain(Bytes::copy_from_slice(bytes)));
    }
    if bytes.len() < FEC_ENVELOPE_LEN {
        bail!("fec envelope truncated");
    }
    let group = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let index = bytes[8];
    let n = bytes[9];
    let k = bytes[10];
    let body = Bytes::copy_from_slice(&bytes[FEC_ENVELOPE_LEN..]);
    if n == 0 || k == 0 {
        bail!("invalid fec config in envelope");
    }
    let total = n as u16 + k as u16;
    if (index as u16) >= total {
        bail!("fec index out of range");
    }
    if index < n {
        Ok(WireKind::Data {
            group,
            index,
            n,
            k,
            frame_bytes: body,
        })
    } else {
        Ok(WireKind::Parity {
            group,
            index,
            n,
            k,
            payload: body,
        })
    }
}

#[derive(Default)]
pub struct FecDecoder {
    groups: HashMap<u32, GroupState>,
    /// Max simultaneous groups kept. When this is exceeded, the lowest group
    /// id is evicted.
    pub max_groups: usize,
}

struct GroupState {
    n: u8,
    k: u8,
    /// For idx < n: the codec-encoded frame bytes (as received, no padding).
    /// For idx >= n: the parity bytes.
    shards: Vec<Option<Bytes>>,
    recovered: bool,
}

impl FecDecoder {
    pub fn new() -> Self {
        FecDecoder {
            groups: HashMap::new(),
            max_groups: 256,
        }
    }

    /// Submit a parsed FEC wire kind. Returns any RECOVERED codec-encoded
    /// frame bytes for missing data shards.
    pub fn submit(&mut self, kind: &WireKind) -> Vec<Bytes> {
        let (group, index, n, k, body) = match kind {
            WireKind::Plain(_) => return vec![],
            WireKind::Data {
                group,
                index,
                n,
                k,
                frame_bytes,
            } => (*group, *index, *n, *k, frame_bytes.clone()),
            WireKind::Parity {
                group,
                index,
                n,
                k,
                payload,
            } => (*group, *index, *n, *k, payload.clone()),
        };
        let g = self.groups.entry(group).or_insert_with(|| GroupState {
            n,
            k,
            shards: vec![None; (n as usize) + (k as usize)],
            recovered: false,
        });
        // Reject if n/k differ from a previously seen group with same id (shouldn't happen).
        if g.n != n || g.k != k {
            return vec![];
        }
        if g.shards[index as usize].is_none() {
            g.shards[index as usize] = Some(body);
        }
        let recovered = self.try_recover(group);
        self.evict_if_needed();
        recovered
    }

    fn try_recover(&mut self, group: u32) -> Vec<Bytes> {
        let g = match self.groups.get_mut(&group) {
            Some(g) => g,
            None => return vec![],
        };
        if g.recovered {
            return vec![];
        }
        let n = g.n as usize;
        let k = g.k as usize;
        let missing_data: Vec<usize> = (0..n).filter(|&i| g.shards[i].is_none()).collect();
        if missing_data.is_empty() {
            g.recovered = true;
            return vec![];
        }
        let received = g.shards.iter().filter(|s| s.is_some()).count();
        if received < n {
            return vec![];
        }
        // shard_len is learnt from any parity shard.
        let shard_len = match (n..n + k).find_map(|i| g.shards[i].as_ref().map(|b| b.len())) {
            Some(l) => l,
            None => return vec![],
        };
        if shard_len < 4 {
            return vec![];
        }

        let mut padded: Vec<Option<Vec<u8>>> = g
            .shards
            .iter()
            .enumerate()
            .map(|(i, s)| {
                s.as_ref().map(|b| {
                    if i < n {
                        let actual_len = b.len();
                        let mut v = vec![0u8; shard_len];
                        v[0..4].copy_from_slice(&(actual_len as u32).to_be_bytes());
                        let take = actual_len.min(shard_len.saturating_sub(4));
                        v[4..4 + take].copy_from_slice(&b[..take]);
                        v
                    } else {
                        let mut v = b.to_vec();
                        if v.len() < shard_len {
                            v.resize(shard_len, 0);
                        }
                        v
                    }
                })
            })
            .collect();

        let rs = match ReedSolomon::new(n, k) {
            Ok(r) => r,
            Err(_) => return vec![],
        };
        if rs.reconstruct_data(&mut padded).is_err() {
            return vec![];
        }

        let mut recovered = Vec::new();
        for &i in &missing_data {
            if let Some(s) = padded[i].as_ref() {
                if s.len() < 4 {
                    continue;
                }
                let actual_len =
                    u32::from_be_bytes([s[0], s[1], s[2], s[3]]) as usize;
                if 4 + actual_len > s.len() {
                    continue;
                }
                let frame_bytes = Bytes::copy_from_slice(&s[4..4 + actual_len]);
                g.shards[i] = Some(frame_bytes.clone());
                recovered.push(frame_bytes);
            }
        }
        g.recovered = true;
        recovered
    }

    fn evict_if_needed(&mut self) {
        if self.groups.len() <= self.max_groups {
            return;
        }
        if let Some(&oldest) = self.groups.keys().min() {
            self.groups.remove(&oldest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(n: u8, k: u8) -> FecConfig {
        FecConfig {
            data_shards: n,
            parity_shards: k,
        }
    }

    #[test]
    fn encoder_emits_data_then_parity() {
        let mut enc = FecEncoder::new(cfg(4, 2)).unwrap();
        let mut out = Vec::new();
        for i in 0..4 {
            let bytes = Bytes::from(vec![i as u8; 10 + i as usize]);
            out.extend(enc.submit(bytes));
        }
        // 4 data + 2 parity = 6 shards.
        assert_eq!(out.len(), 6);
        let mut data = 0;
        let mut parity = 0;
        for s in &out {
            match s {
                Shard::Data { .. } => data += 1,
                Shard::Parity { .. } => parity += 1,
            }
        }
        assert_eq!(data, 4);
        assert_eq!(parity, 2);
    }

    #[test]
    fn decoder_recovers_one_missing_data_shard() {
        let c = cfg(4, 2);
        let mut enc = FecEncoder::new(c).unwrap();
        let originals: Vec<Bytes> = (0..4u32)
            .map(|i| Bytes::from(format!("frame{}_some_payload_data", i).into_bytes()))
            .collect();
        let mut shards: Vec<Shard> = Vec::new();
        for b in &originals {
            shards.extend(enc.submit(b.clone()));
        }

        // Drop the 2nd data shard, keep all parity.
        let mut dec = FecDecoder::new();
        let mut delivered = Vec::new();
        for s in &shards {
            match s {
                Shard::Data { index, frame_bytes, .. } => {
                    if *index == 1 {
                        continue; // simulated loss
                    }
                    delivered.push(frame_bytes.clone());
                    let wrapped = wrap_shard(s, c);
                    let kind = parse_outer(&wrapped).unwrap();
                    let rec = dec.submit(&kind);
                    delivered.extend(rec);
                }
                Shard::Parity { .. } => {
                    let wrapped = wrap_shard(s, c);
                    let kind = parse_outer(&wrapped).unwrap();
                    let rec = dec.submit(&kind);
                    delivered.extend(rec);
                }
            }
        }
        assert_eq!(delivered.len(), 4);
        // Ensure all originals are accounted for (order may not match exactly,
        // because the recovered one comes last).
        let mut got: Vec<Vec<u8>> = delivered.iter().map(|b| b.to_vec()).collect();
        let mut want: Vec<Vec<u8>> = originals.iter().map(|b| b.to_vec()).collect();
        got.sort();
        want.sort();
        assert_eq!(got, want);
    }

    #[test]
    fn decoder_recovers_two_missing_with_k_two() {
        let c = cfg(6, 2);
        let mut enc = FecEncoder::new(c).unwrap();
        let originals: Vec<Bytes> = (0..6u32)
            .map(|i| Bytes::from(vec![i as u8; 50 + (i as usize % 7)]))
            .collect();
        let mut shards: Vec<Shard> = Vec::new();
        for b in &originals {
            shards.extend(enc.submit(b.clone()));
        }
        // Drop data shards 0 and 3.
        let mut dec = FecDecoder::new();
        let mut delivered = Vec::new();
        for s in &shards {
            if let Shard::Data { index, .. } = s {
                if *index == 0 || *index == 3 {
                    continue;
                }
            }
            let wrapped = wrap_shard(s, c);
            let kind = parse_outer(&wrapped).unwrap();
            if let WireKind::Data { ref frame_bytes, .. } = kind {
                delivered.push(frame_bytes.clone());
            }
            let rec = dec.submit(&kind);
            delivered.extend(rec);
        }
        assert_eq!(delivered.len(), 6);
        let mut got: Vec<Vec<u8>> = delivered.iter().map(|b| b.to_vec()).collect();
        let mut want: Vec<Vec<u8>> = originals.iter().map(|b| b.to_vec()).collect();
        got.sort();
        want.sort();
        assert_eq!(got, want);
    }

    #[test]
    fn parse_outer_distinguishes_plain_and_fec() {
        let plain = Bytes::from(b"PNG1\x00...".to_vec());
        match parse_outer(&plain).unwrap() {
            WireKind::Plain(b) => assert_eq!(b, plain),
            _ => panic!("expected Plain"),
        }
        let mut fec_pkt = BytesMut::new();
        fec_pkt.extend_from_slice(b"PNG2");
        fec_pkt.put_u32(7);
        fec_pkt.put_u8(0);
        fec_pkt.put_u8(4);
        fec_pkt.put_u8(2);
        fec_pkt.extend_from_slice(b"frame");
        let p = parse_outer(&fec_pkt).unwrap();
        match p {
            WireKind::Data { group, index, n, k, frame_bytes } => {
                assert_eq!(group, 7);
                assert_eq!(index, 0);
                assert_eq!(n, 4);
                assert_eq!(k, 2);
                assert_eq!(frame_bytes.as_ref(), b"frame");
            }
            _ => panic!("expected Data"),
        }
    }
}
