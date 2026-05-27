//! Server side: receives ICMP frames from clients, dials the requested target,
//! and pumps bytes between the upstream TCP and the tunnel.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio::time::timeout;

use crate::cli::ServerArgs;
use crate::conn::{self, Bootstrap, ConnConfig, Outbound, Side};
use crate::fec::{self, FecDecoder, FecEncoder};
use crate::icmp::{IcmpSocket, ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST};
use crate::proto::{FecConfig, Frame, Op, MAX_WIRE_SIZE};
use crate::wire::Codec;

struct PeerState {
    last_icmp_id: AtomicU16,
}

pub async fn run(args: ServerArgs) -> Result<()> {
    let icmp_sock = IcmpSocket::bind(&args.bind)?;
    let codec = Arc::new(Codec::new(&args.password, args.compression));
    if codec.is_encrypted() {
        tracing::info!("encryption: ChaCha20-Poly1305 (password-derived)");
    } else {
        tracing::warn!("encryption: DISABLED (no password set)");
    }
    tracing::info!("compression: {:?}", args.compression);
    let fec_cfg = FecConfig {
        data_shards: args.fec.0,
        parity_shards: args.fec.1,
    };
    if fec_cfg.is_enabled() {
        tracing::info!(
            "FEC: {}:{} (Reed-Solomon)",
            fec_cfg.data_shards,
            fec_cfg.parity_shards
        );
    }

    let cfg = ConnConfig {
        idle_timeout: Duration::from_secs(args.idle_timeout_secs),
        side: Side::Server,
    };

    // Per-peer-IP: track latest ICMP id we saw, so outgoing replies use it (NAT).
    let peer_ids: Arc<Mutex<HashMap<Ipv4Addr, Arc<PeerState>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // conn_id -> (peer_ip, inbound channel).
    type Conns = Arc<Mutex<HashMap<u64, (Ipv4Addr, mpsc::Sender<Frame>)>>>;
    let conns: Conns = Arc::new(Mutex::new(HashMap::new()));

    let (out_tx, mut out_rx) = mpsc::channel::<Outbound>(4096);
    let icmp_seq = Arc::new(AtomicU16::new(0));

    // Sender task.
    {
        let icmp_sock = icmp_sock.clone_handle();
        let codec = Arc::clone(&codec);
        let peer_ids = Arc::clone(&peer_ids);
        let icmp_seq = Arc::clone(&icmp_seq);
        let fec_cfg = fec_cfg;
        tokio::spawn(async move {
            let mut fec_enc = if fec_cfg.is_enabled() {
                match FecEncoder::new(fec_cfg) {
                    Ok(e) => Some(e),
                    Err(e) => {
                        tracing::error!(error = %e, "fec encoder init failed; disabling FEC");
                        None
                    }
                }
            } else {
                None
            };

            while let Some(out) = out_rx.recv().await {
                let bytes = match codec.encode(&out.frame) {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::warn!(error = %e, "encode failed");
                        continue;
                    }
                };
                let id = match peer_ids.lock().await.get(&out.dst) {
                    Some(p) => p.last_icmp_id.load(Ordering::Relaxed),
                    None => 0,
                };
                if let Some(enc) = fec_enc.as_mut() {
                    for shard in enc.submit(bytes) {
                        let wrapped = fec::wrap_shard(&shard, fec_cfg);
                        let seq = icmp_seq.fetch_add(1, Ordering::Relaxed);
                        if let Err(e) = icmp_sock
                            .send(out.dst, ICMP_ECHO_REPLY, id, seq, &wrapped)
                            .await
                        {
                            tracing::warn!(dst = %out.dst, error = %e, "icmp send failed");
                        }
                    }
                } else {
                    let seq = icmp_seq.fetch_add(1, Ordering::Relaxed);
                    if let Err(e) = icmp_sock
                        .send(out.dst, ICMP_ECHO_REPLY, id, seq, &bytes)
                        .await
                    {
                        tracing::warn!(dst = %out.dst, error = %e, "icmp send failed");
                    }
                }
            }
        });
    }

    let mut fec_dec = if fec_cfg.is_enabled() {
        Some(FecDecoder::new())
    } else {
        None
    };

    // Demux loop runs in the foreground.
    let mut buf = Vec::with_capacity(MAX_WIRE_SIZE);
    tracing::info!(bind = %args.bind, "server listening on ICMP");

    loop {
        let pkt = match icmp_sock.recv(&mut buf).await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "icmp recv failed");
                continue;
            }
        };
        // Server only accepts echo requests (client -> server).
        if pkt.icmp_type != ICMP_ECHO_REQUEST {
            continue;
        }
        // Update peer's known icmp_id.
        {
            let mut map = peer_ids.lock().await;
            let entry = map.entry(pkt.src).or_insert_with(|| {
                Arc::new(PeerState { last_icmp_id: AtomicU16::new(pkt.icmp_id) })
            });
            entry.last_icmp_id.store(pkt.icmp_id, Ordering::Relaxed);
        }

        let parsed = match fec::parse_outer(&buf) {
            Ok(p) => p,
            Err(e) => {
                tracing::trace!(error = %e, "parse_outer failed");
                continue;
            }
        };

        let mut frames: Vec<Frame> = Vec::new();
        match &parsed {
            fec::WireKind::Plain(bytes) => match codec.decode(bytes) {
                Ok(f) => frames.push(f),
                Err(e) => tracing::trace!(error = %e, "decode failed"),
            },
            fec::WireKind::Data { frame_bytes, .. } => {
                match codec.decode(frame_bytes) {
                    Ok(f) => frames.push(f),
                    Err(e) => tracing::trace!(error = %e, "decode failed"),
                }
                if let Some(d) = fec_dec.as_mut() {
                    for rec in d.submit(&parsed) {
                        match codec.decode(&rec) {
                            Ok(f) => {
                                tracing::debug!(conn = %format!("{:016x}", f.conn_id), seq = f.seq, "recovered via FEC");
                                frames.push(f);
                            }
                            Err(e) => tracing::trace!(error = %e, "decode recovered failed"),
                        }
                    }
                }
            }
            fec::WireKind::Parity { .. } => {
                if let Some(d) = fec_dec.as_mut() {
                    for rec in d.submit(&parsed) {
                        match codec.decode(&rec) {
                            Ok(f) => {
                                tracing::debug!(conn = %format!("{:016x}", f.conn_id), seq = f.seq, "recovered via FEC");
                                frames.push(f);
                            }
                            Err(e) => tracing::trace!(error = %e, "decode recovered failed"),
                        }
                    }
                }
            }
        }

        for frame in frames {
            dispatch_frame(
                frame,
                pkt.src,
                &conns,
                &out_tx,
                &cfg,
                args.max_conns,
                args.dial_timeout_ms,
            )
            .await;
        }
    }
}

async fn dispatch_frame(
    frame: Frame,
    peer: Ipv4Addr,
    conns: &Arc<Mutex<HashMap<u64, (Ipv4Addr, mpsc::Sender<Frame>)>>>,
    out_tx: &mpsc::Sender<Outbound>,
    cfg: &ConnConfig,
    max_conns: usize,
    dial_timeout_ms: u64,
) {
    let existing = conns.lock().await.get(&frame.conn_id).map(|(_, tx)| tx.clone());
    if let Some(tx) = existing {
        let _ = tx.send(frame).await;
        return;
    }
    if frame.op != Op::Syn {
        tracing::debug!(conn = %format!("{:016x}", frame.conn_id), op = ?frame.op, "non-syn for unknown conn (ignored)");
        return;
    }
    if max_conns > 0 {
        let live = conns.lock().await.len();
        if live >= max_conns {
            tracing::warn!(live, "max_conns reached, refusing SYN");
            return;
        }
    }
    let target = match std::str::from_utf8(&frame.payload) {
        Ok(s) => s.to_string(),
        Err(_) => {
            tracing::warn!("SYN payload not UTF-8");
            return;
        }
    };
    tracing::info!(
        conn = %format!("{:016x}", frame.conn_id),
        peer = %peer,
        target = %target,
        "SYN"
    );

    let dial_to = Duration::from_millis(dial_timeout_ms);
    let conn_id = frame.conn_id;
    let conns2 = Arc::clone(conns);
    let out_tx2 = out_tx.clone();
    let cfg2 = cfg.clone();
    let initial_frame = frame;

    tokio::spawn(async move {
        let stream = match timeout(dial_to, TcpStream::connect(&target)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                tracing::info!(
                    conn = %format!("{:016x}", conn_id),
                    target = %target,
                    error = %e,
                    "dial failed"
                );
                let _ = out_tx2
                    .send(Outbound {
                        dst: peer,
                        frame: Frame::control(Op::Rst, conn_id),
                    })
                    .await;
                return;
            }
            Err(_) => {
                tracing::info!(
                    conn = %format!("{:016x}", conn_id),
                    target = %target,
                    "dial timed out"
                );
                let _ = out_tx2
                    .send(Outbound {
                        dst: peer,
                        frame: Frame::control(Op::Rst, conn_id),
                    })
                    .await;
                return;
            }
        };

        let (in_tx, in_rx) = mpsc::channel::<Frame>(256);
        conns2.lock().await.insert(conn_id, (peer, in_tx.clone()));
        let _ = in_tx.send(initial_frame).await;

        let drive_res = conn::drive(
            conn_id,
            peer,
            stream,
            in_rx,
            out_tx2,
            cfg2,
            Bootstrap::ServerAccepted,
        )
        .await;
        if let Err(e) = drive_res {
            tracing::debug!(conn = %format!("{:016x}", conn_id), error = %e, "drive ended");
        }
        conns2.lock().await.remove(&conn_id);
        tracing::info!(conn = %format!("{:016x}", conn_id), "closed");
    });
}

#[allow(dead_code)]
fn _force_use() {
    let _ = Op::Ack;
}
