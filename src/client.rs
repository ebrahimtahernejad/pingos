//! Client side: listens on a local TCP port and tunnels each accepted
//! connection to the server through ICMP.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use rand::Rng;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};

use crate::cli::ClientArgs;
use crate::conn::{self, Bootstrap, ConnConfig, Outbound, Side};
use crate::fec::{self, FecDecoder, FecEncoder};
use crate::icmp::{self, IcmpSocket, ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST};
use crate::proto::{FecConfig, Frame, Op, MAX_WIRE_SIZE};
use crate::wire::Codec;

fn pingos_fec_cfg(t: (u8, u8)) -> FecConfig {
    FecConfig {
        data_shards: t.0,
        parity_shards: t.1,
    }
}

pub async fn run(args: ClientArgs) -> Result<()> {
    let listen = args
        .listen
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("missing --listen (CLI or `client.listen` in config)"))?;
    let server = args
        .server
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("missing --server (CLI or `client.server` in config)"))?;
    let target = args
        .target
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("missing --target (CLI or `client.target` in config)"))?;

    let server_ip = icmp::resolve_v4(server)
        .with_context(|| format!("could not resolve server {}", server))?;
    tracing::info!(server = %server, ip = %server_ip, "resolved server");

    let icmp_sock = IcmpSocket::bind("0.0.0.0")?;
    let codec = Arc::new(Codec::new(&args.password, args.compression, Side::Client));
    if codec.is_encrypted() {
        tracing::info!("encryption: ChaCha20-Poly1305 (password-derived)");
    } else {
        tracing::warn!("encryption: DISABLED (no password set)");
    }
    tracing::info!("compression: {:?}", args.compression);
    let fec_cfg = pingos_fec_cfg(args.fec);
    if fec_cfg.is_enabled() {
        tracing::info!(
            "FEC: {}:{} (Reed-Solomon)",
            fec_cfg.data_shards,
            fec_cfg.parity_shards
        );
    }

    let cfg = ConnConfig {
        idle_timeout: Duration::from_secs(args.idle_timeout_secs),
        side: Side::Client,
    };

    // Random 16-bit ICMP identifier for our outgoing echo requests. NAT-stable.
    let icmp_id: u16 = rand::thread_rng().gen();
    // Monotonic ICMP sequence (just for completeness; receivers ignore it).
    let icmp_seq = Arc::new(std::sync::atomic::AtomicU16::new(0));

    // Map: conn_id -> per-connection inbound channel sender.
    let conns: Arc<Mutex<HashMap<u64, mpsc::Sender<Frame>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Outbound frame queue: every Conn task pushes here; one sender task drains.
    let (out_tx, mut out_rx) = mpsc::channel::<Outbound>(4096);

    // Spawn the sender task.
    {
        let icmp_sock = icmp_sock.clone_handle();
        let codec = Arc::clone(&codec);
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
                if let Some(enc) = fec_enc.as_mut() {
                    for shard in enc.submit(bytes) {
                        let wrapped = fec::wrap_shard(&shard, fec_cfg);
                        let seq = icmp_seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if let Err(e) = icmp_sock
                            .send(out.dst, ICMP_ECHO_REQUEST, icmp_id, seq, &wrapped)
                            .await
                        {
                            tracing::warn!(dst = %out.dst, error = %e, "icmp send failed");
                        }
                    }
                } else {
                    let seq = icmp_seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if let Err(e) = icmp_sock
                        .send(out.dst, ICMP_ECHO_REQUEST, icmp_id, seq, &bytes)
                        .await
                    {
                        tracing::warn!(dst = %out.dst, error = %e, "icmp send failed");
                    }
                }
            }
        });
    }

    // Spawn the demux task — reads ICMP, dispatches to the right Conn.
    {
        let icmp_sock = icmp_sock.clone_handle();
        let codec = Arc::clone(&codec);
        let conns = Arc::clone(&conns);
        let fec_cfg = fec_cfg;
        tokio::spawn(async move {
            let mut fec_dec = if fec_cfg.is_enabled() {
                Some(FecDecoder::new())
            } else {
                None
            };
            let mut buf = Vec::with_capacity(MAX_WIRE_SIZE);
            loop {
                let pkt = match icmp_sock.recv(&mut buf).await {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!(error = %e, "icmp recv failed");
                        continue;
                    }
                };
                if pkt.src != server_ip {
                    continue;
                }
                if pkt.icmp_type != ICMP_ECHO_REPLY {
                    continue;
                }

                let parsed = match fec::parse_outer(&buf) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::trace!(error = %e, "parse_outer failed");
                        continue;
                    }
                };

                // Frames to dispatch this round.
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

                if frames.is_empty() {
                    continue;
                }
                let map = conns.lock().await;
                for frame in frames {
                    if let Some(tx) = map.get(&frame.conn_id) {
                        let _ = tx.send(frame).await;
                    } else {
                        tracing::debug!(conn = %format!("{:016x}", frame.conn_id), op = ?frame.op, "frame for unknown conn (likely closed)");
                    }
                }
            }
        });
    }

    // Accept loop.
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("bind {}", listen))?;
    tracing::info!(listen = %listen, target = %target, "client listening");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                continue;
            }
        };

        if args.max_conns > 0 {
            let live = conns.lock().await.len();
            if live >= args.max_conns {
                tracing::warn!(live, "max_conns reached, refusing new TCP");
                drop(stream);
                continue;
            }
        }

        let conn_id: u64 = rand::thread_rng().gen();
        tracing::info!(conn = %format!("{:016x}", conn_id), peer = %peer, "accept");

        let (in_tx, in_rx) = mpsc::channel::<Frame>(256);
        conns.lock().await.insert(conn_id, in_tx);

        spawn_conn(
            conn_id,
            server_ip,
            stream,
            in_rx,
            out_tx.clone(),
            cfg.clone(),
            Bootstrap::ClientSyn { target: target.to_string() },
            Arc::clone(&conns),
        );
    }
}

fn spawn_conn(
    conn_id: u64,
    dst: Ipv4Addr,
    stream: TcpStream,
    in_rx: mpsc::Receiver<Frame>,
    out_tx: mpsc::Sender<Outbound>,
    cfg: ConnConfig,
    bootstrap: Bootstrap,
    conns: Arc<Mutex<HashMap<u64, mpsc::Sender<Frame>>>>,
) {
    tokio::spawn(async move {
        let _ = conn::drive(conn_id, dst, stream, in_rx, out_tx, cfg, bootstrap).await;
        conns.lock().await.remove(&conn_id);
        tracing::info!(conn = %format!("{:016x}", conn_id), "closed");
    });
}

// Quiet some "unused" warnings if the file is re-evaluated.
#[allow(dead_code)]
fn _force_use() {
    let _ = Op::Data;
}
