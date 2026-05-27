//! End-to-end test of the reliable channel + tunnel logic, without ICMP.
//!
//! We wire two `conn::drive()` instances together via mpsc channels (one per
//! direction). One side acts as client, the other as server, with a real TCP
//! echo server backing the server-side TCP stream and a real TCP client
//! talking to a local listener that feeds the client-side stream.
//!
//! Run with: `cargo test --test integration -- --nocapture`

use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use pingos::conn::{self, Bootstrap, ConnConfig, Outbound, Side};
use pingos::fec::{self, FecDecoder, FecEncoder};
use pingos::proto::{Compression, FecConfig, Frame, Op};
use pingos::wire::Codec;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

async fn spawn_echo() -> Result<std::net::SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let (mut s, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    Ok(addr)
}

/// Bridge `Outbound` → `Frame` (the relay throws away dst since the test wires
/// a single client↔server pair). Apply an optional drop predicate to simulate loss.
async fn relay<F>(
    mut out_rx: mpsc::Receiver<Outbound>,
    in_tx: mpsc::Sender<Frame>,
    mut drop_filter: F,
) where
    F: FnMut(&Frame) -> bool + Send + 'static,
{
    while let Some(o) = out_rx.recv().await {
        if drop_filter(&o.frame) {
            continue;
        }
        if in_tx.send(o.frame).await.is_err() {
            break;
        }
    }
}

async fn run_pair(
    local_stream: TcpStream,
    target: String,
    drop_client_to_server: impl FnMut(&Frame) -> bool + Send + 'static,
    drop_server_to_client: impl FnMut(&Frame) -> bool + Send + 'static,
) -> Result<()> {
    let (client_out_tx, client_out_rx) = mpsc::channel::<Outbound>(256);
    let (server_out_tx, server_out_rx) = mpsc::channel::<Outbound>(256);
    let (client_in_tx, client_in_rx) = mpsc::channel::<Frame>(256);
    let (server_in_tx, server_in_rx) = mpsc::channel::<Frame>(256);

    // Relays
    tokio::spawn(relay(client_out_rx, server_in_tx, drop_client_to_server));
    tokio::spawn(relay(server_out_rx, client_in_tx, drop_server_to_client));

    let conn_id: u64 = 0xDEAD_BEEF_CAFE_F00D;
    let any_ip: Ipv4Addr = "0.0.0.0".parse().unwrap();

    // Server side: dial target now (in the real server this happens after SYN).
    let server_stream = TcpStream::connect(&target).await?;
    let server_cfg = ConnConfig {
        idle_timeout: Duration::from_secs(10),
        side: Side::Server,
    };
    tokio::spawn(async move {
        let _ = conn::drive(
            conn_id,
            any_ip,
            server_stream,
            server_in_rx,
            server_out_tx,
            server_cfg,
            Bootstrap::ServerAccepted,
        )
        .await;
    });

    // Client side
    let client_cfg = ConnConfig {
        idle_timeout: Duration::from_secs(10),
        side: Side::Client,
    };
    tokio::spawn(async move {
        let _ = conn::drive(
            conn_id,
            any_ip,
            local_stream,
            client_in_rx,
            client_out_tx,
            client_cfg,
            Bootstrap::ClientSyn { target },
        )
        .await;
    });

    Ok(())
}

#[tokio::test]
async fn tunnel_echoes_small_payload() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .try_init();

    let echo_addr = spawn_echo().await?;
    let local_listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_addr = local_listener.local_addr()?;

    // When tester connects, we hand the accepted stream to the client drive.
    let accept_task = tokio::spawn(async move {
        let (stream, _) = local_listener.accept().await.unwrap();
        stream
    });

    let mut tester = TcpStream::connect(local_addr).await?;
    let client_stream = accept_task.await?;

    run_pair(
        client_stream,
        echo_addr.to_string(),
        |_| false,
        |_| false,
    )
    .await?;

    // Send a small payload and expect it echoed back.
    let payload = b"hello pingos!\n";
    tester.write_all(payload).await?;

    let mut buf = vec![0u8; payload.len()];
    let res = tokio::time::timeout(Duration::from_secs(5), async {
        tester.read_exact(&mut buf).await
    })
    .await;
    res.expect("timeout waiting for echo")?;
    assert_eq!(buf.as_slice(), payload);

    Ok(())
}

#[tokio::test]
async fn tunnel_handles_large_payload() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .try_init();

    let echo_addr = spawn_echo().await?;
    let local_listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_addr = local_listener.local_addr()?;

    let accept_task = tokio::spawn(async move {
        let (stream, _) = local_listener.accept().await.unwrap();
        stream
    });

    let mut tester = TcpStream::connect(local_addr).await?;
    let client_stream = accept_task.await?;

    run_pair(client_stream, echo_addr.to_string(), |_| false, |_| false).await?;

    // 64 KiB blob.
    let mut payload = vec![0u8; 64 * 1024];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }

    let (mut r, mut w) = tester.split();
    let write_fut = async {
        w.write_all(&payload).await?;
        anyhow::Ok(())
    };
    let read_fut = async {
        let mut got = vec![0u8; payload.len()];
        r.read_exact(&mut got).await?;
        anyhow::Ok(got)
    };

    let (_, got) = tokio::time::timeout(Duration::from_secs(20), async {
        tokio::try_join!(write_fut, read_fut)
    })
    .await
    .expect("timeout")?;

    assert_eq!(got, payload);
    Ok(())
}

/// Drive a pair through codec.encode → FecEncoder → loss → FecDecoder → codec.decode,
/// to exercise the actual production-pipeline (the other end-to-end tests bypass
/// the codec entirely and only verify the conn-level reliability).
async fn run_pair_codec_fec(
    local_stream: TcpStream,
    target: String,
    fec_cfg: FecConfig,
    compression: Compression,
    password: &str,
    mut drop_c2s: impl FnMut(usize) -> bool + Send + 'static,
    mut drop_s2c: impl FnMut(usize) -> bool + Send + 'static,
) -> Result<()> {
    // Two encoder/decoder pairs (one per direction).
    let codec_c = Codec::new(password, compression, Side::Client);
    let codec_s = Codec::new(password, compression, Side::Server);

    let (client_out_tx, mut client_out_rx) = mpsc::channel::<Outbound>(256);
    let (server_out_tx, mut server_out_rx) = mpsc::channel::<Outbound>(256);
    let (client_in_tx, client_in_rx) = mpsc::channel::<Frame>(256);
    let (server_in_tx, server_in_rx) = mpsc::channel::<Frame>(256);

    // C->S pipeline: codec_c.encode → fec_enc → drop_c2s → fec_dec/codec_s.decode → server_in_tx
    {
        let codec_c = codec_c.clone();
        let codec_s = codec_s.clone();
        tokio::spawn(async move {
            let mut enc = if fec_cfg.is_enabled() {
                Some(FecEncoder::new(fec_cfg).unwrap())
            } else {
                None
            };
            let mut dec = if fec_cfg.is_enabled() {
                Some(FecDecoder::new())
            } else {
                None
            };
            let mut idx = 0usize;
            while let Some(o) = client_out_rx.recv().await {
                let bytes = codec_c.encode(&o.frame).unwrap();
                let packets: Vec<Bytes> = if let Some(e) = enc.as_mut() {
                    e.submit(bytes)
                        .iter()
                        .map(|s| fec::wrap_shard(s, fec_cfg))
                        .collect()
                } else {
                    vec![bytes]
                };
                for pkt in packets {
                    idx += 1;
                    if drop_c2s(idx) {
                        continue;
                    }
                    let parsed = fec::parse_outer(&pkt).unwrap();
                    let mut to_send = Vec::new();
                    match &parsed {
                        fec::WireKind::Plain(b) => {
                            if let Ok(f) = codec_s.decode(b) {
                                to_send.push(f);
                            }
                        }
                        fec::WireKind::Data { frame_bytes, .. } => {
                            if let Ok(f) = codec_s.decode(frame_bytes) {
                                to_send.push(f);
                            }
                            if let Some(d) = dec.as_mut() {
                                for rec in d.submit(&parsed) {
                                    if let Ok(f) = codec_s.decode(&rec) {
                                        to_send.push(f);
                                    }
                                }
                            }
                        }
                        fec::WireKind::Parity { .. } => {
                            if let Some(d) = dec.as_mut() {
                                for rec in d.submit(&parsed) {
                                    if let Ok(f) = codec_s.decode(&rec) {
                                        to_send.push(f);
                                    }
                                }
                            }
                        }
                    }
                    for f in to_send {
                        if server_in_tx.send(f).await.is_err() {
                            return;
                        }
                    }
                }
            }
        });
    }

    // S->C mirror pipeline.
    {
        let codec_c = codec_c.clone();
        let codec_s = codec_s.clone();
        tokio::spawn(async move {
            let mut enc = if fec_cfg.is_enabled() {
                Some(FecEncoder::new(fec_cfg).unwrap())
            } else {
                None
            };
            let mut dec = if fec_cfg.is_enabled() {
                Some(FecDecoder::new())
            } else {
                None
            };
            let mut idx = 0usize;
            while let Some(o) = server_out_rx.recv().await {
                let bytes = codec_s.encode(&o.frame).unwrap();
                let packets: Vec<Bytes> = if let Some(e) = enc.as_mut() {
                    e.submit(bytes)
                        .iter()
                        .map(|s| fec::wrap_shard(s, fec_cfg))
                        .collect()
                } else {
                    vec![bytes]
                };
                for pkt in packets {
                    idx += 1;
                    if drop_s2c(idx) {
                        continue;
                    }
                    let parsed = fec::parse_outer(&pkt).unwrap();
                    let mut to_send = Vec::new();
                    match &parsed {
                        fec::WireKind::Plain(b) => {
                            if let Ok(f) = codec_c.decode(b) {
                                to_send.push(f);
                            }
                        }
                        fec::WireKind::Data { frame_bytes, .. } => {
                            if let Ok(f) = codec_c.decode(frame_bytes) {
                                to_send.push(f);
                            }
                            if let Some(d) = dec.as_mut() {
                                for rec in d.submit(&parsed) {
                                    if let Ok(f) = codec_c.decode(&rec) {
                                        to_send.push(f);
                                    }
                                }
                            }
                        }
                        fec::WireKind::Parity { .. } => {
                            if let Some(d) = dec.as_mut() {
                                for rec in d.submit(&parsed) {
                                    if let Ok(f) = codec_c.decode(&rec) {
                                        to_send.push(f);
                                    }
                                }
                            }
                        }
                    }
                    for f in to_send {
                        if client_in_tx.send(f).await.is_err() {
                            return;
                        }
                    }
                }
            }
        });
    }

    let conn_id: u64 = 0xCAFE_BABE_DEAD_BEEF;
    let any_ip: Ipv4Addr = "0.0.0.0".parse().unwrap();
    let server_stream = TcpStream::connect(&target).await?;
    let server_cfg = ConnConfig {
        idle_timeout: Duration::from_secs(20),
        side: Side::Server,
    };
    tokio::spawn(async move {
        let _ = conn::drive(
            conn_id,
            any_ip,
            server_stream,
            server_in_rx,
            server_out_tx,
            server_cfg,
            Bootstrap::ServerAccepted,
        )
        .await;
    });
    let client_cfg = ConnConfig {
        idle_timeout: Duration::from_secs(20),
        side: Side::Client,
    };
    tokio::spawn(async move {
        let _ = conn::drive(
            conn_id,
            any_ip,
            local_stream,
            client_in_rx,
            client_out_tx,
            client_cfg,
            Bootstrap::ClientSyn { target },
        )
        .await;
    });
    Ok(())
}

#[tokio::test]
async fn end_to_end_with_codec_fec_compression_and_loss() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .try_init();

    let echo_addr = spawn_echo().await?;
    let local_listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_addr = local_listener.local_addr()?;

    let accept_task = tokio::spawn(async move {
        let (stream, _) = local_listener.accept().await.unwrap();
        stream
    });

    let mut tester = TcpStream::connect(local_addr).await?;
    let client_stream = accept_task.await?;

    let fec_cfg = FecConfig {
        data_shards: 8,
        parity_shards: 3,
    };

    // Drop ~15% in each direction, skipping the first few to let handshake through.
    run_pair_codec_fec(
        client_stream,
        echo_addr.to_string(),
        fec_cfg,
        Compression::Lz4,
        "test-secret",
        {
            let mut n: usize = 0;
            move |_| {
                n += 1;
                n > 4 && n % 7 == 0
            }
        },
        {
            let mut n: usize = 0;
            move |_| {
                n += 1;
                n > 4 && n % 7 == 0
            }
        },
    )
    .await?;

    // Compressible payload (repeating-ish pattern).
    let mut payload = vec![0u8; 32 * 1024];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (i % 64) as u8;
    }

    let (mut r, mut w) = tester.split();
    let write_fut = async {
        w.write_all(&payload).await?;
        anyhow::Ok(())
    };
    let read_fut = async {
        let mut got = vec![0u8; payload.len()];
        r.read_exact(&mut got).await?;
        anyhow::Ok(got)
    };
    let (_, got) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::try_join!(write_fut, read_fut)
    })
    .await
    .expect("timeout")?;

    assert_eq!(got, payload);
    Ok(())
}

// Quiet "unused" for Op when fec/compression imports change.
#[allow(dead_code)]
fn _force() {
    let _ = Op::Ack;
}

#[tokio::test]
async fn tunnel_recovers_from_packet_loss() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .try_init();

    let echo_addr = spawn_echo().await?;
    let local_listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_addr = local_listener.local_addr()?;

    let accept_task = tokio::spawn(async move {
        let (stream, _) = local_listener.accept().await.unwrap();
        stream
    });

    let mut tester = TcpStream::connect(local_addr).await?;
    let client_stream = accept_task.await?;

    // Drop every 4th frame in each direction (after the first 2, so SYN/SynAck still get through).
    let mut c2s_count: u64 = 0;
    let mut s2c_count: u64 = 0;
    run_pair(
        client_stream,
        echo_addr.to_string(),
        move |_| {
            c2s_count += 1;
            c2s_count > 2 && c2s_count % 4 == 0
        },
        move |_| {
            s2c_count += 1;
            s2c_count > 2 && s2c_count % 4 == 0
        },
    )
    .await?;

    let mut payload = vec![0u8; 16 * 1024];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = ((i * 7) % 251) as u8;
    }

    let (mut r, mut w) = tester.split();
    let write_fut = async {
        w.write_all(&payload).await?;
        anyhow::Ok(())
    };
    let read_fut = async {
        let mut got = vec![0u8; payload.len()];
        r.read_exact(&mut got).await?;
        anyhow::Ok(got)
    };

    let (_, got) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::try_join!(write_fut, read_fut)
    })
    .await
    .expect("timeout")?;

    assert_eq!(got, payload);
    Ok(())
}
