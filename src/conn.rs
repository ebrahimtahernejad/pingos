//! Per-connection reliable channel running on top of unreliable ICMP frames.
//!
//! Each side runs an event-driven loop with `tokio::select!` — no polling,
//! no fixed sleeps. The select waits on (at most) four things at once:
//!
//!   - inbound frame from the demux mpsc
//!   - TCP socket readable  (only when our send window has room)
//!   - TCP socket writable  (only when we have bytes ready to deliver)
//!   - the next timer tick  (RTO, ack-delay, keepalive)
//!
//! Reliability model:
//!   - Every frame other than `Ack` carries a per-side monotonic `seq`.
//!   - Peer's `ack` field is cumulative: "I have everything through seq N".
//!   - Sender keeps unacked frames in a small in-flight deque, retransmits the
//!     oldest on RTO with exponential backoff (capped).
//!   - Receiver buffers out-of-order frames in a BTreeMap, delivers in order.
//!   - Delayed-ACK: after receiving DATA, hold the ack briefly so it can
//!     piggyback on a return frame; if nothing returns within ACK_DELAY, send
//!     a standalone Ack frame.

use std::collections::{BTreeMap, VecDeque};
use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::Result;
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{sleep_until, Instant};

use crate::proto::{Frame, Op, MAX_DATA_PAYLOAD};

// ---- tuning ----------------------------------------------------------------

const MAX_INFLIGHT: usize = 128;
const MAX_DELIVER_BUF: usize = 1 << 20; // 1 MiB per-connection receive buffer
const INITIAL_RTO: Duration = Duration::from_millis(400);
const MIN_RTO: Duration = Duration::from_millis(80);
const MAX_RTO: Duration = Duration::from_secs(5);
const ACK_DELAY: Duration = Duration::from_millis(20);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const GIVE_UP_AFTER: Duration = Duration::from_secs(45); // per-frame max retransmit lifetime

// ---- public types ----------------------------------------------------------

/// What the role of this side is in the conn-id ownership / dst routing.
#[derive(Debug, Clone, Copy)]
pub enum Side {
    /// Client: known fixed peer IP, sends ICMP echo request.
    Client,
    /// Server: peer IP determined at handshake; sends ICMP echo reply.
    Server,
}

/// Frame produced by a Conn for the central sender task to emit.
#[derive(Debug)]
pub struct Outbound {
    pub dst: Ipv4Addr,
    pub frame: Frame,
}

/// Configuration shared by every Conn instance.
#[derive(Clone)]
pub struct ConnConfig {
    pub idle_timeout: Duration,
    #[allow(dead_code)]
    pub side: Side,
}

// ---- per-direction state ---------------------------------------------------

#[derive(Debug)]
struct Unacked {
    seq: u32,
    op: Op,
    payload: Bytes,
    queued_at: Instant,
    last_sent: Instant,
    sent_once: bool,
    retries: u32,
}

struct SendState {
    next_seq: u32,
    inflight: VecDeque<Unacked>,
    rto: Duration,
    srtt: Option<Duration>,
    rttvar: Duration,
    fin_seq: Option<u32>,    // seq of our FIN, once sent
    fin_acked: bool,
}

struct RecvState {
    rcv_next: u32,
    out_of_order: BTreeMap<u32, (Op, Bytes)>,
    deliver_buf: BytesMut,
    pending_ack_since: Option<Instant>,
    immediate_ack: bool,
    peer_fin_consumed: bool,
}

impl SendState {
    fn new() -> Self {
        SendState {
            next_seq: 1,
            inflight: VecDeque::new(),
            rto: INITIAL_RTO,
            srtt: None,
            rttvar: Duration::from_millis(0),
            fin_seq: None,
            fin_acked: false,
        }
    }

    fn window_full(&self) -> bool {
        self.inflight.len() >= MAX_INFLIGHT
    }

    fn on_ack(&mut self, ack: u32, now: Instant) {
        loop {
            let Some(front) = self.inflight.front() else { break };
            if front.seq > ack {
                break;
            }
            let rtt_sample = if front.retries == 0 && front.sent_once {
                Some(now.saturating_duration_since(front.last_sent))
            } else {
                None
            };
            let seq = front.seq;
            self.inflight.pop_front();
            if let Some(fseq) = self.fin_seq {
                if seq == fseq {
                    self.fin_acked = true;
                }
            }
            if let Some(sample) = rtt_sample {
                self.update_rtt(sample);
            }
        }
    }

    fn update_rtt(&mut self, sample: Duration) {
        // Jacobson/Karels.
        match self.srtt {
            None => {
                self.srtt = Some(sample);
                self.rttvar = sample / 2;
            }
            Some(srtt) => {
                let err = if sample > srtt { sample - srtt } else { srtt - sample };
                // rttvar = 0.75*rttvar + 0.25*err
                self.rttvar = (self.rttvar * 3 + err) / 4;
                // srtt = 0.875*srtt + 0.125*sample
                self.srtt = Some((srtt * 7 + sample) / 8);
            }
        }
        let new_rto = self.srtt.unwrap() + self.rttvar * 4;
        self.rto = new_rto.clamp(MIN_RTO, MAX_RTO);
    }

    /// When should the RTO-driven retransmit fire? `None` if no in-flight,
    /// or if the oldest hasn't been emitted yet (will be emitted immediately).
    fn next_rto_deadline(&self) -> Option<Instant> {
        let oldest = self.inflight.front()?;
        if !oldest.sent_once {
            return None;
        }
        Some(oldest.last_sent + self.rto)
    }
}

impl RecvState {
    fn new() -> Self {
        RecvState {
            rcv_next: 1,
            out_of_order: BTreeMap::new(),
            deliver_buf: BytesMut::new(),
            pending_ack_since: None,
            immediate_ack: false,
            peer_fin_consumed: false,
        }
    }

    fn ack(&self) -> u32 {
        self.rcv_next.saturating_sub(1)
    }

    fn window_frames(&self) -> u16 {
        let used = self.deliver_buf.len();
        if used >= MAX_DELIVER_BUF {
            return 0;
        }
        let free = MAX_DELIVER_BUF - used;
        ((free + MAX_DATA_PAYLOAD - 1) / MAX_DATA_PAYLOAD).min(u16::MAX as usize) as u16
    }
}

// ---- conn driver -----------------------------------------------------------

/// Drives a single tunneled TCP connection from start to teardown.
///
/// The `bootstrap` argument controls handshake behavior:
///   - On the client, pass `Bootstrap::ClientSyn { target }` — the driver will
///     emit a Syn and wait for SynAck before pumping the local TCP stream.
///   - On the server, pass `Bootstrap::ServerAccepted` — the driver assumes
///     the SYN was already consumed by the caller and sends a SynAck.
pub enum Bootstrap {
    ClientSyn { target: String },
    ServerAccepted,
}

pub async fn drive(
    conn_id: u64,
    dst: Ipv4Addr,
    mut tcp: TcpStream,
    mut rx_frames: mpsc::Receiver<Frame>,
    tx_frames: mpsc::Sender<Outbound>,
    cfg: ConnConfig,
    bootstrap: Bootstrap,
) -> Result<()> {
    let mut send = SendState::new();
    let mut recv = RecvState::new();
    let mut closing = false; // we've decided to send FIN (after local read EOF / error)
    let mut peer_rst = false;
    let mut last_activity = Instant::now();
    let mut next_keepalive = Instant::now() + KEEPALIVE_INTERVAL;

    // Emit initial handshake frame.
    match &bootstrap {
        Bootstrap::ClientSyn { target } => {
            queue(&mut send, Op::Syn, Bytes::copy_from_slice(target.as_bytes()));
        }
        Bootstrap::ServerAccepted => {
            queue(&mut send, Op::SynAck, Bytes::new());
        }
    }

    let established_role = matches!(bootstrap, Bootstrap::ServerAccepted);
    let mut established = established_role;

    let (mut tcp_r, mut tcp_w) = tcp.split();
    let mut read_buf = vec![0u8; MAX_DATA_PAYLOAD];

    // Initial emit pass.
    emit_all(&mut send, &mut recv, &tx_frames, conn_id, dst, &cfg).await;

    loop {
        // Termination conditions.
        if peer_rst {
            break;
        }
        if closing && send.fin_acked && recv.peer_fin_consumed && recv.deliver_buf.is_empty() {
            break;
        }
        if last_activity.elapsed() > cfg.idle_timeout {
            tracing::info!(conn = %fmt_conn(conn_id), "idle timeout");
            send_rst(&tx_frames, conn_id, dst, &cfg).await;
            break;
        }
        // Drop frames stuck in retransmit longer than GIVE_UP_AFTER (peer gone).
        if let Some(front) = send.inflight.front() {
            if front.sent_once && front.queued_at.elapsed() > GIVE_UP_AFTER {
                tracing::info!(conn = %fmt_conn(conn_id), "peer unresponsive, giving up");
                send_rst(&tx_frames, conn_id, dst, &cfg).await;
                break;
            }
        }

        // Decide what we can wait on.
        let want_read = established && !closing && !send.window_full();
        let want_write = !recv.deliver_buf.is_empty();

        // Compute next wakeup deadline.
        let mut next_deadline: Option<Instant> = None;
        if let Some(d) = send.next_rto_deadline() {
            next_deadline = Some(min_inst(next_deadline, d));
        }
        if let Some(t) = recv.pending_ack_since {
            next_deadline = Some(min_inst(next_deadline, t + ACK_DELAY));
        }
        next_deadline = Some(min_inst(next_deadline, next_keepalive));

        let sleep_to = next_deadline.unwrap_or_else(|| Instant::now() + Duration::from_secs(60));

        tokio::select! {
            biased;

            // Inbound frame from the demux.
            maybe_frame = rx_frames.recv() => {
                match maybe_frame {
                    Some(frame) => {
                        last_activity = Instant::now();
                        handle_inbound(
                            frame,
                            &mut send,
                            &mut recv,
                            &mut established,
                            &mut peer_rst,
                            &mut closing,
                        );
                    }
                    None => {
                        // demux dropped — tunnel down.
                        break;
                    }
                }
            }

            // RTO / ack-delay / keepalive.
            _ = sleep_until(sleep_to) => {
                let now = Instant::now();
                // RTO?
                if let Some(rto_at) = send.next_rto_deadline() {
                    if now >= rto_at {
                        retransmit_oldest(&mut send, &tx_frames, conn_id, dst, &cfg, &recv).await;
                    }
                }
                // delayed ack?
                if let Some(since) = recv.pending_ack_since {
                    if now >= since + ACK_DELAY {
                        send_standalone_ack(&recv, &tx_frames, conn_id, dst, &cfg).await;
                        recv.pending_ack_since = None;
                    }
                }
                // keepalive?
                if now >= next_keepalive {
                    if established && send.inflight.is_empty() && recv.deliver_buf.is_empty() {
                        // Send a Ping just to keep NAT alive and let the other
                        // side notice we're around.
                        send_ping(&tx_frames, conn_id, dst, &cfg).await;
                    }
                    next_keepalive = now + KEEPALIVE_INTERVAL;
                }
            }

            // Local TCP → tunnel.
            res = tcp_r.read(&mut read_buf), if want_read => {
                match res {
                    Ok(0) => {
                        // Local closed. Send FIN once we've finished queueing.
                        closing = true;
                        if send.fin_seq.is_none() {
                            send.fin_seq = Some(send.next_seq);
                            queue(&mut send, Op::Fin, Bytes::new());
                        }
                    }
                    Ok(n) => {
                        // Segment into DATA frames.
                        let mut remaining = &read_buf[..n];
                        while !remaining.is_empty() {
                            if send.window_full() { break; /* shouldn't happen due to want_read guard */ }
                            let take = remaining.len().min(MAX_DATA_PAYLOAD);
                            let payload = Bytes::copy_from_slice(&remaining[..take]);
                            queue(&mut send, Op::Data, payload);
                            remaining = &remaining[take..];
                        }
                        last_activity = Instant::now();
                    }
                    Err(e) => {
                        tracing::debug!(conn = %fmt_conn(conn_id), error = %e, "tcp read error");
                        closing = true;
                        if send.fin_seq.is_none() {
                            send.fin_seq = Some(send.next_seq);
                            queue(&mut send, Op::Fin, Bytes::new());
                        }
                    }
                }
            }

            // Tunnel → local TCP.
            res = tcp_w.write(&recv.deliver_buf), if want_write => {
                match res {
                    Ok(0) | Err(_) => {
                        tracing::debug!(conn = %fmt_conn(conn_id), "tcp write closed");
                        closing = true;
                        if send.fin_seq.is_none() {
                            send.fin_seq = Some(send.next_seq);
                            queue(&mut send, Op::Fin, Bytes::new());
                        }
                    }
                    Ok(n) => {
                        let _ = recv.deliver_buf.split_to(n);
                        last_activity = Instant::now();
                    }
                }
            }
        }

        // After any event, push everything that's emittable.
        emit_all(&mut send, &mut recv, &tx_frames, conn_id, dst, &cfg).await;
    }

    let _ = tcp_w.shutdown().await;
    Ok(())
}

// ---- helpers ---------------------------------------------------------------

fn queue(send: &mut SendState, op: Op, payload: Bytes) {
    let seq = send.next_seq;
    send.next_seq = send.next_seq.wrapping_add(1);
    let now = Instant::now();
    send.inflight.push_back(Unacked {
        seq,
        op,
        payload,
        queued_at: now,
        last_sent: now,
        sent_once: false,
        retries: 0,
    });
}

fn handle_inbound(
    frame: Frame,
    send: &mut SendState,
    recv: &mut RecvState,
    established: &mut bool,
    peer_rst: &mut bool,
    closing: &mut bool,
) {
    let now = Instant::now();

    // Always process the ack field.
    if frame.ack > 0 {
        send.on_ack(frame.ack, now);
    }

    match frame.op {
        Op::Ack | Op::Ping | Op::Pong => {
            // Nothing further. Ping triggers a Pong below.
            if frame.op == Op::Ping {
                // Send a Pong out-of-band: we queue it as a control frame.
                // We piggyback by queueing as a 0-seq ACK-like frame; but to keep
                // it simple we just emit a Pong via the normal queue (with seq).
                // Actually Pong doesn't need reliability — emit directly via ack
                // path. For simplicity, do nothing here; ACKs already keep the
                // path warm.
            }
        }
        Op::Rst => {
            *peer_rst = true;
        }
        Op::Syn | Op::SynAck | Op::Data | Op::Fin => {
            // These carry a seq and need ordered delivery.
            let seq = frame.seq;
            if seq == 0 {
                return;
            }
            if seq < recv.rcv_next {
                // Dup; just re-arm the ack (peer likely missed our ack).
                recv.pending_ack_since.get_or_insert(now);
                return;
            }
            if seq == recv.rcv_next {
                deliver(frame.op, frame.payload, recv, established);
                recv.rcv_next = recv.rcv_next.wrapping_add(1);
                // Drain any contiguous out-of-order entries.
                while let Some((&next_seq, _)) = recv.out_of_order.iter().next() {
                    if next_seq == recv.rcv_next {
                        let (_, (op, payload)) = recv.out_of_order.pop_first().unwrap();
                        deliver(op, payload, recv, established);
                        recv.rcv_next = recv.rcv_next.wrapping_add(1);
                    } else {
                        break;
                    }
                }
                recv.pending_ack_since.get_or_insert(now);
            } else {
                // Future. Buffer.
                if !recv.out_of_order.contains_key(&seq) {
                    recv.out_of_order.insert(seq, (frame.op, frame.payload));
                }
                // Send an ack immediately to encourage fast recovery.
                recv.immediate_ack = true;
                recv.pending_ack_since.get_or_insert(now);
            }
        }
    }

    // If we've consumed peer FIN, mark closing on the local side too so we
    // stop reading from TCP.
    if recv.peer_fin_consumed && !*closing {
        *closing = true;
        if send.fin_seq.is_none() {
            send.fin_seq = Some(send.next_seq);
            queue(send, Op::Fin, Bytes::new());
        }
    }
}

fn deliver(op: Op, payload: Bytes, recv: &mut RecvState, established: &mut bool) {
    match op {
        Op::Syn | Op::SynAck => {
            *established = true;
        }
        Op::Data => {
            recv.deliver_buf.extend_from_slice(&payload);
        }
        Op::Fin => {
            recv.peer_fin_consumed = true;
        }
        _ => {}
    }
}

/// Push any newly queued frames out the wire (initial transmission), and clear
/// the pending-ack flag if at least one of those frames piggybacks the ack.
async fn emit_all(
    send: &mut SendState,
    recv: &mut RecvState,
    tx_frames: &mpsc::Sender<Outbound>,
    conn_id: u64,
    dst: Ipv4Addr,
    _cfg: &ConnConfig,
) {
    let mut emitted_any = false;
    // Collect indices to avoid borrowing send.inflight mutably while building frames.
    let pending_acks: Vec<u32> = send
        .inflight
        .iter()
        .filter(|u| !u.sent_once)
        .map(|u| u.seq)
        .collect();

    for seq in pending_acks {
        // Re-find each time; the deque only grows or pops front during a turn.
        let Some(u) = send.inflight.iter_mut().find(|u| u.seq == seq) else { continue };
        let frame = Frame {
            op: u.op,
            conn_id,
            seq: u.seq,
            ack: recv.ack(),
            win: recv.window_frames(),
            payload: u.payload.clone(),
        };
        if tx_frames.send(Outbound { dst, frame }).await.is_err() {
            return;
        }
        u.sent_once = true;
        u.last_sent = Instant::now();
        emitted_any = true;
    }

    if emitted_any {
        // Piggybacked the ack onto a frame.
        recv.pending_ack_since = None;
        recv.immediate_ack = false;
    }

    // If still owe an immediate ACK (no piggyback possible right now), emit it now.
    if recv.immediate_ack {
        let frame = Frame {
            op: Op::Ack,
            conn_id,
            seq: 0,
            ack: recv.ack(),
            win: recv.window_frames(),
            payload: Bytes::new(),
        };
        let _ = tx_frames.send(Outbound { dst, frame }).await;
        recv.immediate_ack = false;
        recv.pending_ack_since = None;
    }
}

async fn retransmit_oldest(
    send: &mut SendState,
    tx_frames: &mpsc::Sender<Outbound>,
    conn_id: u64,
    dst: Ipv4Addr,
    cfg: &ConnConfig,
    recv: &RecvState,
) {
    let _ = cfg;
    let Some(front) = send.inflight.front_mut() else { return };
    front.retries = front.retries.saturating_add(1);
    front.last_sent = Instant::now();
    let frame = Frame {
        op: front.op,
        conn_id,
        seq: front.seq,
        ack: recv.ack(),
        win: recv.window_frames(),
        payload: front.payload.clone(),
    };
    // Exponential backoff (cap at MAX_RTO).
    send.rto = (send.rto * 2).min(MAX_RTO);
    tracing::debug!(
        conn = %fmt_conn(conn_id),
        seq = front.seq,
        retries = front.retries,
        rto_ms = send.rto.as_millis() as u64,
        "retransmit"
    );
    let _ = tx_frames.send(Outbound { dst, frame }).await;
}

async fn send_standalone_ack(
    recv: &RecvState,
    tx_frames: &mpsc::Sender<Outbound>,
    conn_id: u64,
    dst: Ipv4Addr,
    _cfg: &ConnConfig,
) {
    let frame = Frame {
        op: Op::Ack,
        conn_id,
        seq: 0,
        ack: recv.ack(),
        win: recv.window_frames(),
        payload: Bytes::new(),
    };
    let _ = tx_frames.send(Outbound { dst, frame }).await;
}

async fn send_ping(
    tx_frames: &mpsc::Sender<Outbound>,
    conn_id: u64,
    dst: Ipv4Addr,
    _cfg: &ConnConfig,
) {
    let frame = Frame {
        op: Op::Ping,
        conn_id,
        seq: 0,
        ack: 0,
        win: 0,
        payload: Bytes::new(),
    };
    let _ = tx_frames.send(Outbound { dst, frame }).await;
}

async fn send_rst(
    tx_frames: &mpsc::Sender<Outbound>,
    conn_id: u64,
    dst: Ipv4Addr,
    _cfg: &ConnConfig,
) {
    let frame = Frame::control(Op::Rst, conn_id);
    let _ = tx_frames.send(Outbound { dst, frame }).await;
}

fn min_inst(a: Option<Instant>, b: Instant) -> Instant {
    match a {
        None => b,
        Some(x) => x.min(b),
    }
}

fn fmt_conn(id: u64) -> String {
    format!("{:016x}", id)
}
