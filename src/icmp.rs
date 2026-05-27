//! Async ICMP transport.
//!
//! Uses `SOCK_RAW` + `IPPROTO_ICMP` (requires root or `cap_net_raw`). We
//! manually build/parse the 8-byte ICMP echo header. The OS prepends the IPv4
//! header on send, and includes it on recv (we strip it).
//!
//! Direction conventions (so NAT lets replies through):
//!   - Client → Server: ICMP type 8 (echo request)
//!   - Server → Client: ICMP type 0 (echo reply), with the ICMP id copied from
//!     the most recent request the server has seen from that client source IP.

use std::io;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::unix::AsyncFd;

pub const ICMP_ECHO_REQUEST: u8 = 8;
pub const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_HEADER_LEN: usize = 8;

#[derive(Debug, Clone, Copy)]
pub struct IcmpPacket {
    pub src: Ipv4Addr,
    pub icmp_type: u8,
    pub icmp_id: u16,
    #[allow(dead_code)]
    pub icmp_seq: u16,
}

/// Owned async wrapper around an ICMP socket.
///
/// We try `SOCK_DGRAM` + `IPPROTO_ICMP` first (works without root on macOS, and
/// on Linux if `net.ipv4.ping_group_range` permits the calling gid). If that
/// fails with EPERM/EACCES we fall back to `SOCK_RAW` + `IPPROTO_ICMP` (root /
/// `cap_net_raw`). The two modes differ on recv: `SOCK_RAW` includes the IPv4
/// header, `SOCK_DGRAM` does not.
pub struct IcmpSocket {
    inner: Arc<AsyncFd<Socket>>,
    is_raw: bool,
}

impl IcmpSocket {
    pub fn bind(bind_ip: &str) -> Result<Self> {
        let bind_addr: Ipv4Addr = bind_ip
            .parse()
            .with_context(|| format!("invalid bind address: {}", bind_ip))?;

        // First, try the unprivileged DGRAM ICMP socket.
        let (sock, is_raw) = match Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4)) {
            Ok(s) => {
                tracing::debug!("using SOCK_DGRAM ICMP (unprivileged)");
                (s, false)
            }
            Err(e_dgram) => {
                tracing::debug!(error = %e_dgram, "DGRAM ICMP unavailable, falling back to RAW");
                let s = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
                    .context("failed to create ICMP socket (need root or cap_net_raw, and DGRAM ICMP unavailable)")?;
                (s, true)
            }
        };

        sock.bind(&SocketAddr::new(IpAddr::V4(bind_addr), 0).into())
            .with_context(|| format!("bind {} failed", bind_ip))?;
        sock.set_nonblocking(true)?;
        let _ = sock.set_recv_buffer_size(4 * 1024 * 1024);
        let _ = sock.set_send_buffer_size(4 * 1024 * 1024);

        Ok(IcmpSocket {
            inner: Arc::new(AsyncFd::new(sock)?),
            is_raw,
        })
    }

    pub fn clone_handle(&self) -> IcmpSocket {
        IcmpSocket {
            inner: Arc::clone(&self.inner),
            is_raw: self.is_raw,
        }
    }

    /// Read a single ICMP packet. Returns the trimmed payload (after the 8-byte
    /// ICMP header) along with packet metadata. We expect echo request OR echo
    /// reply; other types are returned too — callers can filter.
    pub async fn recv(&self, buf: &mut Vec<u8>) -> Result<IcmpPacket> {
        buf.clear();
        loop {
            let mut guard = self.inner.readable().await?;
            // socket2 wants MaybeUninit. Use a scratch then copy out.
            let mut scratch = [MaybeUninit::<u8>::uninit(); 65536];
            let res = guard.try_io(|inner| inner.get_ref().recv_from(&mut scratch));
            match res {
                Ok(Ok((n, sock_addr))) => {
                    let raw: &[u8] = unsafe {
                        std::slice::from_raw_parts(scratch.as_ptr() as *const u8, n)
                    };
                    let src_v4 = match sock_addr.as_socket() {
                        Some(SocketAddr::V4(v4)) => *v4.ip(),
                        _ => Ipv4Addr::UNSPECIFIED,
                    };
                    // SOCK_RAW includes the IPv4 header; SOCK_DGRAM doesn't.
                    let icmp: &[u8] = if self.is_raw {
                        if raw.len() < 20 {
                            continue;
                        }
                        let ihl = (raw[0] & 0x0F) as usize * 4;
                        if ihl < 20 || raw.len() < ihl + ICMP_HEADER_LEN {
                            continue;
                        }
                        &raw[ihl..]
                    } else {
                        if raw.len() < ICMP_HEADER_LEN {
                            continue;
                        }
                        raw
                    };
                    let icmp_type = icmp[0];
                    let icmp_id = u16::from_be_bytes([icmp[4], icmp[5]]);
                    let icmp_seq = u16::from_be_bytes([icmp[6], icmp[7]]);
                    let payload = &icmp[ICMP_HEADER_LEN..];
                    buf.extend_from_slice(payload);
                    return Ok(IcmpPacket {
                        src: src_v4,
                        icmp_type,
                        icmp_id,
                        icmp_seq,
                    });
                }
                Ok(Err(e)) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Ok(Err(e)) => return Err(e.into()),
                Err(_would_block) => continue,
            }
        }
    }

    /// Send a single ICMP echo packet (with our own ICMP header) to `dst`.
    pub async fn send(
        &self,
        dst: Ipv4Addr,
        icmp_type: u8,
        icmp_id: u16,
        icmp_seq: u16,
        payload: &[u8],
    ) -> Result<()> {
        let mut pkt = Vec::with_capacity(ICMP_HEADER_LEN + payload.len());
        pkt.push(icmp_type); // type
        pkt.push(0); // code
        pkt.extend_from_slice(&[0, 0]); // checksum placeholder
        pkt.extend_from_slice(&icmp_id.to_be_bytes());
        pkt.extend_from_slice(&icmp_seq.to_be_bytes());
        pkt.extend_from_slice(payload);
        let cksum = checksum(&pkt);
        pkt[2..4].copy_from_slice(&cksum.to_be_bytes());

        let sock_addr: SockAddr = SocketAddr::new(IpAddr::V4(dst), 0).into();
        loop {
            let mut guard = self.inner.writable().await?;
            match guard.try_io(|inner| inner.get_ref().send_to(&pkt, &sock_addr)) {
                Ok(Ok(_)) => return Ok(()),
                Ok(Err(e)) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Ok(Err(e)) => return Err(e.into()),
                Err(_would_block) => continue,
            }
        }
    }
}

/// Standard "internet" checksum (RFC 1071).
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Resolve a hostname to an IPv4 address (synchronously; called rarely).
pub fn resolve_v4(host: &str) -> Result<Ipv4Addr> {
    use std::net::ToSocketAddrs;
    // Append a dummy port so ToSocketAddrs parses it.
    let probe = format!("{}:0", host);
    for addr in probe.to_socket_addrs()? {
        if let SocketAddr::V4(v4) = addr {
            return Ok(*v4.ip());
        }
    }
    Err(anyhow!("no IPv4 address found for {}", host))
}

