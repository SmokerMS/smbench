//! TCP stream reassembly from raw packets.
//!
//! Parses Ethernet, IPv4/IPv6 and TCP headers, then reassembles
//! payload bytes into per-connection streams ordered by sequence
//! number. Only streams involving TCP port 445 (SMB) are kept.
//!
//! Reference: RFC 793 (TCP), RFC 791 (IPv4), RFC 8200 (IPv6).

use super::pcap_reader::Packet;
use anyhow::Result;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// SMB port used to filter relevant streams.
const SMB_PORT: u16 = 445;

/// A unique identifier for a TCP half-connection (one direction).
#[derive(Clone, Hash, Eq, PartialEq)]
pub struct StreamId {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

impl fmt::Debug for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{} -> {}:{}", self.src_ip, self.src_port, self.dst_ip, self.dst_port)
    }
}

impl StreamId {
    /// Return the canonical (bi-directional) key so both directions map to the
    /// same logical connection. The side with the lower (ip, port) comes first.
    pub fn canonical(&self) -> (StreamId, StreamId) {
        let a = self.clone();
        let b = StreamId {
            src_ip: self.dst_ip,
            src_port: self.dst_port,
            dst_ip: self.src_ip,
            dst_port: self.src_port,
        };
        if (a.src_ip, a.src_port) <= (b.src_ip, b.src_port) {
            (a, b)
        } else {
            (b, a)
        }
    }

    /// True when this half-connection is from the SMB client to the server
    /// (destination port is 445).
    pub fn is_client_to_server(&self) -> bool {
        self.dst_port == SMB_PORT
    }
}

/// A fully reassembled TCP stream (one direction).
#[derive(Debug, Clone)]
pub struct TcpStream {
    pub id: StreamId,
    pub data: Vec<u8>,
    pub start_time_us: u64,
}

// ── internal helpers ──

struct StreamBuffer {
    /// Out-of-order segments keyed by sequence number.
    segments: BTreeMap<u32, Vec<u8>>,
    /// The next expected sequence number (for in-order reassembly).
    next_seq: Option<u32>,
    /// Reassembled payload accumulated so far.
    reassembled: Vec<u8>,
    /// Timestamp of the first segment seen.
    start_time_us: u64,
    /// Track seen sequence numbers to deduplicate retransmissions.
    seen_max_seq: u32,
}

impl StreamBuffer {
    fn new() -> Self {
        Self {
            segments: BTreeMap::new(),
            next_seq: None,
            reassembled: Vec::new(),
            start_time_us: 0,
            seen_max_seq: 0,
        }
    }

    fn add_segment(&mut self, seq: u32, data: &[u8], timestamp_us: u64) {
        if data.is_empty() {
            return;
        }
        if self.start_time_us == 0 {
            self.start_time_us = timestamp_us;
        }
        if self.next_seq.is_none() {
            self.next_seq = Some(seq);
        }

        let end_seq = seq.wrapping_add(data.len() as u32);

        // Simple retransmission filter: skip if the segment end is not past
        // what we have already reassembled.
        if self.seen_max_seq != 0 && self.next_seq.is_some() {
            let expected = self.next_seq.unwrap();
            // If seq is before expected and end is also before expected, skip.
            if seq_before(end_seq, expected) || end_seq == expected {
                if !seq_before(self.seen_max_seq, end_seq) {
                    return; // duplicate / retransmit
                }
            }
        }

        if end_seq.wrapping_sub(seq) > 0 && seq_before(self.seen_max_seq, end_seq) {
            self.seen_max_seq = end_seq;
        }

        self.segments.insert(seq, data.to_vec());
        self.try_reassemble();
    }

    fn try_reassemble(&mut self) {
        let Some(mut expected) = self.next_seq else { return };
        loop {
            if let Some(data) = self.segments.remove(&expected) {
                let len = data.len() as u32;
                self.reassembled.extend_from_slice(&data);
                expected = expected.wrapping_add(len);
                self.next_seq = Some(expected);
            } else {
                break;
            }
        }
    }
}

/// Returns true when `a` is strictly before `b` in the TCP sequence space
/// (handles wrapping).
fn seq_before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

// ── Ethernet / IP / TCP parsing ──

fn parse_ethernet(data: &[u8]) -> Option<(u16, &[u8])> {
    if data.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    Some((ethertype, &data[14..]))
}

fn parse_ipv4(data: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr, u8, &[u8])> {
    if data.len() < 20 {
        return None;
    }
    let ihl = (data[0] & 0x0F) as usize * 4;
    if data.len() < ihl {
        return None;
    }
    let protocol = data[9];
    let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
    Some((src, dst, protocol, &data[ihl..]))
}

fn parse_ipv6(data: &[u8]) -> Option<(Ipv6Addr, Ipv6Addr, u8, &[u8])> {
    if data.len() < 40 {
        return None;
    }
    let next_header = data[6];
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).ok()?);
    // Simplified: no extension header chasing.
    Some((src, dst, next_header, &data[40..]))
}

struct TcpHeader {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    _ack: u32,
    flags: u8,
}

fn parse_tcp(data: &[u8]) -> Option<(TcpHeader, &[u8])> {
    if data.len() < 20 {
        return None;
    }
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let data_offset = ((data[12] >> 4) as usize) * 4;
    let flags = data[13];
    if data.len() < data_offset {
        return None;
    }
    let payload = &data[data_offset..];
    Some((
        TcpHeader {
            src_port,
            dst_port,
            seq,
            _ack: ack,
            flags,
        },
        payload,
    ))
}

const TCP_FLAG_SYN: u8 = 0x02;

// ── public API ──

/// Reassembles TCP streams from raw packets.
pub struct TcpReassembler {
    streams: HashMap<StreamId, StreamBuffer>,
}

impl TcpReassembler {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
        }
    }

    /// Feed a raw packet (starting at the Ethernet header).
    pub fn process_packet(&mut self, packet: Packet) -> Result<()> {
        let Some((ethertype, ip_data)) = parse_ethernet(&packet.data) else {
            return Ok(()); // not Ethernet
        };

        let (src_ip, dst_ip, proto, tcp_data) = match ethertype {
            0x0800 => {
                // IPv4
                let Some((s, d, proto, rest)) = parse_ipv4(ip_data) else {
                    return Ok(());
                };
                (IpAddr::V4(s), IpAddr::V4(d), proto, rest)
            }
            0x86DD => {
                // IPv6
                let Some((s, d, proto, rest)) = parse_ipv6(ip_data) else {
                    return Ok(());
                };
                (IpAddr::V6(s), IpAddr::V6(d), proto, rest)
            }
            _ => return Ok(()), // not IP
        };

        if proto != 6 {
            return Ok(()); // not TCP
        }

        let Some((tcp_hdr, payload)) = parse_tcp(tcp_data) else {
            return Ok(());
        };

        // Filter: only keep streams involving SMB port 445.
        if tcp_hdr.src_port != SMB_PORT && tcp_hdr.dst_port != SMB_PORT {
            return Ok(());
        }

        let stream_id = StreamId {
            src_ip,
            src_port: tcp_hdr.src_port,
            dst_ip,
            dst_port: tcp_hdr.dst_port,
        };

        // For SYN packets, record the initial sequence number (ISN).
        let is_syn = tcp_hdr.flags & TCP_FLAG_SYN != 0;
        let seq = if is_syn {
            // SYN consumes one sequence number; payload starts at seq+1.
            tcp_hdr.seq.wrapping_add(1)
        } else {
            tcp_hdr.seq
        };

        let buf = self.streams.entry(stream_id).or_insert_with(StreamBuffer::new);

        if is_syn && buf.next_seq.is_none() {
            buf.next_seq = Some(seq);
        }

        if !payload.is_empty() {
            buf.add_segment(tcp_hdr.seq, payload, packet.timestamp_us);
        }

        Ok(())
    }

    /// Consume the reassembler and return all collected streams.
    pub fn finalize(self) -> Result<Vec<TcpStream>> {
        let mut out = Vec::new();
        for (id, buf) in self.streams {
            if buf.reassembled.is_empty() {
                continue;
            }
            out.push(TcpStream {
                id,
                data: buf.reassembled,
                start_time_us: buf.start_time_us,
            });
        }
        // Deterministic order: sort by start time.
        out.sort_by_key(|s| s.start_time_us);
        Ok(out)
    }
}

impl Default for TcpReassembler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal Ethernet + IPv4 + TCP packet.
    fn build_tcp_packet(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut pkt = Vec::new();

        // Ethernet header (14 bytes): dst MAC, src MAC, ethertype IPv4
        pkt.extend_from_slice(&[0u8; 6]); // dst mac
        pkt.extend_from_slice(&[0u8; 6]); // src mac
        pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4

        // IPv4 header (20 bytes, IHL=5)
        let total_len = (20 + 20 + payload.len()) as u16;
        pkt.push(0x45); // version + IHL
        pkt.push(0);    // DSCP
        pkt.extend_from_slice(&total_len.to_be_bytes());
        pkt.extend_from_slice(&[0; 4]); // id, flags, frag
        pkt.push(64);   // TTL
        pkt.push(6);    // protocol = TCP
        pkt.extend_from_slice(&[0; 2]); // checksum
        pkt.extend_from_slice(&src_ip.octets());
        pkt.extend_from_slice(&dst_ip.octets());

        // TCP header (20 bytes, data offset = 5)
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&seq.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes()); // ack
        pkt.push(0x50); // data offset = 5 words
        pkt.push(flags);
        pkt.extend_from_slice(&1024u16.to_be_bytes()); // window
        pkt.extend_from_slice(&[0; 2]); // checksum
        pkt.extend_from_slice(&[0; 2]); // urgent ptr

        // payload
        pkt.extend_from_slice(payload);
        pkt
    }

    #[test]
    fn test_in_order_reassembly() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let mut r = TcpReassembler::new();

        // SYN
        let syn = build_tcp_packet(src, dst, 50000, SMB_PORT, 100, TCP_FLAG_SYN, &[]);
        r.process_packet(Packet { timestamp_us: 1, data: syn }).unwrap();

        // Data 1
        let p1 = build_tcp_packet(src, dst, 50000, SMB_PORT, 101, 0x10, b"hello");
        r.process_packet(Packet { timestamp_us: 2, data: p1 }).unwrap();

        // Data 2
        let p2 = build_tcp_packet(src, dst, 50000, SMB_PORT, 106, 0x10, b" world");
        r.process_packet(Packet { timestamp_us: 3, data: p2 }).unwrap();

        let streams = r.finalize().unwrap();
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].data, b"hello world");
    }

    #[test]
    fn test_out_of_order_reassembly() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let mut r = TcpReassembler::new();

        // SYN
        let syn = build_tcp_packet(src, dst, 50000, SMB_PORT, 100, TCP_FLAG_SYN, &[]);
        r.process_packet(Packet { timestamp_us: 1, data: syn }).unwrap();

        // Arrives out of order: second segment first
        let p2 = build_tcp_packet(src, dst, 50000, SMB_PORT, 106, 0x10, b" world");
        r.process_packet(Packet { timestamp_us: 2, data: p2 }).unwrap();

        // First segment arrives late
        let p1 = build_tcp_packet(src, dst, 50000, SMB_PORT, 101, 0x10, b"hello");
        r.process_packet(Packet { timestamp_us: 3, data: p1 }).unwrap();

        let streams = r.finalize().unwrap();
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].data, b"hello world");
    }

    #[test]
    fn test_non_smb_filtered_out() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let mut r = TcpReassembler::new();

        // HTTP traffic on port 80 -- should be filtered out
        let p = build_tcp_packet(src, dst, 50000, 80, 100, 0x10, b"GET / HTTP/1.1");
        r.process_packet(Packet { timestamp_us: 1, data: p }).unwrap();

        let streams = r.finalize().unwrap();
        assert!(streams.is_empty());
    }
}
