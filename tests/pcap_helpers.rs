#![allow(dead_code)]
//! Helpers for programmatically generating test PCAP files that contain
//! realistic SMB2 traffic. Used by the compiler integration tests.
//!
//! The generated PCAPs are minimal but structurally valid:
//!   Global header + N×(Packet header + Ethernet + IPv4 + TCP + SMB2).

use std::net::Ipv4Addr;
use std::path::PathBuf;

// ── PCAP global header (24 bytes) ──

const PCAP_MAGIC: u32 = 0xa1b2_c3d4; // microsecond resolution
const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;
const PCAP_SNAPLEN: u32 = 65535;
const PCAP_LINKTYPE_ETHERNET: u32 = 1;

fn pcap_global_header() -> Vec<u8> {
    let mut h = Vec::new();
    h.extend_from_slice(&PCAP_MAGIC.to_le_bytes());
    h.extend_from_slice(&PCAP_VERSION_MAJOR.to_le_bytes());
    h.extend_from_slice(&PCAP_VERSION_MINOR.to_le_bytes());
    h.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    h.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    h.extend_from_slice(&PCAP_SNAPLEN.to_le_bytes());
    h.extend_from_slice(&PCAP_LINKTYPE_ETHERNET.to_le_bytes());
    h
}

fn pcap_packet_header(ts_sec: u32, ts_usec: u32, len: u32) -> Vec<u8> {
    let mut h = Vec::new();
    h.extend_from_slice(&ts_sec.to_le_bytes());
    h.extend_from_slice(&ts_usec.to_le_bytes());
    h.extend_from_slice(&len.to_le_bytes()); // incl_len
    h.extend_from_slice(&len.to_le_bytes()); // orig_len
    h
}

// ── Ethernet + IPv4 + TCP ──

fn build_eth_ipv4_tcp(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut pkt = Vec::new();

    // Ethernet (14 bytes)
    pkt.extend_from_slice(&[0u8; 6]); // dst MAC
    pkt.extend_from_slice(&[0u8; 6]); // src MAC
    pkt.extend_from_slice(&0x0800u16.to_be_bytes());

    // IPv4 (20 bytes)
    let total_len = (20 + 20 + payload.len()) as u16;
    pkt.push(0x45); // version=4, IHL=5
    pkt.push(0);
    pkt.extend_from_slice(&total_len.to_be_bytes());
    pkt.extend_from_slice(&[0; 4]); // id, flags, frag
    pkt.push(64); // TTL
    pkt.push(6); // TCP
    pkt.extend_from_slice(&[0; 2]); // checksum
    pkt.extend_from_slice(&src_ip.octets());
    pkt.extend_from_slice(&dst_ip.octets());

    // TCP (20 bytes)
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(&ack.to_be_bytes());
    pkt.push(0x50); // data offset = 5 words
    pkt.push(flags);
    pkt.extend_from_slice(&8192u16.to_be_bytes()); // window
    pkt.extend_from_slice(&[0; 2]); // checksum
    pkt.extend_from_slice(&[0; 2]); // urgent

    pkt.extend_from_slice(payload);
    pkt
}

// ── SMB2 message builder ──

const SMB2_MAGIC: &[u8; 4] = b"\xfeSMB";

fn smb2_header(
    command: u16,
    flags: u32,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    status: u32,
) -> Vec<u8> {
    let mut h = Vec::new();
    h.extend_from_slice(SMB2_MAGIC);
    h.extend_from_slice(&64u16.to_le_bytes()); // StructureSize
    h.extend_from_slice(&1u16.to_le_bytes());  // CreditCharge
    h.extend_from_slice(&status.to_le_bytes());
    h.extend_from_slice(&command.to_le_bytes());
    h.extend_from_slice(&1u16.to_le_bytes());  // Credits
    h.extend_from_slice(&flags.to_le_bytes());
    h.extend_from_slice(&0u32.to_le_bytes());  // NextCommand
    h.extend_from_slice(&message_id.to_le_bytes());
    h.extend_from_slice(&0u32.to_le_bytes());  // Reserved
    h.extend_from_slice(&tree_id.to_le_bytes());
    h.extend_from_slice(&session_id.to_le_bytes());
    h.extend_from_slice(&[0u8; 16]);           // Signature
    h
}

/// NetBIOS session service frame: 4-byte big-endian length + payload.
fn netbios_frame(smb_msg: &[u8]) -> Vec<u8> {
    let len = smb_msg.len() as u32;
    let mut f = Vec::new();
    f.extend_from_slice(&len.to_be_bytes());
    f.extend_from_slice(smb_msg);
    f
}

/// Build a NEGOTIATE request (command 0x0000).
fn negotiate_request(msg_id: u64) -> Vec<u8> {
    let hdr = smb2_header(0x0000, 0, msg_id, 0, 0, 0);
    // Minimal negotiate request body: StructureSize (36) + rest zeros
    let mut body = vec![0u8; 36];
    body[0] = 36; // StructureSize
    let mut msg = hdr;
    msg.extend_from_slice(&body);
    msg
}

/// Build a NEGOTIATE response (command 0x0000, flags=0x01).
fn negotiate_response(msg_id: u64) -> Vec<u8> {
    let hdr = smb2_header(0x0000, 0x0000_0001, msg_id, 0, 0, 0);
    let mut body = vec![0u8; 65];
    body[0] = 65; // StructureSize
    let mut msg = hdr;
    msg.extend_from_slice(&body);
    msg
}

/// Build a SESSION_SETUP request.
fn session_setup_request(msg_id: u64) -> Vec<u8> {
    let hdr = smb2_header(0x0001, 0, msg_id, 0, 0, 0);
    let mut body = vec![0u8; 25];
    body[0] = 25;
    let mut msg = hdr;
    msg.extend_from_slice(&body);
    msg
}

/// Build a SESSION_SETUP response.
fn session_setup_response(msg_id: u64, session_id: u64) -> Vec<u8> {
    let hdr = smb2_header(0x0001, 0x0000_0001, msg_id, session_id, 0, 0);
    let mut body = vec![0u8; 9];
    body[0] = 9;
    let mut msg = hdr;
    msg.extend_from_slice(&body);
    msg
}

/// Build a TREE_CONNECT request with a UNC path.
fn tree_connect_request(msg_id: u64, session_id: u64, path: &str) -> Vec<u8> {
    let path_bytes: Vec<u8> = path.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let path_offset = 64 + 8; // after header + 8-byte fixed body
    let hdr = smb2_header(0x0003, 0, msg_id, session_id, 0, 0);
    // Body: StructureSize (2) + Reserved/Flags (2) + PathOffset (2) + PathLength (2)
    let mut body = Vec::new();
    body.extend_from_slice(&9u16.to_le_bytes()); // StructureSize
    body.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    body.extend_from_slice(&(path_offset as u16).to_le_bytes());
    body.extend_from_slice(&(path_bytes.len() as u16).to_le_bytes());
    body.extend_from_slice(&path_bytes);
    let mut msg = hdr;
    msg.extend_from_slice(&body);
    msg
}

/// Build a TREE_CONNECT response.
fn tree_connect_response(msg_id: u64, session_id: u64, tree_id: u32) -> Vec<u8> {
    let hdr = smb2_header(0x0003, 0x0000_0001, msg_id, session_id, tree_id, 0);
    let mut body = vec![0u8; 16];
    body[0] = 16;
    let mut msg = hdr;
    msg.extend_from_slice(&body);
    msg
}

/// Build a CREATE request for a file.
fn create_request(
    msg_id: u64,
    session_id: u64,
    tree_id: u32,
    file_name: &str,
    desired_access: u32,
    create_disposition: u32,
    oplock_level: u8,
) -> Vec<u8> {
    let name_bytes: Vec<u8> = file_name.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let name_offset = 64 + 56; // header + fixed create body
    let hdr = smb2_header(0x0005, 0, msg_id, session_id, tree_id, 0);

    // [MS-SMB2 2.2.13] CREATE Request fixed body = 57 bytes (StructureSize)
    let mut body = vec![0u8; 56];
    body[0] = 57; body[1] = 0; // StructureSize
    // byte 3 = RequestedOplockLevel
    body[3] = oplock_level;
    // bytes 24..28 = DesiredAccess
    body[24..28].copy_from_slice(&desired_access.to_le_bytes());
    // bytes 36..40 = CreateDisposition
    body[36..40].copy_from_slice(&create_disposition.to_le_bytes());
    // bytes 44..46 = NameOffset
    body[44..46].copy_from_slice(&(name_offset as u16).to_le_bytes());
    // bytes 46..48 = NameLength
    body[46..48].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());

    let mut msg = hdr;
    msg.extend_from_slice(&body);
    msg.extend_from_slice(&name_bytes);
    msg
}

/// Build a CREATE response with a file ID.
fn create_response(
    msg_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: [u8; 16],
    oplock_level: u8,
) -> Vec<u8> {
    let hdr = smb2_header(0x0005, 0x0000_0001, msg_id, session_id, tree_id, 0);
    // [MS-SMB2 2.2.14] CREATE Response: StructureSize = 89, 88 bytes of body
    let mut body = vec![0u8; 88];
    body[0] = 89; body[1] = 0;
    body[2] = oplock_level;
    // FileId at offset 64
    body[64..80].copy_from_slice(&file_id);
    let mut msg = hdr;
    msg.extend_from_slice(&body);
    msg
}

/// Build a READ request.
fn read_request(
    msg_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: [u8; 16],
    offset: u64,
    length: u32,
) -> Vec<u8> {
    let hdr = smb2_header(0x0008, 0, msg_id, session_id, tree_id, 0);
    let mut body = vec![0u8; 49];
    body[0] = 49; body[1] = 0;
    body[4..8].copy_from_slice(&length.to_le_bytes());
    body[8..16].copy_from_slice(&offset.to_le_bytes());
    body[16..32].copy_from_slice(&file_id);
    let mut msg = hdr;
    msg.extend_from_slice(&body);
    msg
}

/// Build a READ response.
fn read_response(
    msg_id: u64,
    session_id: u64,
    tree_id: u32,
    data_length: u32,
) -> Vec<u8> {
    let hdr = smb2_header(0x0008, 0x0000_0001, msg_id, session_id, tree_id, 0);
    let mut body = vec![0u8; 17];
    body[0] = 17; body[1] = 0;
    body[4..8].copy_from_slice(&data_length.to_le_bytes());
    let mut msg = hdr;
    msg.extend_from_slice(&body);
    // Append dummy read data
    msg.extend(vec![0xAA; data_length as usize]);
    msg
}

/// Build a WRITE request.
fn write_request(
    msg_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: [u8; 16],
    offset: u64,
    data: &[u8],
) -> Vec<u8> {
    let hdr = smb2_header(0x0009, 0, msg_id, session_id, tree_id, 0);
    let data_offset = 64 + 48; // header + fixed write body
    let mut body = vec![0u8; 48];
    body[0] = 49; body[1] = 0;
    body[2..4].copy_from_slice(&(data_offset as u16).to_le_bytes());
    body[4..8].copy_from_slice(&(data.len() as u32).to_le_bytes());
    body[8..16].copy_from_slice(&offset.to_le_bytes());
    body[16..32].copy_from_slice(&file_id);
    let mut msg = hdr;
    msg.extend_from_slice(&body);
    msg.extend_from_slice(data);
    msg
}

/// Build a WRITE response.
fn write_response(
    msg_id: u64,
    session_id: u64,
    tree_id: u32,
    count: u32,
) -> Vec<u8> {
    let hdr = smb2_header(0x0009, 0x0000_0001, msg_id, session_id, tree_id, 0);
    let mut body = vec![0u8; 17];
    body[0] = 17; body[1] = 0;
    body[4..8].copy_from_slice(&count.to_le_bytes());
    let mut msg = hdr;
    msg.extend_from_slice(&body);
    msg
}

/// Build a CLOSE request.
fn close_request(
    msg_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: [u8; 16],
) -> Vec<u8> {
    let hdr = smb2_header(0x0006, 0, msg_id, session_id, tree_id, 0);
    let mut body = vec![0u8; 24];
    body[0] = 24; body[1] = 0;
    body[8..24].copy_from_slice(&file_id);
    let mut msg = hdr;
    msg.extend_from_slice(&body);
    msg
}

/// Build a CLOSE response.
fn close_response(
    msg_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: [u8; 16],
) -> Vec<u8> {
    let hdr = smb2_header(0x0006, 0x0000_0001, msg_id, session_id, tree_id, 0);
    let mut body = vec![0u8; 60];
    body[0] = 60; body[1] = 0;
    body[4..20].copy_from_slice(&file_id);
    let mut msg = hdr;
    msg.extend_from_slice(&body);
    msg
}

// ── High-level PCAP generation ──

/// A packet to be added to the PCAP, with network metadata.
struct SmbPacket {
    ts_sec: u32,
    ts_usec: u32,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    smb_msg: Vec<u8>,
}

/// A builder for constructing PCAP files from SMB message sequences.
pub struct PcapBuilder {
    packets: Vec<SmbPacket>,
    client_seq: u32,
    server_seq: u32,
}

impl PcapBuilder {
    pub fn new() -> Self {
        Self {
            packets: Vec::new(),
            client_seq: 1000,
            server_seq: 5000,
        }
    }

    /// Add a client→server SMB message.
    fn client_msg(
        &mut self,
        ts_sec: u32,
        ts_usec: u32,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        msg: Vec<u8>,
    ) {
        let framed = netbios_frame(&msg);
        let seq = self.client_seq;
        self.client_seq += framed.len() as u32;
        self.packets.push(SmbPacket {
            ts_sec,
            ts_usec,
            src_ip,
            dst_ip,
            src_port,
            dst_port: 445,
            seq,
            ack: self.server_seq,
            flags: 0x18, // PSH+ACK
            smb_msg: framed,
        });
    }

    /// Add a server→client SMB message.
    fn server_msg(
        &mut self,
        ts_sec: u32,
        ts_usec: u32,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        msg: Vec<u8>,
    ) {
        let framed = netbios_frame(&msg);
        let seq = self.server_seq;
        self.server_seq += framed.len() as u32;
        self.packets.push(SmbPacket {
            ts_sec,
            ts_usec,
            src_ip: dst_ip,    // server IP
            dst_ip: src_ip,    // client IP
            src_port: 445,
            dst_port,
            seq,
            ack: self.client_seq,
            flags: 0x18,
            smb_msg: framed,
        });
    }

    /// Write the PCAP to a file.
    fn write_to(&self, path: &std::path::Path) {
        let mut data = pcap_global_header();
        for p in &self.packets {
            let eth_pkt = build_eth_ipv4_tcp(
                p.src_ip, p.dst_ip, p.src_port, p.dst_port,
                p.seq, p.ack, p.flags, &p.smb_msg,
            );
            data.extend(pcap_packet_header(p.ts_sec, p.ts_usec, eth_pkt.len() as u32));
            data.extend(&eth_pkt);
        }
        std::fs::write(path, data).expect("Failed to write PCAP");
    }
}

// ── Public PCAP generators ──

/// Generate `simple.pcap`: 1 client, negotiate → session_setup →
/// tree_connect → create → write → read → close.
pub fn generate_simple_pcap(dir: &std::path::Path) -> PathBuf {
    let path = dir.join("simple.pcap");
    let client = Ipv4Addr::new(10, 0, 0, 1);
    let server = Ipv4Addr::new(10, 0, 0, 2);
    let cport = 49152u16;
    let session_id = 0x1000u64;
    let tree_id = 100u32;
    let file_id: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    ];

    let mut b = PcapBuilder::new();
    let mut t = 0u32;

    // NEGOTIATE
    b.client_msg(t, 0, client, server, cport, negotiate_request(0));
    t += 1;
    b.server_msg(t, 0, client, server, cport, negotiate_response(0));

    // SESSION_SETUP
    t += 1;
    b.client_msg(t, 0, client, server, cport, session_setup_request(1));
    t += 1;
    b.server_msg(t, 0, client, server, cport, session_setup_response(1, session_id));

    // TREE_CONNECT
    t += 1;
    b.client_msg(t, 0, client, server, cport,
        tree_connect_request(2, session_id, r"\\10.0.0.2\share"));
    t += 1;
    b.server_msg(t, 0, client, server, cport,
        tree_connect_response(2, session_id, tree_id));

    // CREATE
    t += 1;
    b.client_msg(t, 0, client, server, cport,
        create_request(3, session_id, tree_id, "testfile.txt", 0x0012_0089, 2, 0));
    t += 1;
    b.server_msg(t, 0, client, server, cport,
        create_response(3, session_id, tree_id, file_id, 0));

    // WRITE
    t += 1;
    let write_data = b"Hello SMBench PCAP compiler!";
    b.client_msg(t, 0, client, server, cport,
        write_request(4, session_id, tree_id, file_id, 0, write_data));
    t += 1;
    b.server_msg(t, 0, client, server, cport,
        write_response(4, session_id, tree_id, write_data.len() as u32));

    // READ
    t += 1;
    b.client_msg(t, 0, client, server, cport,
        read_request(5, session_id, tree_id, file_id, 0, write_data.len() as u32));
    t += 1;
    b.server_msg(t, 0, client, server, cport,
        read_response(5, session_id, tree_id, write_data.len() as u32));

    // CLOSE
    t += 1;
    b.client_msg(t, 0, client, server, cport,
        close_request(6, session_id, tree_id, file_id));
    t += 1;
    b.server_msg(t, 0, client, server, cport,
        close_response(6, session_id, tree_id, file_id));

    b.write_to(&path);
    path
}

/// Generate `multi_client.pcap`: 3 clients each doing create→write→close.
pub fn generate_multi_client_pcap(dir: &std::path::Path) -> PathBuf {
    let path = dir.join("multi_client.pcap");
    let server = Ipv4Addr::new(10, 0, 0, 100);
    let session_id = 0x2000u64;
    let tree_id = 200u32;

    let mut data = pcap_global_header();
    let mut global_ts = 0u32;

    for client_idx in 0..3u8 {
        let client = Ipv4Addr::new(10, 0, client_idx + 1, 1);
        let cport = 50000 + client_idx as u16;
        let sid = session_id + client_idx as u64;
        let tid = tree_id + client_idx as u32;
        let file_id: [u8; 16] = [client_idx + 1; 16];

        let mut b = PcapBuilder::new();

        // NEGOTIATE
        b.client_msg(global_ts, 0, client, server, cport, negotiate_request(0));
        global_ts += 1;
        b.server_msg(global_ts, 0, client, server, cport, negotiate_response(0));
        global_ts += 1;

        // SESSION_SETUP
        b.client_msg(global_ts, 0, client, server, cport, session_setup_request(1));
        global_ts += 1;
        b.server_msg(global_ts, 0, client, server, cport, session_setup_response(1, sid));
        global_ts += 1;

        // TREE_CONNECT
        b.client_msg(global_ts, 0, client, server, cport,
            tree_connect_request(2, sid, r"\\10.0.0.100\data"));
        global_ts += 1;
        b.server_msg(global_ts, 0, client, server, cport,
            tree_connect_response(2, sid, tid));
        global_ts += 1;

        // CREATE
        let fname = format!("client{}_file.dat", client_idx + 1);
        b.client_msg(global_ts, 0, client, server, cport,
            create_request(3, sid, tid, &fname, 0x0012_0089, 2, 0));
        global_ts += 1;
        b.server_msg(global_ts, 0, client, server, cport,
            create_response(3, sid, tid, file_id, 0));
        global_ts += 1;

        // WRITE
        let wdata = format!("data from client {}", client_idx + 1);
        b.client_msg(global_ts, 0, client, server, cport,
            write_request(4, sid, tid, file_id, 0, wdata.as_bytes()));
        global_ts += 1;
        b.server_msg(global_ts, 0, client, server, cport,
            write_response(4, sid, tid, wdata.len() as u32));
        global_ts += 1;

        // CLOSE
        b.client_msg(global_ts, 0, client, server, cport,
            close_request(5, sid, tid, file_id));
        global_ts += 1;
        b.server_msg(global_ts, 0, client, server, cport,
            close_response(5, sid, tid, file_id));
        global_ts += 1;

        // Append this client's packets to the global data.
        for p in &b.packets {
            let eth = build_eth_ipv4_tcp(
                p.src_ip, p.dst_ip, p.src_port, p.dst_port,
                p.seq, p.ack, p.flags, &p.smb_msg,
            );
            data.extend(pcap_packet_header(p.ts_sec, p.ts_usec, eth.len() as u32));
            data.extend(&eth);
        }
    }

    std::fs::write(&path, data).expect("Failed to write multi_client.pcap");
    path
}

/// Generate an empty but valid PCAP (global header only, no packets).
pub fn generate_empty_pcap(dir: &std::path::Path) -> PathBuf {
    let path = dir.join("empty.pcap");
    std::fs::write(&path, pcap_global_header()).expect("Failed to write empty.pcap");
    path
}
