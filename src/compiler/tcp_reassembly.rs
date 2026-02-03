//! TCP stream reassembly from packets
//!
//! Reference: RFC 793 - Transmission Control Protocol

use super::pcap_reader::Packet;
use anyhow::Result;
use std::collections::HashMap;

/// TCP stream identifier
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct StreamId {
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
}

/// Reassembled TCP stream
#[derive(Debug, Clone)]
pub struct TcpStream {
    pub id: StreamId,
    pub data: Vec<u8>,
    pub start_time_us: u64,
}

/// TCP stream reassembler
pub struct TcpReassembler {
    streams: HashMap<StreamId, Vec<u8>>,
    start_times: HashMap<StreamId, u64>,
}

impl TcpReassembler {
    /// Create a new TCP reassembler
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
            start_times: HashMap::new(),
        }
    }

    /// Process a packet and add it to the appropriate stream
    pub fn process_packet(&mut self, _packet: Packet) -> Result<()> {
        // TODO: Implement TCP reassembly
        // 1. Parse IP header to get src/dst IP
        // 2. Parse TCP header to get src/dst port, sequence number
        // 3. Add payload to appropriate stream buffer
        // 4. Handle out-of-order packets
        // 5. Detect stream completion (FIN/RST)
        Ok(())
    }

    /// Finalize reassembly and return all streams
    pub fn finalize(self) -> Result<Vec<TcpStream>> {
        let mut streams = Vec::new();

        for (id, data) in self.streams {
            let start_time_us = self.start_times.get(&id).copied().unwrap_or(0);
            streams.push(TcpStream {
                id,
                data,
                start_time_us,
            });
        }

        Ok(streams)
    }
}

impl Default for TcpReassembler {
    fn default() -> Self {
        Self::new()
    }
}
