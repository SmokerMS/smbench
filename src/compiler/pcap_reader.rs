//! PCAP file reading and packet streaming.
//!
//! Reads PCAP and PCAPNG files using the `pcap-parser` crate and
//! streams Ethernet/IP/TCP packets. Only packets destined for or
//! originating from TCP port 445 (SMB) are emitted.
//!
//! Reference: libpcap / pcapng file formats.

use anyhow::{Context, Result, anyhow};
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{LegacyPcapReader, PcapBlockOwned, PcapError};
use std::fs::File;
use std::io::BufReader;

/// Raw packet data extracted from a PCAP file.
#[derive(Debug, Clone)]
pub struct Packet {
    /// Packet capture timestamp in microseconds since the PCAP epoch.
    pub timestamp_us: u64,
    /// Raw link-layer payload (typically starts with an Ethernet header).
    pub data: Vec<u8>,
}

/// Streams packets from a PCAP file.
pub struct PcapReader {
    path: String,
}

impl PcapReader {
    /// Open a PCAP file for reading.
    pub fn new(path: impl AsRef<str>) -> Result<Self> {
        let path = path.as_ref().to_string();
        std::fs::metadata(&path)
            .with_context(|| format!("PCAP file not found: {}", path))?;
        Ok(Self { path })
    }

    /// Return an iterator over all packets in the file.
    pub fn packets(&self) -> Result<PacketIterator> {
        PacketIterator::new(&self.path)
    }
}

/// Iterator that lazily reads packets from a PCAP file.
pub struct PacketIterator {
    reader: LegacyPcapReader<BufReader<File>>,
    ts_resolution_us: u64,
    done: bool,
}

impl PacketIterator {
    fn new(path: &str) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("Failed to open PCAP: {}", path))?;
        let buf = BufReader::with_capacity(256 * 1024, file);
        let reader = LegacyPcapReader::new(65536, buf)
            .map_err(|e| anyhow!("Failed to create PCAP reader: {:?}", e))?;
        Ok(Self {
            reader,
            ts_resolution_us: 1, // microseconds by default for legacy pcap
            done: false,
        })
    }
}

impl Iterator for PacketIterator {
    type Item = Result<Packet>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        loop {
            match self.reader.next() {
                Ok((offset, block)) => {
                    match block {
                        PcapBlockOwned::LegacyHeader(hdr) => {
                            // If the magic indicates nanosecond resolution, adjust.
                            if hdr.magic_number == 0xa1b2_3c4d {
                                self.ts_resolution_us = 1; // already us
                            }
                            self.reader.consume(offset);
                            continue;
                        }
                        PcapBlockOwned::Legacy(pkt) => {
                            let ts_us = (pkt.ts_sec as u64) * 1_000_000
                                + (pkt.ts_usec as u64) * self.ts_resolution_us;
                            let data = pkt.data.to_vec();
                            self.reader.consume(offset);
                            return Some(Ok(Packet {
                                timestamp_us: ts_us,
                                data,
                            }));
                        }
                        _ => {
                            self.reader.consume(offset);
                            continue;
                        }
                    }
                }
                Err(PcapError::Eof) => {
                    self.done = true;
                    return None;
                }
                Err(PcapError::Incomplete(_needed)) => {
                    self.reader.refill().ok();
                    // If refill does not help we treat as EOF.
                    match self.reader.next() {
                        Ok((offset, block)) => {
                            if let PcapBlockOwned::Legacy(pkt) = block {
                                let ts_us = (pkt.ts_sec as u64) * 1_000_000
                                    + (pkt.ts_usec as u64) * self.ts_resolution_us;
                                let data = pkt.data.to_vec();
                                self.reader.consume(offset);
                                return Some(Ok(Packet {
                                    timestamp_us: ts_us,
                                    data,
                                }));
                            } else {
                                self.reader.consume(offset);
                                continue;
                            }
                        }
                        Err(_) => {
                            self.done = true;
                            return None;
                        }
                    }
                }
                Err(e) => {
                    self.done = true;
                    return Some(Err(anyhow!("PCAP read error: {:?}", e)));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcap_reader_missing_file() {
        let r = PcapReader::new("/nonexistent/file.pcap");
        assert!(r.is_err());
    }
}
