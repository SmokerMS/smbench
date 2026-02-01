# SMBench Architecture Specification

**Version:** 1.0  
**Date:** February 1, 2026  
**Status:** Foundational Architecture  
**Technology Stack:** Rust + Linux

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [System Overview](#system-overview)
3. [Technology Stack](#technology-stack)
4. [Component Architecture](#component-architecture)
5. [Data Flow](#data-flow)
6. [Workload IR Schema](#workload-ir-schema)
7. [PCAP Compiler](#pcap-compiler)
8. [Replay Engine](#replay-engine)
9. [Multi-Client Coordination](#multi-client-coordination)
10. [Oplock & Lease Handling](#oplock--lease-handling)
11. [Error Handling & Retry](#error-handling--retry)
12. [Observability](#observability)
13. [Deployment](#deployment)
14. [Implementation Phases](#implementation-phases)

---

## Executive Summary

SMBench is a high-fidelity SMB3 workload replay system designed for bug reproduction and load testing.

### Primary Use Case
**Bug Reproduction:** Capture customer SMB workloads (PCAP), replay in lab environment to reproduce file server issues with full protocol fidelity.

### Secondary Use Case
**Load Testing:** Scale captured workloads to 5000+ concurrent users for stress testing.

### Core Design Principles

1. **Semantic Replay** - Replay filesystem operations, not raw packets
2. **Hybrid Timing Model** - Preserve PCAP timeline, react to real-time server events
3. **High Fidelity** - Support oplocks, leases, durable handles (typical in production)
4. **Horizontal Scalability** - 5000+ concurrent users via Rust async
5. **Immutable IR** - Portable workload representation, independent of execution

### Technology Decision

**Language:** Rust  
**SMB Client:** smb-rs (`/afiffon/smb-rs`)  
**Async Runtime:** tokio  
**Platform:** Linux (Docker optional)  
**PCAP Parsing:** Python (Scapy/Pyshark) → Rust engine

**Rationale:** Native async, SMB credit system support, memory efficiency, single binary deployment.

---

## System Overview

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    CAPTURE & ANALYSIS (Python)                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐       ┌─────────────────┐                    │
│  │ Customer     │       │   PCAP Parser   │                    │
│  │ PCAP         │──────▶│   (Scapy/       │                    │
│  │ (Wireshark)  │       │    Pyshark)     │                    │
│  └──────────────┘       └────────┬────────┘                    │
│                                  │                             │
│                                  ▼                             │
│                         ┌─────────────────┐                    │
│                         │  SMB State      │                    │
│                         │  Machine        │                    │
│                         │  (Session/Tree/ │                    │
│                         │   File tracking)│                    │
│                         └────────┬────────┘                    │
│                                  │                             │
│                                  ▼                             │
│                         ┌─────────────────┐                    │
│                         │ IR Generator    │                    │
│                         │ (Operations +   │                    │
│                         │  Dependencies)  │                    │
│                         └────────┬────────┘                    │
└──────────────────────────────────┼──────────────────────────────┘
                                   │
                                   ▼
                         ┌──────────────────┐
                         │  Workload IR     │
                         │  (JSON + blobs/) │
                         └────────┬─────────┘
                                  │
┌──────────────────────────────────┼──────────────────────────────┐
│                    REPLAY ENGINE (Rust)                         │
├──────────────────────────────────┼──────────────────────────────┤
│                                  │                             │
│                                  ▼                             │
│                         ┌─────────────────┐                    │
│                         │  IR Loader      │                    │
│                         │  (serde_json)   │                    │
│                         └────────┬────────┘                    │
│                                  │                             │
│                                  ▼                             │
│                         ┌─────────────────┐                    │
│                         │  Environment    │                    │
│                         │  Mapper         │                    │
│                         │  (paths, users) │                    │
│                         └────────┬────────┘                    │
│                                  │                             │
│                                  ▼                             │
│                         ┌─────────────────┐                    │
│                         │  Provisioner    │                    │
│                         │  (AD users,     │                    │
│                         │   directories)  │                    │
│                         └────────┬────────┘                    │
│                                  │                             │
│                                  ▼                             │
│              ┌──────────────────────────────────┐             │
│              │   Tokio Runtime (Event Loop)     │             │
│              │   - Work-stealing scheduler      │             │
│              │   - Microsecond-precision timers │             │
│              └────────┬─────────────────────────┘             │
│                       │                                       │
│         ┌─────────────┴─────────────┐                         │
│         ▼                           ▼                         │
│  ┌──────────────┐           ┌──────────────┐                 │
│  │  Timeline    │           │  Protocol    │                 │
│  │  Scheduler   │◀─────────▶│  Handler     │                 │
│  │  (Jepsen-    │  coord    │  (Oplock/    │                 │
│  │   inspired)  │           │   Lease)     │                 │
│  └──────┬───────┘           └──────┬───────┘                 │
│         │                          │                         │
│         └──────────┬───────────────┘                         │
│                    ▼                                         │
│         ┌────────────────────────┐                           │
│         │   Client State Pool    │                           │
│         │   (5000 clients)       │                           │
│         │   Arc<Client> per user │                           │
│         └──────────┬─────────────┘                           │
│                    │                                         │
│                    ▼                                         │
│         ┌────────────────────────┐                           │
│         │   SMB Executor Pool    │                           │
│         │   (smb-rs clients)     │                           │
│         └──────────┬─────────────┘                           │
└────────────────────┼─────────────────────────────────────────┘
                     │
                     ▼
            ┌──────────────────┐
            │  Nutanix Files   │
            │  (SMB3 Server)   │
            └──────────────────┘
                     ▲
                     │
┌────────────────────┼─────────────────────────────────────────┐
│              OBSERVABILITY (Rust)                             │
├────────────────────┼─────────────────────────────────────────┤
│                    │                                         │
│  Every operation ──┘                                         │
│         │                                                    │
│         ▼                                                    │
│  ┌──────────────────┐      ┌─────────────────┐             │
│  │ Metrics          │      │  Structured     │             │
│  │ Collector        │─────▶│  Logs           │             │
│  │ (prometheus-rs)  │      │  (tracing-rs)   │             │
│  └──────────────────┘      └─────────────────┘             │
└─────────────────────────────────────────────────────────────┘
```

---

## Technology Stack

### Core Components

| Component | Technology | Version | Rationale |
|-----------|-----------|---------|-----------|
| **Replay Engine** | Rust | 1.75+ | Native async, memory safety, performance |
| **SMB Client** | smb-rs | Latest | SMB2/3 support, credit system, async |
| **Async Runtime** | tokio | 1.48+ | Proven scalability, microsecond timers |
| **PCAP Parser** | Python 3.9+ | - | Scapy/Pyshark for protocol dissection |
| **IR Format** | JSON | - | Human-readable, versioned, portable |
| **Metrics** | prometheus-rs | Latest | Industry standard, Grafana integration |
| **Logging** | tracing-rs | Latest | Structured async-aware logging |
| **Serialization** | serde | Latest | Zero-copy JSON parsing |
| **CLI** | clap | Latest | User-friendly command-line interface |

### Development Tools

| Tool | Purpose |
|------|---------|
| **cargo** | Build system, dependency management |
| **rustfmt** | Code formatting |
| **clippy** | Linting and best practices |
| **cargo-criterion** | Benchmarking |
| **cargo-nextest** | Fast test runner |

### Deployment

| Component | Technology |
|-----------|-----------|
| **Container** | Docker (Debian slim base) |
| **Orchestration** | Kubernetes (optional) |
| **Platform** | Linux (Ubuntu 22.04+ / RHEL 9+) |

---

## Component Architecture

### 1. PCAP Compiler (Python)

**Responsibility:** Convert customer PCAP to Workload IR

**Input:** Customer PCAP file (GB-sized, mixed protocols)  
**Output:** Workload IR (JSON) + blobs directory

**Architecture:**
```python
# compiler/main.py

class PCAPCompiler:
    def __init__(self, pcap_file: str, output_dir: str):
        self.pcap_file = pcap_file
        self.output_dir = output_dir
        self.state_machine = SMBStateMachine()
        self.operations = []
        
    def compile(self) -> WorkloadIR:
        """Main compilation pipeline"""
        # 1. Stream PCAP (don't load all into memory)
        packets = self.stream_packets()
        
        # 2. Reassemble TCP streams
        streams = self.reassemble_tcp(packets)
        
        # 3. Parse SMB protocol
        smb_packets = self.parse_smb(streams)
        
        # 4. Track protocol state
        operations = self.extract_operations(smb_packets)
        
        # 5. Build dependency graph
        operations = self.analyze_dependencies(operations)
        
        # 6. Assign logical clocks (Jepsen-inspired)
        operations = self.assign_logical_clocks(operations)
        
        # 7. Generate IR
        return self.generate_ir(operations)
```

**Key Classes:**

```python
class SMBStateMachine:
    """Track SMB protocol state across packets"""
    sessions: Dict[int, Session]     # SessionId → Session
    trees: Dict[int, TreeConnect]     # TreeId → Share
    opens: Dict[int, OpenFile]        # FileId → File
    
    def process_packet(self, pkt: SMBPacket) -> Optional[Operation]:
        """State machine logic"""
        if pkt.command == SMB2_SESSION_SETUP:
            self.sessions[pkt.session_id] = Session(...)
            
        elif pkt.command == SMB2_CREATE:
            # Track file open
            file_id = pkt.file_id
            self.opens[file_id] = OpenFile(
                path=self.resolve_path(pkt),
                session=self.sessions[pkt.session_id],
                tree=self.trees[pkt.tree_id],
                oplock_level=pkt.oplock_requested,
                create_contexts=pkt.create_contexts
            )
            return OpenOperation(...)
            
        elif pkt.command == SMB2_WRITE:
            # Resolve file from handle
            open_file = self.opens[pkt.file_id]
            return WriteOperation(
                path=open_file.path,
                offset=pkt.offset,
                data=pkt.data,
                handle_ref=pkt.file_id
            )
```

**Dependencies:**
- Scapy or Pyshark (PCAP parsing)
- dpkt (TCP reassembly)
- serde_json (IR generation)

---

### 2. Workload IR (Data Format)

**Responsibility:** Portable, immutable workload representation

**Design Principles:**
- ✅ Immutable (reproducible replay)
- ✅ Versioned (schema evolution)
- ✅ Content-addressed blobs (deduplication)
- ✅ Logical clocks (time-scalable)
- ✅ Platform-independent (maps to test environment)

**Schema Version 1:**

```json
{
  "$schema": "https://smbench.io/schemas/workload-ir/v1",
  "version": 1,
  "metadata": {
    "source_pcap": "customer_trace_2026-02-01.pcap",
    "compile_time": "2026-02-01T12:00:00Z",
    "duration_seconds": 600.0,
    "total_operations": 50000,
    "client_count": 3,
    "compiler_version": "1.0.0"
  },
  
  "clients": [
    {
      "client_id": "client_001",
      "source_ip": "192.168.1.50",
      "username": "jsmith@customer.com",
      "session_id": "0x1234567890ABCDEF",
      "operation_count": 15000
    },
    {
      "client_id": "client_002",
      "source_ip": "192.168.1.51", 
      "username": "mjones@customer.com",
      "session_id": "0xABCDEF1234567890",
      "operation_count": 20000
    },
    {
      "client_id": "client_003",
      "source_ip": "192.168.1.52",
      "username": "alee@customer.com",
      "session_id": "0x1111222233334444",
      "operation_count": 15000
    }
  ],
  
  "shares": [
    {
      "share_path": "\\\\customer-fs01\\sales",
      "tree_id": "0x0001"
    },
    {
      "share_path": "\\\\customer-fs01\\marketing",
      "tree_id": "0x0002"
    }
  ],
  
  "operations": [
    {
      "op_id": "op_00001",
      "client_id": "client_001",
      "logical_clock": 0,
      "timestamp_us": 0,
      "wall_time": "2026-02-01T12:00:00.000000Z",
      "type": "session_setup",
      "session_id": "0x1234567890ABCDEF",
      "username": "jsmith@customer.com",
      "auth_type": "ntlm"
    },
    {
      "op_id": "op_00002",
      "client_id": "client_001",
      "logical_clock": 1,
      "timestamp_us": 50000,
      "wall_time": "2026-02-01T12:00:00.050000Z",
      "type": "tree_connect",
      "tree_id": "0x0001",
      "share_path": "\\\\customer-fs01\\sales"
    },
    {
      "op_id": "op_00003",
      "client_id": "client_001",
      "logical_clock": 2,
      "timestamp_us": 100000,
      "wall_time": "2026-02-01T12:00:00.100000Z",
      "type": "open",
      "tree_id": "0x0001",
      "path": "Documents/Q1_Report.docx",
      "handle_ref": "h_001",
      "disposition": "open_or_create",
      "access_mask": "0x00120089",
      "share_mode": "FILE_SHARE_READ",
      "create_options": "FILE_NON_DIRECTORY_FILE",
      
      "protocol_details": {
        "requested_oplock_level": "SMB2_OPLOCK_LEVEL_BATCH",
        "create_contexts": [
          {
            "type": "SMB2_CREATE_REQUEST_LEASE",
            "lease_key": "12345678-1234-1234-1234-123456789012",
            "lease_state": "READ_CACHING|WRITE_CACHING|HANDLE_CACHING"
          },
          {
            "type": "SMB2_CREATE_DURABLE_HANDLE_REQUEST",
            "durable_timeout_ms": 300000
          }
        ]
      },
      
      "response": {
        "granted_oplock_level": "SMB2_OPLOCK_LEVEL_BATCH",
        "create_action": "FILE_OPENED",
        "file_attributes": "0x00000020",
        "file_size": 2048576
      },
      
      "dependencies": []
    },
    {
      "op_id": "op_00004",
      "client_id": "client_001",
      "logical_clock": 3,
      "timestamp_us": 150000,
      "wall_time": "2026-02-01T12:00:00.150000Z",
      "type": "write",
      "handle_ref": "h_001",
      "offset": 0,
      "length": 4096,
      "blob": {
        "sha256": "abc123...",
        "path": "blobs/abc123.bin",
        "size": 4096
      },
      "dependencies": ["op_00003"]
    },
    {
      "op_id": "op_00005",
      "client_id": "client_002",
      "logical_clock": 10,
      "timestamp_us": 1000000,
      "wall_time": "2026-02-01T12:00:01.000000Z",
      "type": "open",
      "tree_id": "0x0001",
      "path": "Documents/Q1_Report.docx",
      "handle_ref": "h_002",
      "disposition": "open_existing",
      "access_mask": "0x00120089",
      "share_mode": "FILE_SHARE_READ|FILE_SHARE_WRITE",
      
      "protocol_details": {
        "requested_oplock_level": "SMB2_OPLOCK_LEVEL_II",
        "create_contexts": []
      },
      
      "triggers_oplock_break": true,
      "breaks_oplock_for": ["op_00003"],
      
      "dependencies": []
    },
    {
      "op_id": "op_00006",
      "client_id": "client_001",
      "logical_clock": 11,
      "timestamp_us": 1050000,
      "wall_time": "2026-02-01T12:00:01.050000Z",
      "type": "oplock_break_ack",
      "handle_ref": "h_001",
      "new_oplock_level": "SMB2_OPLOCK_LEVEL_II",
      "triggered_by": "op_00005",
      "dependencies": ["op_00005"]
    },
    {
      "op_id": "op_00007",
      "client_id": "client_001",
      "logical_clock": 20,
      "timestamp_us": 2500000,
      "wall_time": "2026-02-01T12:00:02.500000Z",
      "type": "close",
      "handle_ref": "h_001",
      "dependencies": ["op_00003", "op_00004", "op_00006"]
    },
    {
      "op_id": "op_00008",
      "client_id": "client_001",
      "logical_clock": 30,
      "timestamp_us": 3000000,
      "wall_time": "2026-02-01T12:00:03.000000Z",
      "type": "rename",
      "tree_id": "0x0001",
      "source_path": "Documents/Q1_Report.docx",
      "dest_path": "Archive/Q1_Report_Final.docx",
      "replace_if_exists": false,
      "dependencies": ["op_00007"]
    }
  ]
}
```

**Operation Types:**
- `session_setup` - Authenticate to server
- `tree_connect` - Connect to share
- `open` - Open/create file (with oplock/lease details)
- `read` - Read file data
- `write` - Write file data (with blob reference)
- `close` - Close file handle
- `rename` - Rename/move file
- `delete` - Delete file
- `mkdir` - Create directory
- `rmdir` - Remove directory
- `list` - Directory enumeration
- `oplock_break_ack` - Acknowledge oplock break (recorded from PCAP)
- `oplock_break_notification` - Server-initiated (for reference)
- `tree_disconnect` - Disconnect from share
- `logoff` - End session

**Blob Storage:**
```
workload/
├── workload.json          # Main IR file
└── blobs/
    ├── abc123...bin       # Write data (content-addressed)
    ├── def456...bin
    └── ...
```

---

## Data Flow

### Compilation Phase

```
Customer PCAP (5 GB)
  ↓
[Stream Reader] (read packet-by-packet, not all at once)
  ↓
[BPF Filter] (tcp port 445, reduce to SMB traffic only)
  ↓
[TCP Reassembler] (reconstruct SMB messages from segments)
  ↓
[SMB Parser] (dissect SMB2/3 protocol)
  ↓
[State Machine] (track sessions, trees, files, oplocks)
  ↓
[Operation Extractor] (convert packets → operations)
  ↓
[Dependency Analyzer] (build operation graph)
  ↓
[Logical Clock Assigner] (Jepsen-inspired timing)
  ↓
[IR Generator] (serialize to JSON)
  ↓
Workload IR + Blobs
```

### Replay Phase

```
Workload IR
  ↓
[IR Loader] (deserialize JSON with serde)
  ↓
[Environment Mapper] (map paths, users to lab)
  ↓
[Provisioner] (create AD users, directories)
  ↓
[Tokio Runtime Initialization]
  ↓
[Client Pool Creation] (5000 smb-rs clients)
  ↓
[Timeline Scheduler] (priority queue by logical_clock)
  ↓
┌─────────────────────────────────────────────┐
│  Spawn 5000 tokio tasks (one per client)   │
│  Each task:                                 │
│    1. Wait for operation time               │
│    2. Execute SMB operation (smb-rs)        │
│    3. Handle protocol events (oplock break) │
│    4. Log metrics                           │
│    5. Schedule next operation               │
└─────────────────────────────────────────────┘
  ↓
[Metrics Collector] (aggregate results)
  ↓
Results (JSON, Prometheus metrics, logs)
```

---

## Workload IR Schema

### Core Types (Rust)

```rust
// ir/schema.rs

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkloadIR {
    pub version: u32,
    pub metadata: Metadata,
    pub clients: Vec<ClientInfo>,
    pub shares: Vec<ShareInfo>,
    pub operations: Vec<Operation>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Metadata {
    pub source_pcap: String,
    pub compile_time: String,
    pub duration_seconds: f64,
    pub total_operations: usize,
    pub client_count: usize,
    pub compiler_version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientInfo {
    pub client_id: String,
    pub source_ip: String,
    pub username: String,
    pub session_id: String,
    pub operation_count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ShareInfo {
    pub share_path: String,
    pub tree_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Operation {
    SessionSetup {
        op_id: String,
        client_id: String,
        logical_clock: u64,
        timestamp_us: u64,
        wall_time: String,
        session_id: String,
        username: String,
        auth_type: String,
    },
    
    TreeConnect {
        op_id: String,
        client_id: String,
        logical_clock: u64,
        timestamp_us: u64,
        wall_time: String,
        tree_id: String,
        share_path: String,
    },
    
    Open {
        op_id: String,
        client_id: String,
        logical_clock: u64,
        timestamp_us: u64,
        wall_time: String,
        tree_id: String,
        path: String,
        handle_ref: String,
        disposition: String,
        access_mask: String,
        share_mode: String,
        create_options: String,
        protocol_details: ProtocolDetails,
        response: Option<OpenResponse>,
        triggers_oplock_break: bool,
        breaks_oplock_for: Vec<String>,
        dependencies: Vec<String>,
    },
    
    Write {
        op_id: String,
        client_id: String,
        logical_clock: u64,
        timestamp_us: u64,
        wall_time: String,
        handle_ref: String,
        offset: u64,
        length: u64,
        blob: BlobReference,
        dependencies: Vec<String>,
    },
    
    Read {
        op_id: String,
        client_id: String,
        logical_clock: u64,
        timestamp_us: u64,
        wall_time: String,
        handle_ref: String,
        offset: u64,
        length: u64,
        dependencies: Vec<String>,
    },
    
    Close {
        op_id: String,
        client_id: String,
        logical_clock: u64,
        timestamp_us: u64,
        wall_time: String,
        handle_ref: String,
        dependencies: Vec<String>,
    },
    
    OplockBreakAck {
        op_id: String,
        client_id: String,
        logical_clock: u64,
        timestamp_us: u64,
        wall_time: String,
        handle_ref: String,
        new_oplock_level: String,
        triggered_by: String,
        dependencies: Vec<String>,
    },
    
    Rename {
        op_id: String,
        client_id: String,
        logical_clock: u64,
        timestamp_us: u64,
        wall_time: String,
        tree_id: String,
        source_path: String,
        dest_path: String,
        replace_if_exists: bool,
        dependencies: Vec<String>,
    },
    
    Delete {
        op_id: String,
        client_id: String,
        logical_clock: u64,
        timestamp_us: u64,
        wall_time: String,
        tree_id: String,
        path: String,
        dependencies: Vec<String>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProtocolDetails {
    pub requested_oplock_level: Option<String>,
    pub create_contexts: Vec<CreateContext>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateContext {
    pub context_type: String,  // "LEASE", "DURABLE_HANDLE", etc.
    pub data: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenResponse {
    pub granted_oplock_level: Option<String>,
    pub create_action: String,
    pub file_attributes: String,
    pub file_size: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlobReference {
    pub sha256: String,
    pub path: String,
    pub size: u64,
}
```

---

## PCAP Compiler

### Architecture

**Input:** Customer PCAP (may contain multiple protocols)  
**Output:** Workload IR (SMB operations only)

### Compilation Pipeline

#### Stage 1: Packet Streaming
```python
def stream_packets(pcap_file: str) -> Iterator[Packet]:
    """Stream PCAP without loading into memory"""
    import pyshark
    
    cap = pyshark.FileCapture(
        pcap_file,
        display_filter='smb2',  # Filter to SMB only
        use_json=True,
        include_raw=True
    )
    
    for pkt in cap:
        yield pkt
```

#### Stage 2: TCP Stream Reassembly
```python
class TCPStreamReassembler:
    """Reassemble SMB messages from TCP segments"""
    
    def __init__(self):
        self.streams = {}  # (src_ip, dst_ip, src_port, dst_port) → buffer
        
    def add_packet(self, tcp_pkt):
        stream_key = (tcp_pkt.ip.src, tcp_pkt.ip.dst, 
                      tcp_pkt.tcp.srcport, tcp_pkt.tcp.dstport)
        
        stream = self.streams.setdefault(stream_key, TCPStream())
        stream.add_segment(tcp_pkt.tcp.seq, tcp_pkt.tcp.payload)
        
        # Yield complete SMB messages
        for smb_msg in stream.get_complete_messages():
            yield smb_msg
```

#### Stage 3: SMB Protocol Parsing
```python
def parse_smb_packet(smb_data: bytes) -> SMBPacket:
    """Parse SMB2/3 packet structure"""
    # NetBIOS header (4 bytes)
    netbios_header = smb_data[0:4]
    
    # SMB2 header (64 bytes)
    smb2_header = smb_data[4:68]
    
    # Extract fields
    protocol_id = smb2_header[0:4]  # Should be 0xFE534D42 (SMB2)
    header_length = struct.unpack('<H', smb2_header[4:6])[0]
    command = struct.unpack('<H', smb2_header[12:14])[0]
    message_id = struct.unpack('<Q', smb2_header[24:32])[0]
    session_id = struct.unpack('<Q', smb2_header[32:40])[0]
    tree_id = struct.unpack('<I', smb2_header[36:40])[0]
    
    # Command-specific parsing
    if command == SMB2_CREATE:
        return parse_create_request(smb_data[68:])
    elif command == SMB2_WRITE:
        return parse_write_request(smb_data[68:])
    # ... etc
```

#### Stage 4: State Machine

```python
class SMBStateMachine:
    """Track protocol state across packets"""
    
    def __init__(self):
        self.sessions = {}
        self.trees = {}
        self.opens = {}
        self.oplocks = {}  # Track oplock state
        
    def process_packet(self, pkt: SMBPacket) -> Optional[Operation]:
        """Convert packet to operation, maintaining state"""
        
        if pkt.command == SMB2_CREATE:
            # Track file open
            file_id = pkt.file_id
            path = self.resolve_path(pkt.tree_id, pkt.filename)
            
            self.opens[file_id] = OpenFile(
                path=path,
                session=self.sessions[pkt.session_id],
                tree=self.trees[pkt.tree_id],
            )
            
            # Track oplock request
            if pkt.oplock_level:
                self.oplocks[file_id] = OplockState(
                    level=pkt.oplock_level,
                    client=pkt.session_id,
                    path=path
                )
            
            return OpenOperation(...)
            
        elif pkt.command == SMB2_OPLOCK_BREAK:
            # Server initiated oplock break
            file_id = pkt.file_id
            return OplockBreakNotification(...)
```

#### Stage 5: Dependency Analysis

```python
class DependencyAnalyzer:
    """Build operation dependency graph"""
    
    def analyze(self, operations: List[Operation]) -> List[Operation]:
        """Add dependency information to operations"""
        
        handle_ops = {}  # handle_ref → [operations]
        path_ops = {}    # path → [operations]
        
        for op in operations:
            # Add dependencies based on:
            # 1. Handle lifecycle (open → write → close)
            if op.type == "write":
                # Depends on open
                open_op = handle_ops[op.handle_ref][0]
                op.dependencies.append(open_op.op_id)
                
            # 2. File path conflicts (oplock breaks)
            if op.type == "open" and op.path in path_ops:
                # Check if triggers oplock break
                existing_opens = path_ops[op.path]
                for existing in existing_opens:
                    if existing.oplock_level == "EXCLUSIVE":
                        op.triggers_oplock_break = True
                        op.breaks_oplock_for.append(existing.op_id)
            
            # Track operation
            if hasattr(op, 'handle_ref'):
                handle_ops.setdefault(op.handle_ref, []).append(op)
            if hasattr(op, 'path'):
                path_ops.setdefault(op.path, []).append(op)
        
        return operations
```

#### Stage 6: Logical Clock Assignment

```python
class LogicalClockAssigner:
    """Assign logical clocks (Jepsen-inspired)"""
    
    def assign(self, operations: List[Operation]) -> List[Operation]:
        """
        Logical clock preserves causality while allowing time scaling.
        
        Rules:
        1. Operations on same client are ordered by PCAP timestamp
        2. Dependencies create happens-before relationships
        3. Oplock breaks create cross-client ordering
        """
        
        # Sort by client_id, then timestamp
        ops_by_client = defaultdict(list)
        for op in operations:
            ops_by_client[op.client_id].append(op)
        
        logical_clock = 0
        for client_id in sorted(ops_by_client.keys()):
            for op in sorted(ops_by_client[client_id], key=lambda x: x.timestamp_us):
                # Assign logical clock
                op.logical_clock = logical_clock
                logical_clock += 1
                
                # Adjust for dependencies
                if op.dependencies:
                    max_dep_clock = max(
                        find_op(dep).logical_clock 
                        for dep in op.dependencies
                    )
                    op.logical_clock = max(op.logical_clock, max_dep_clock + 1)
        
        return operations
```

---

## Replay Engine (Rust)

### Main Architecture

```rust
// src/main.rs

use clap::Parser;
use tokio::runtime::Runtime;
use std::sync::Arc;

#[derive(Parser)]
#[clap(name = "smbench")]
#[clap(about = "SMB3 Workload Replay Engine", version)]
struct Args {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Parser)]
enum Command {
    /// Replay workload from IR
    Replay {
        /// Path to workload IR file
        #[clap(value_name = "IR_FILE")]
        ir_file: String,
        
        /// Mapping configuration
        #[clap(short, long, value_name = "CONFIG")]
        config: String,
        
        /// Time scale multiplier (1.0 = original speed)
        #[clap(long, default_value = "1.0")]
        time_scale: f64,
        
        /// Enable metrics export
        #[clap(long)]
        metrics: bool,
        
        /// Output directory for logs/metrics
        #[clap(short, long, default_value = "results/")]
        output: String,
    },
    
    /// Provision environment (create users, directories)
    Provision {
        #[clap(value_name = "IR_FILE")]
        ir_file: String,
        
        #[clap(short, long)]
        config: String,
    },
    
    /// Analyze replay results
    Analyze {
        #[clap(value_name = "RESULTS_DIR")]
        results_dir: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    let args = Args::parse();
    
    match args.command {
        Command::Replay { ir_file, config, time_scale, metrics, output } => {
            replay_workload(ir_file, config, time_scale, metrics, output).await?;
        },
        Command::Provision { ir_file, config } => {
            provision_environment(ir_file, config).await?;
        },
        Command::Analyze { results_dir } => {
            analyze_results(results_dir)?;
        },
    }
    
    Ok(())
}
```

### IR Loader

```rust
// src/ir/loader.rs

use serde_json;
use std::fs;
use std::path::Path;

pub struct IRLoader;

impl IRLoader {
    pub fn load(ir_path: &str) -> Result<WorkloadIR, Box<dyn std::error::Error>> {
        let contents = fs::read_to_string(ir_path)?;
        let ir: WorkloadIR = serde_json::from_str(&contents)?;
        
        // Validate IR
        Self::validate(&ir)?;
        
        Ok(ir)
    }
    
    fn validate(ir: &WorkloadIR) -> Result<(), String> {
        // Check version compatibility
        if ir.version != 1 {
            return Err(format!("Unsupported IR version: {}", ir.version));
        }
        
        // Check operation dependencies exist
        let op_ids: HashSet<_> = ir.operations.iter()
            .map(|op| op.op_id())
            .collect();
            
        for op in &ir.operations {
            for dep in op.dependencies() {
                if !op_ids.contains(dep) {
                    return Err(format!("Missing dependency: {}", dep));
                }
            }
        }
        
        Ok(())
    }
    
    pub fn load_blob(&self, blob_ref: &BlobReference) -> Result<Vec<u8>, std::io::Error> {
        fs::read(&blob_ref.path)
    }
}
```

### Environment Mapper

```rust
// src/mapper.rs

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct MappingConfig {
    pub server: String,
    pub share: String,
    pub path_mappings: Vec<PathMapping>,
    pub user_mappings: Vec<UserMapping>,
}

#[derive(Debug, Deserialize)]
pub struct PathMapping {
    pub source: String,  // "\\\\customer-fs01\\sales"
    pub target: String,  // "\\\\lab-files\\testshare\\sales"
}

#[derive(Debug, Deserialize)]
pub struct UserMapping {
    pub source: String,  // "jsmith@customer.com"
    pub target: String,  // "testuser001@lab.local"
    pub password: String,
}

pub struct EnvironmentMapper {
    config: MappingConfig,
    path_cache: HashMap<String, String>,
}

impl EnvironmentMapper {
    pub fn new(config: MappingConfig) -> Self {
        Self {
            config,
            path_cache: HashMap::new(),
        }
    }
    
    pub fn map_path(&mut self, source_path: &str) -> String {
        // Check cache
        if let Some(mapped) = self.path_cache.get(source_path) {
            return mapped.clone();
        }
        
        // Apply mappings
        let mut mapped = source_path.to_string();
        for mapping in &self.config.path_mappings {
            if mapped.starts_with(&mapping.source) {
                mapped = mapped.replace(&mapping.source, &mapping.target);
                break;
            }
        }
        
        self.path_cache.insert(source_path.to_string(), mapped.clone());
        mapped
    }
    
    pub fn map_user(&self, source_user: &str) -> Option<&UserMapping> {
        self.config.user_mappings.iter()
            .find(|m| m.source == source_user)
    }
}
```

---

## Replay Engine

### Main Replay Loop

```rust
// src/engine/mod.rs

use smb::{Client, ClientConfig, UncPath};
use tokio::time::{sleep_until, Instant, Duration};
use tokio::sync::{mpsc, Semaphore};
use std::sync::Arc;
use std::collections::HashMap;

pub struct ReplayEngine {
    workload: WorkloadIR,
    mapper: EnvironmentMapper,
    time_scale: f64,
    metrics: Arc<MetricsCollector>,
}

impl ReplayEngine {
    pub fn new(
        workload: WorkloadIR,
        mapper: EnvironmentMapper,
        time_scale: f64,
    ) -> Self {
        Self {
            workload,
            mapper,
            time_scale,
            metrics: Arc::new(MetricsCollector::new()),
        }
    }
    
    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // 1. Create SMB client pool
        let clients = self.create_client_pool().await?;
        
        // 2. Group operations by client
        let operations_by_client = self.group_operations_by_client();
        
        // 3. Create coordination channels
        let (oplock_tx, oplock_rx) = mpsc::channel(1000);
        
        // 4. Spawn client replay tasks
        let mut tasks = Vec::new();
        let start_time = Instant::now();
        
        for (client_id, client) in clients {
            let ops = operations_by_client.get(&client_id).cloned()
                .unwrap_or_default();
            let oplock_tx = oplock_tx.clone();
            let metrics = Arc::clone(&self.metrics);
            let time_scale = self.time_scale;
            
            let task = tokio::spawn(async move {
                let mut executor = ClientExecutor::new(
                    client,
                    ops,
                    start_time,
                    time_scale,
                    oplock_tx,
                    metrics,
                );
                executor.run().await
            });
            
            tasks.push(task);
        }
        
        // 5. Spawn oplock coordinator task
        let oplock_task = tokio::spawn(async move {
            coordinate_oplocks(oplock_rx).await
        });
        tasks.push(oplock_task);
        
        // 6. Wait for all tasks to complete
        for task in tasks {
            task.await??;
        }
        
        // 7. Export metrics
        self.metrics.export("results/metrics.json")?;
        
        Ok(())
    }
    
    async fn create_client_pool(&self) -> Result<HashMap<String, Arc<Client>>, Box<dyn std::error::Error>> {
        let mut clients = HashMap::new();
        
        for client_info in &self.workload.clients {
            // Map user to test environment
            let user_mapping = self.mapper.map_user(&client_info.username)
                .ok_or("User mapping not found")?;
            
            // Create SMB client
            let client = Client::new(ClientConfig::default());
            
            // Connect to share
            let share_path = format!(r"\\{}\{}", 
                self.mapper.config.server,
                self.mapper.config.share
            );
            let unc_path = UncPath::from_str(&share_path)?;
            
            client.share_connect(
                &unc_path,
                &user_mapping.target,
                user_mapping.password.clone()
            ).await?;
            
            clients.insert(client_info.client_id.clone(), Arc::new(client));
        }
        
        Ok(clients)
    }
    
    fn group_operations_by_client(&self) -> HashMap<String, Vec<Operation>> {
        let mut grouped = HashMap::new();
        
        for op in &self.workload.operations {
            grouped.entry(op.client_id().to_string())
                .or_insert_with(Vec::new)
                .push(op.clone());
        }
        
        // Sort each client's operations by logical clock
        for ops in grouped.values_mut() {
            ops.sort_by_key(|op| op.logical_clock());
        }
        
        grouped
    }
}
```

### Client Executor

```rust
// src/engine/executor.rs

use smb::Client;
use tokio::time::{sleep_until, Instant, Duration};
use tokio::sync::mpsc;
use std::sync::Arc;
use std::collections::HashMap;

pub struct ClientExecutor {
    client: Arc<Client>,
    operations: Vec<Operation>,
    start_time: Instant,
    time_scale: f64,
    oplock_channel: mpsc::Sender<OplockEvent>,
    metrics: Arc<MetricsCollector>,
    file_handles: HashMap<String, FileHandle>,
}

impl ClientExecutor {
    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        for op in &self.operations {
            // Calculate target execution time
            let delay_us = (op.timestamp_us() as f64 * self.time_scale) as u64;
            let target_time = self.start_time + Duration::from_micros(delay_us);
            
            // Wait until operation time
            sleep_until(target_time).await;
            
            // Execute operation
            let exec_start = Instant::now();
            let result = self.execute_operation(op).await;
            let latency = exec_start.elapsed();
            
            // Record metrics
            self.metrics.record_operation(
                op.op_id(),
                op.operation_type(),
                latency,
                result.is_ok()
            );
            
            // Handle result
            match result {
                Ok(_) => {
                    tracing::info!(
                        op_id = op.op_id(),
                        op_type = op.operation_type(),
                        latency_ms = latency.as_millis(),
                        "Operation succeeded"
                    );
                },
                Err(e) => {
                    tracing::error!(
                        op_id = op.op_id(),
                        op_type = op.operation_type(),
                        error = %e,
                        "Operation failed"
                    );
                    
                    // Decide: retry, skip, or abort?
                    self.handle_error(&e, op).await?;
                }
            }
        }
        
        Ok(())
    }
    
    async fn execute_operation(&mut self, op: &Operation) -> Result<(), Box<dyn std::error::Error>> {
        match op {
            Operation::Open { path, handle_ref, disposition, access_mask, protocol_details, .. } => {
                let mapped_path = self.map_path(path);
                
                // Build FileCreateArgs with oplock request
                let mut args = self.build_create_args(disposition, access_mask);
                
                // Add create contexts (oplocks, leases, durable handles)
                if let Some(details) = protocol_details {
                    args = self.add_create_contexts(args, details);
                }
                
                // Execute open
                let file = self.client.create_file(&mapped_path, &args).await?;
                
                // Store handle for later operations
                self.file_handles.insert(handle_ref.clone(), file);
                
                // Check if oplock/lease granted
                // (smb-rs should expose this in response)
                
                Ok(())
            },
            
            Operation::Write { handle_ref, offset, blob, .. } => {
                let file = self.file_handles.get(handle_ref)
                    .ok_or("File handle not found")?;
                
                // Load blob data
                let data = self.load_blob(blob)?;
                
                // Execute write
                file.write_at(&data, *offset).await?;
                
                Ok(())
            },
            
            Operation::Read { handle_ref, offset, length, .. } => {
                let file = self.file_handles.get(handle_ref)
                    .ok_or("File handle not found")?;
                
                // Execute read
                let mut buffer = vec![0u8; *length as usize];
                file.read_at(&mut buffer, *offset).await?;
                
                // Optionally validate read data
                
                Ok(())
            },
            
            Operation::Close { handle_ref, .. } => {
                let file = self.file_handles.remove(handle_ref)
                    .ok_or("File handle not found")?;
                
                file.close().await?;
                
                Ok(())
            },
            
            Operation::Rename { source_path, dest_path, .. } => {
                let src = self.map_path(source_path);
                let dst = self.map_path(dest_path);
                
                // TODO: smb-rs rename operation
                // self.client.rename(&src, &dst).await?;
                
                Ok(())
            },
            
            Operation::OplockBreakAck { handle_ref, new_oplock_level, .. } => {
                // Handle oplock break acknowledgment
                // This is reactive - server sent break, we ACK
                
                let file = self.file_handles.get(handle_ref)
                    .ok_or("File handle not found")?;
                
                // TODO: smb-rs oplock break ACK
                // file.acknowledge_oplock_break(new_oplock_level).await?;
                
                // Notify oplock coordinator
                self.oplock_channel.send(OplockEvent::AckSent {
                    op_id: op.op_id().to_string(),
                    handle: handle_ref.clone(),
                }).await?;
                
                Ok(())
            },
            
            _ => {
                tracing::warn!("Unimplemented operation type");
                Ok(())
            }
        }
    }
    
    fn build_create_args(&self, disposition: &str, access_mask: &str) -> FileCreateArgs {
        // Convert IR strings to smb-rs types
        let disposition = match disposition {
            "open_existing" => CreateDisposition::OpenExisting,
            "open_or_create" => CreateDisposition::OpenOrCreate,
            "create_new" => CreateDisposition::CreateNew,
            "overwrite" => CreateDisposition::Overwrite,
            _ => CreateDisposition::OpenExisting,
        };
        
        // Parse access mask (hex string → flags)
        let access = self.parse_access_mask(access_mask);
        
        FileCreateArgs::new(disposition, access)
    }
    
    fn add_create_contexts(&self, mut args: FileCreateArgs, details: &ProtocolDetails) -> FileCreateArgs {
        // Add oplock request
        if let Some(oplock_level) = &details.requested_oplock_level {
            // TODO: smb-rs API for oplock request
            // args = args.with_oplock(parse_oplock_level(oplock_level));
        }
        
        // Add create contexts (lease, durable handle)
        for ctx in &details.create_contexts {
            match ctx.context_type.as_str() {
                "SMB2_CREATE_REQUEST_LEASE" => {
                    // TODO: args = args.with_lease(...);
                },
                "SMB2_CREATE_DURABLE_HANDLE_REQUEST" => {
                    // TODO: args = args.with_durable_handle(...);
                },
                _ => {}
            }
        }
        
        args
    }
    
    fn map_path(&self, path: &str) -> String {
        // Apply path mapping from config
        // This is set during initialization
        path.to_string()  // Simplified
    }
    
    fn load_blob(&self, blob_ref: &BlobReference) -> Result<Vec<u8>, std::io::Error> {
        std::fs::read(&blob_ref.path)
    }
    
    async fn handle_error(&self, error: &dyn std::error::Error, op: &Operation) -> Result<(), Box<dyn std::error::Error>> {
        // Error classification and retry logic
        let error_str = error.to_string();
        
        if error_str.contains("STATUS_SHARING_VIOLATION") {
            // Retry with backoff
            tokio::time::sleep(Duration::from_millis(500)).await;
            return Ok(());  // Retry will happen
        } else if error_str.contains("STATUS_NOT_FOUND") {
            // File doesn't exist, skip
            tracing::warn!("File not found, skipping operation");
            return Ok(());
        } else {
            // Fatal error
            return Err(error.into());
        }
    }
}
```

---

## Multi-Client Coordination

### Scheduler Design (Jepsen-Inspired)

```rust
// src/scheduler/mod.rs

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use tokio::time::{Instant, Duration, sleep_until};

#[derive(Debug)]
pub struct ScheduledOp {
    pub execute_at: Instant,
    pub logical_clock: u64,
    pub client_id: String,
    pub operation: Operation,
}

// Priority queue ordering: by execute_at, then logical_clock
impl Ord for ScheduledOp {
    fn cmp(&self, other: &Self) -> Ordering {
        other.execute_at.cmp(&self.execute_at)
            .then_with(|| other.logical_clock.cmp(&self.logical_clock))
    }
}

impl PartialOrd for ScheduledOp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for ScheduledOp {
    fn eq(&self, other: &Self) -> bool {
        self.execute_at == other.execute_at && self.logical_clock == other.logical_clock
    }
}

impl Eq for ScheduledOp {}

pub struct TimelineScheduler {
    heap: BinaryHeap<ScheduledOp>,
    start_time: Instant,
    time_scale: f64,
}

impl TimelineScheduler {
    pub fn new(start_time: Instant, time_scale: f64) -> Self {
        Self {
            heap: BinaryHeap::new(),
            start_time,
            time_scale,
        }
    }
    
    pub fn schedule(&mut self, op: Operation) {
        let delay_us = (op.timestamp_us() as f64 * self.time_scale) as u64;
        let execute_at = self.start_time + Duration::from_micros(delay_us);
        
        self.heap.push(ScheduledOp {
            execute_at,
            logical_clock: op.logical_clock(),
            client_id: op.client_id().to_string(),
            operation: op,
        });
    }
    
    pub async fn get_next(&mut self) -> Option<ScheduledOp> {
        if let Some(op) = self.heap.pop() {
            // Wait until operation time
            let now = Instant::now();
            if op.execute_at > now {
                sleep_until(op.execute_at).await;
            }
            
            Some(op)
        } else {
            None
        }
    }
}
```

### Per-Client Task Pattern

**Each client runs in independent tokio task:**

```rust
// src/engine/client_task.rs

pub async fn run_client_replay(
    client: Arc<Client>,
    operations: Vec<Operation>,
    start_time: Instant,
    time_scale: f64,
    oplock_channel: mpsc::Sender<OplockEvent>,
    metrics: Arc<MetricsCollector>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut file_handles = HashMap::new();
    
    for op in operations {
        // Calculate execution time
        let delay_us = (op.timestamp_us() as f64 * time_scale) as u64;
        let target_time = start_time + Duration::from_micros(delay_us);
        
        // Wait (preserves PCAP timing)
        sleep_until(target_time).await;
        
        // Execute operation
        let result = execute_op(
            &client,
            &op,
            &mut file_handles,
            &oplock_channel
        ).await;
        
        // Record metrics
        metrics.record(op, result);
    }
    
    Ok(())
}
```

**Key aspects:**
- ✅ Each client is isolated (own task, own file handles)
- ✅ Timeline preserved (sleep_until)
- ✅ Concurrent execution (all tasks run in parallel)
- ✅ Oplock coordination via channels

---

## Oplock & Lease Handling

### Hybrid Protocol Model

**Challenge:** PCAP shows client operations, but server responses happen at runtime.

**Solution:** Combine scheduled operations (from PCAP) with reactive protocol handling (runtime).

### Architecture

```rust
// src/protocol/oplock_handler.rs

use tokio::sync::mpsc;
use std::collections::HashMap;

pub enum OplockEvent {
    /// Server sent oplock break (runtime)
    BreakReceived {
        file_handle: String,
        new_level: String,
        timestamp: Instant,
    },
    
    /// Client acknowledged break (from PCAP or reactive)
    AckSent {
        op_id: String,
        handle: String,
    },
    
    /// Oplock granted (from server response)
    Granted {
        op_id: String,
        handle: String,
        level: String,
    },
}

pub struct OplockCoordinator {
    /// Track active oplocks across all clients
    active_oplocks: HashMap<String, OplockState>,
    
    /// Receive events from client tasks
    event_rx: mpsc::Receiver<OplockEvent>,
}

#[derive(Debug)]
pub struct OplockState {
    pub client_id: String,
    pub file_handle: String,
    pub path: String,
    pub level: String,
    pub granted_at: Instant,
}

impl OplockCoordinator {
    pub async fn run(mut self) -> Result<(), Box<dyn std::error::Error>> {
        while let Some(event) = self.event_rx.recv().await {
            match event {
                OplockEvent::Granted { op_id, handle, level } => {
                    // Track new oplock
                    self.active_oplocks.insert(handle.clone(), OplockState {
                        client_id: op_id.clone(),
                        file_handle: handle,
                        path: "".to_string(),  // Resolve from operation
                        level,
                        granted_at: Instant::now(),
                    });
                    
                    tracing::info!(
                        op_id = op_id,
                        level = level,
                        "Oplock granted"
                    );
                },
                
                OplockEvent::BreakReceived { file_handle, new_level, timestamp } => {
                    // Server broke an oplock
                    if let Some(oplock) = self.active_oplocks.get_mut(&file_handle) {
                        tracing::warn!(
                            handle = file_handle,
                            old_level = oplock.level,
                            new_level = new_level,
                            "Oplock break received from server"
                        );
                        
                        oplock.level = new_level;
                    }
                },
                
                OplockEvent::AckSent { op_id, handle } => {
                    // Client acknowledged oplock break
                    tracing::info!(
                        op_id = op_id,
                        handle = handle,
                        "Oplock break acknowledged"
                    );
                },
            }
        }
        
        Ok(())
    }
}
```

### Oplock Break Handling (Runtime)

**From PCAP, we know:**
- Client A has oplock on file.txt
- Client B opens file.txt at T+1.0s
- Server will send oplock break to Client A
- Client A must acknowledge

**In replay:**

```rust
// Client A's task
async fn handle_oplock_break_if_needed(
    client: &Client,
    file_handle: &FileHandle,
    oplock_rx: &mut mpsc::Receiver<OplockBreak>
) -> Result<(), Error> {
    // Check if server sent oplock break (non-blocking)
    if let Ok(break_msg) = oplock_rx.try_recv() {
        // Server sent break (not in PCAP timeline!)
        // Must respond immediately
        
        tracing::warn!("Received oplock break from server (runtime)");
        
        // Send acknowledgment
        file_handle.acknowledge_oplock_break(break_msg.new_level).await?;
        
        tracing::info!("Oplock break acknowledged");
    }
    
    Ok(())
}

// Integrate with operation execution
async fn execute_with_oplock_handling(
    op: &Operation,
    client: &Client,
    oplock_rx: &mut mpsc::Receiver<OplockBreak>
) -> Result<(), Error> {
    // Before each operation, check for oplock breaks
    handle_oplock_break_if_needed(client, oplock_rx).await?;
    
    // Execute scheduled operation
    execute_operation(op, client).await?;
    
    Ok(())
}
```

**This implements the "Hybrid Model":**
- ✅ Operations scheduled from PCAP timeline
- ✅ Oplock breaks handled reactively (server-initiated)
- ✅ Preserves protocol correctness

---

## Error Handling & Retry

### Error Classification

```rust
// src/error.rs

#[derive(Debug)]
pub enum SMBError {
    /// Network/transport errors (retry)
    NetworkError(std::io::Error),
    
    /// Protocol errors
    ProtocolError {
        status_code: u32,
        message: String,
    },
    
    /// Application errors
    ApplicationError(String),
}

impl SMBError {
    pub fn from_status_code(status: u32) -> Self {
        match status {
            0xC0000043 => Self::ProtocolError {
                status_code: status,
                message: "STATUS_SHARING_VIOLATION".to_string(),
            },
            0xC0000034 => Self::ProtocolError {
                status_code: status,
                message: "STATUS_NOT_FOUND".to_string(),
            },
            0xC00000BA => Self::ProtocolError {
                status_code: status,
                message: "STATUS_FILE_LOCK_CONFLICT".to_string(),
            },
            _ => Self::ProtocolError {
                status_code: status,
                message: format!("Unknown status: 0x{:08X}", status),
            },
        }
    }
    
    pub fn is_retriable(&self) -> bool {
        match self {
            Self::NetworkError(_) => true,
            Self::ProtocolError { status_code, .. } => {
                matches!(status_code,
                    0xC0000043 |  // STATUS_SHARING_VIOLATION
                    0xC00000BA    // STATUS_FILE_LOCK_CONFLICT
                )
            },
            Self::ApplicationError(_) => false,
        }
    }
}
```

### Retry Policy

```rust
// src/retry.rs

use tokio::time::{sleep, Duration};

pub struct RetryPolicy {
    max_attempts: u32,
    base_delay_ms: u64,
    max_delay_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay_ms: 100,
            max_delay_ms: 5000,
        }
    }
}

impl RetryPolicy {
    pub async fn execute_with_retry<F, Fut, T>(
        &self,
        mut operation: F
    ) -> Result<T, Box<dyn std::error::Error>>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, Box<dyn std::error::Error>>>,
    {
        let mut attempt = 0;
        
        loop {
            attempt += 1;
            
            match operation().await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    // Check if retriable
                    let smb_error = e.downcast_ref::<SMBError>();
                    
                    if let Some(smb_err) = smb_error {
                        if smb_err.is_retriable() && attempt < self.max_attempts {
                            // Exponential backoff
                            let delay = self.base_delay_ms * (2_u64.pow(attempt - 1));
                            let delay = delay.min(self.max_delay_ms);
                            
                            tracing::warn!(
                                attempt = attempt,
                                delay_ms = delay,
                                error = %e,
                                "Retrying operation"
                            );
                            
                            sleep(Duration::from_millis(delay)).await;
                            continue;
                        }
                    }
                    
                    // Not retriable or max attempts reached
                    return Err(e);
                }
            }
        }
    }
}
```

---

## Observability

### Metrics Collection

```rust
// src/observability/metrics.rs

use prometheus::{Registry, Counter, Histogram, Gauge, HistogramOpts};
use std::sync::Arc;

pub struct MetricsCollector {
    registry: Registry,
    
    // Counters
    operations_total: Counter,
    operations_success: Counter,
    operations_failed: Counter,
    
    // Histograms
    operation_duration: Histogram,
    oplock_break_latency: Histogram,
    
    // Gauges
    active_clients: Gauge,
    active_file_handles: Gauge,
}

impl MetricsCollector {
    pub fn new() -> Self {
        let registry = Registry::new();
        
        let operations_total = Counter::new(
            "smbench_operations_total",
            "Total SMB operations executed"
        ).unwrap();
        
        let operation_duration = Histogram::with_opts(
            HistogramOpts::new(
                "smbench_operation_duration_seconds",
                "SMB operation latency"
            ).buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0])
        ).unwrap();
        
        let active_clients = Gauge::new(
            "smbench_active_clients",
            "Number of active SMB clients"
        ).unwrap();
        
        registry.register(Box::new(operations_total.clone())).unwrap();
        registry.register(Box::new(operation_duration.clone())).unwrap();
        registry.register(Box::new(active_clients.clone())).unwrap();
        
        Self {
            registry,
            operations_total,
            operations_success: Counter::new("success", "").unwrap(),
            operations_failed: Counter::new("failed", "").unwrap(),
            operation_duration,
            oplock_break_latency: Histogram::with_opts(HistogramOpts::new("", "")).unwrap(),
            active_clients,
            active_file_handles: Gauge::new("", "").unwrap(),
        }
    }
    
    pub fn record_operation(
        &self,
        op_id: &str,
        op_type: &str,
        latency: Duration,
        success: bool
    ) {
        self.operations_total.inc();
        
        if success {
            self.operations_success.inc();
        } else {
            self.operations_failed.inc();
        }
        
        self.operation_duration.observe(latency.as_secs_f64());
    }
    
    pub fn export_prometheus(&self, port: u16) -> Result<(), Box<dyn std::error::Error>> {
        // Start Prometheus exporter on :9090
        use prometheus::Encoder;
        use tiny_http::{Server, Response};
        
        let server = Server::http(format!("0.0.0.0:{}", port)).unwrap();
        
        for request in server.incoming_requests() {
            let mut buffer = Vec::new();
            let encoder = prometheus::TextEncoder::new();
            let metric_families = self.registry.gather();
            encoder.encode(&metric_families, &mut buffer).unwrap();
            
            let response = Response::from_data(buffer);
            request.respond(response).unwrap();
        }
        
        Ok(())
    }
}
```

### Structured Logging

```rust
// src/observability/logging.rs

use tracing::{info, warn, error, debug};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub fn init_logging() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().json())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();
}

// Usage in code
#[instrument]
pub async fn execute_operation(op: &Operation) -> Result<(), Error> {
    info!(
        op_id = op.op_id(),
        op_type = op.operation_type(),
        client_id = op.client_id(),
        "Executing operation"
    );
    
    let result = match op {
        Operation::Open { .. } => execute_open(op).await,
        Operation::Write { .. } => execute_write(op).await,
        _ => Ok(()),
    };
    
    if let Err(e) = &result {
        error!(
            op_id = op.op_id(),
            error = %e,
            "Operation failed"
        );
    }
    
    result
}
```

---

## Deployment

### Container Strategy

**Dockerfile:**
```dockerfile
# Stage 1: Build
FROM rust:1.75-slim as builder

WORKDIR /app

# Copy dependency manifests
COPY Cargo.toml Cargo.lock ./

# Cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -rf src

# Copy source code
COPY src ./src

# Build application
RUN cargo build --release

# Stage 2: Runtime
FROM debian:bookworm-slim

# Install minimal dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy binary
COPY --from=builder /app/target/release/smbench /usr/local/bin/smbench

# Create workload directory
RUN mkdir -p /workloads /results

# Non-root user
RUN useradd -m -u 1000 smbench
USER smbench

ENTRYPOINT ["smbench"]
CMD ["--help"]
```

**Image size:** ~50-100 MB (vs. 4-10 GB for Windows)

### Running

```bash
# Single execution
docker run --rm \
    -v $(pwd)/workloads:/workloads \
    -v $(pwd)/results:/results \
    --network host \
    smbench:latest replay \
        /workloads/customer_workload.json \
        --config /workloads/mapping.yaml \
        --time-scale 1.0 \
        --output /results

# Load testing (5000 users)
docker run --rm \
    -v $(pwd)/workloads:/workloads \
    -v $(pwd)/results:/results \
    --network host \
    -m 8G \
    --cpus 4 \
    smbench:latest replay \
        /workloads/scaled_5000_users.json \
        --config /workloads/mapping.yaml \
        --metrics \
        --output /results
```

### Kubernetes Deployment (Optional)

```yaml
# k8s/deployment.yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: smbench-replay
spec:
  template:
    spec:
      containers:
      - name: smbench
        image: smbench:latest
        args:
          - replay
          - /workloads/workload.json
          - --config
          - /config/mapping.yaml
        volumeMounts:
          - name: workloads
            mountPath: /workloads
          - name: config
            mountPath: /config
          - name: results
            mountPath: /results
        resources:
          requests:
            memory: "4Gi"
            cpu: "2"
          limits:
            memory: "8Gi"
            cpu: "4"
      volumes:
        - name: workloads
          persistentVolumeClaim:
            claimName: workloads-pvc
        - name: config
          configMap:
            name: smbench-config
        - name: results
          persistentVolumeClaim:
            claimName: results-pvc
      restartPolicy: Never
```

---

## Implementation Phases

### Phase 0: Technology Validation (Weeks 1-2)

**Goal:** Validate smb-rs + tokio for SMB replay

**Deliverables:**
- [ ] Minimal Rust program connecting to SMB share
- [ ] Test oplock request/acknowledgment
- [ ] Test with 100 concurrent connections
- [ ] Measure memory per connection
- [ ] Parse simple PCAP (Python) → IR
- [ ] Load IR in Rust, execute 10 operations

**Success Criteria:**
- smb-rs can request oplocks
- Tokio handles 100 concurrent clients
- Memory < 1 MB per client
- IR schema works

**Decision Point:** If smb-rs has oplock gaps, evaluate alternatives.

---

### Phase 1: Core Engine (Weeks 3-6)

**Goal:** Build replay engine for single-client workloads

**Deliverables:**
- [ ] IR schema v1 finalized (Rust structs)
- [ ] IR loader (serde_json)
- [ ] Environment mapper (paths, users)
- [ ] Basic SMB executor (open, read, write, close)
- [ ] Timeline scheduler (tokio timers)
- [ ] PCAP compiler (Python) - basic operations
- [ ] End-to-end test: PCAP → IR → Replay (1 client, 100 ops)

**Success Criteria:**
- Replay 1 client workload with exact timing
- Handle file operations correctly
- Basic error handling and logging

---

### Phase 2: Multi-Client & Oplocks (Weeks 7-10)

**Goal:** Support multi-client coordination with oplock handling

**Deliverables:**
- [ ] Multi-client replay (spawn N tokio tasks)
- [ ] Oplock coordinator (channel-based communication)
- [ ] Oplock break handling (hybrid model)
- [ ] Dependency graph in IR
- [ ] State machine in compiler (track oplocks)
- [ ] Test: 2 clients, oplock conflict scenario
- [ ] Test: 10 clients, mixed workload

**Success Criteria:**
- Multiple clients replay simultaneously
- Oplock breaks handled correctly
- Timing preserved across clients
- No deadlocks or race conditions

---

### Phase 3: Scale & Observability (Weeks 11-14)

**Goal:** Scale to 5000 users, production observability

**Deliverables:**
- [ ] Connection pooling optimizations
- [ ] Memory profiling and optimization
- [ ] Prometheus metrics exporter
- [ ] Structured logging (tracing-rs)
- [ ] Grafana dashboards
- [ ] Test: 100 users, 10K operations
- [ ] Test: 1000 users, 100K operations
- [ ] Test: 5000 users, 1M operations

**Success Criteria:**
- 5000 concurrent users sustained for 1 hour
- Memory < 4 GB total
- Throughput > 10K ops/sec
- <1% error rate
- Real-time metrics available

---

### Phase 4: Production Hardening (Weeks 15-18)

**Goal:** Production-ready system

**Deliverables:**
- [ ] Checkpoint/resume capability
- [ ] Lease handling (SMB3)
- [ ] Durable handle reconnection
- [ ] Compound operations support
- [ ] Advanced PCAP compiler (all SMB ops)
- [ ] Comprehensive error handling
- [ ] Performance benchmarks
- [ ] Documentation
- [ ] CI/CD pipeline

**Success Criteria:**
- Replay 95% of customer PCAPs successfully
- Reproduce known bugs with >90% success rate
- Stable for 8-hour load tests
- Production deployment ready

---

## Risk Matrix

| Risk | Probability | Impact | Mitigation | Phase |
|------|-------------|--------|------------|-------|
| **smb-rs oplock support** | High | Critical | Phase 0 validation, fallback to Impacket | 0 |
| **Tokio performance at 5000 users** | Low | High | Phase 2 benchmarking | 2 |
| **PCAP compiler complexity** | Medium | High | Incremental development, test suite | 1-2 |
| **Multi-client coordination bugs** | Medium | High | Extensive testing, formal verification | 2 |
| **Memory leaks at scale** | Low | Medium | Profiling, Rust safety | 3 |
| **Team Rust expertise** | Medium | Medium | Training, pair programming | 0-1 |
| **Durable handle edge cases** | Medium | Medium | Comprehensive PCAP test suite | 4 |

---

## Success Metrics

### Development
- Phase 0: 2 weeks
- Phase 1: 4 weeks
- Phase 2: 4 weeks
- Phase 3: 4 weeks
- Phase 4: 4 weeks
- **Total: 18 weeks**

### Technical
- Replay 95% of customer PCAPs
- Support 5000 concurrent users
- <1% error rate at scale
- Memory < 1 MB per user
- Latency overhead < 10% vs. real client

### Business
- Reduce bug reproduction time from hours to minutes
- Enable multi-client bug reproduction (previously impossible)
- Support load testing at customer scale
- Actionable debugging data (logs, metrics, traces)

---

## Appendices

### Appendix A: Rust Crates

| Crate | Purpose | Version |
|-------|---------|---------|
| `smb` | SMB2/3 client | Latest |
| `tokio` | Async runtime | 1.48+ |
| `serde` | Serialization | Latest |
| `serde_json` | JSON parsing | Latest |
| `clap` | CLI parsing | Latest |
| `tracing` | Structured logging | Latest |
| `prometheus` | Metrics | Latest |
| `anyhow` | Error handling | Latest |
| `thiserror` | Error derive | Latest |

### Appendix B: Python Dependencies

| Package | Purpose | Version |
|---------|---------|---------|
| `scapy` or `pyshark` | PCAP parsing | Latest |
| `dpkt` | TCP reassembly | Latest |
| `pyyaml` | Config parsing | Latest |

### Appendix C: Comparison with Original Architecture

| Aspect | Original (Python) | New (Rust) | Improvement |
|--------|-------------------|------------|-------------|
| **Language** | Python | Rust | 10-100x performance |
| **SMB Library** | smbprotocol | smb-rs | Native async, credit system |
| **Concurrency** | asyncio + threads | tokio | No GIL, simpler |
| **Memory/User** | ~1-2 MB | ~100-500 KB | 2-4x better |
| **Deployment** | Python + deps | Single binary | Much simpler |
| **Scale Target** | 1000 users | 10000+ users | 10x better |
| **Timeline** | 10-13 weeks | 18 weeks | +5 weeks but better result |

---

## Conclusion

This architecture provides:

✅ **High Fidelity** - Oplocks, leases, durable handles supported  
✅ **Scalability** - 5000+ concurrent users via Rust async  
✅ **Simplicity** - Single binary deployment  
✅ **Flexibility** - Time scaling, path mapping, user mapping  
✅ **Observability** - Prometheus metrics, structured logs  
✅ **Correctness** - Dependency tracking, happens-before preservation  

**The Rust + Linux approach is the elegant solution** that balances protocol fidelity, performance, and operational simplicity.

---

*Architecture v1.0 - Ready for implementation.*
