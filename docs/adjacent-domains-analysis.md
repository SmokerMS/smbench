# Learning from Adjacent Domains: Architecture Patterns for SMBench

**Date:** February 1, 2026  
**Purpose:** Synthesize learnings from related tools to inform SMBench architecture  
**Status:** Research Summary

---

## Executive Summary

SMBench is novel - no direct competitors exist for SMB trace replay with multi-client coordination. However, three adjacent domains provide valuable architectural patterns:

1. **Database Query Replay** → Workload capture & normalization patterns
2. **Jepsen (Distributed Systems Testing)** → Multi-client coordination & timeline management
3. **tcpreplay / PCAP Tools** → Packet parsing & timing reconstruction

This document synthesizes learnings from these domains into actionable architecture recommendations.

---

## 1. Database Query Replay Tools

### Tools Analyzed
- **PostgreSQL**: WAL replay, pg_stat_statements
- **MySQL**: Binary log replay, Percona pt-query-digest
- **Oracle**: Automatic Workload Repository (AWR), Real Application Testing

### Key Architectural Patterns

#### Pattern 1: Three-Phase Architecture
```
┌──────────┐     ┌──────────────┐     ┌─────────┐
│ Capture  │────▶│ Normalization│────▶│ Replay  │
└──────────┘     └──────────────┘     └─────────┘
```

**Capture Phase:**
- Record all operations with full context
- Include timing, user context, transaction boundaries
- Store raw format (SQL queries, execution plans)

**Normalization Phase:**
- Fingerprint operations (group similar queries)
- Extract parameters from literals
- Build dependency graph (transaction ordering)
- Calculate impact metrics (frequency, latency)

**Replay Phase:**
- Reconstruct execution order
- Scale timing (compress/expand)
- Map users/databases to test environment
- Validate results against baseline

**Application to SMBench:**
```
Capture: PCAP with SMB packets
Normalization: Extract SMB operations → IR
Replay: Execute operations via smbprotocol
```

#### Pattern 2: Workload Fingerprinting

**PostgreSQL pg_stat_statements approach:**
```sql
-- Normalize query patterns
SELECT * FROM users WHERE id = 123
SELECT * FROM users WHERE id = 456
-- Becomes fingerprint:
SELECT * FROM users WHERE id = ?
```

**Application to SMBench:**
```python
# Fingerprint SMB operations
open("Documents/Q1_Report.docx", mode=READ)
open("Documents/Q2_Report.docx", mode=READ)
# Becomes pattern:
open("Documents/*_Report.docx", mode=READ)

# Use for:
# - Identifying common operation patterns
# - Prioritizing which operations to replay
# - Detecting anomalies (rare operations)
```

#### Pattern 3: Dependency Tracking

**Database transactions have dependencies:**
```
BEGIN TRANSACTION
  INSERT INTO orders ...
  UPDATE inventory ...
COMMIT
```

**SMB operations have dependencies:**
```
OPEN file.txt → handle_123
WRITE handle_123, offset=0, data=...
WRITE handle_123, offset=4096, data=...
CLOSE handle_123
```

**Key Insight:** Your IR must preserve operation dependencies (file handle lifecycle, oplock state).

### Learnings for SMBench

| Database Concept | SMBench Equivalent | Implementation |
|------------------|-------------------|----------------|
| **Transaction log** | PCAP trace | Raw input |
| **Query fingerprint** | Operation pattern | IR normalization |
| **Execution plan** | Operation sequence | IR timeline |
| **Bind variables** | Path parameters | Path mapping config |
| **Connection pool** | SMB session pool | smbprotocol sessions |
| **Workload prioritization** | Operation filtering | User-specified filters |

**Recommendation:** Implement workload fingerprinting in your compiler to identify patterns and enable intelligent filtering.

---

## 2. Jepsen: Distributed Systems Testing

### Overview
Jepsen tests distributed databases for consistency violations by:
1. Running concurrent clients with specific operation sequences
2. Recording operation history with precise timing
3. Checking if history satisfies consistency models (linearizability, serializability)

### Relevant Architectural Patterns

#### Pattern 1: Logical Clocks vs. Wall Clocks

**Jepsen uses logical time:**
```clojure
; Operations scheduled by logical clock, not wall time
{:process 0, :type :invoke, :f :write, :value 5, :time 100}
{:process 1, :type :invoke, :f :read, :value nil, :time 101}
{:process 0, :type :ok, :f :write, :value 5, :time 150}
{:process 1, :type :ok, :f :read, :value 5, :time 160}
```

**Application to SMBench:**
```python
# Don't use absolute PCAP timestamps
# Use relative timing from trace start

class ScheduledOperation:
    logical_time: float  # Seconds from trace start
    wall_time: float     # Original PCAP timestamp (for reference)
    client_id: str
    operation: Dict
    
# Schedule by logical_time, preserve relative ordering
```

**Why this matters:** Allows time scaling without breaking operation ordering.

#### Pattern 2: Happens-Before Relationships

**Jepsen tracks causality:**
```
Operation A happens-before Operation B if:
1. Same client: A completes before B starts
2. Different clients: B reads value written by A
```

**Application to SMBench (Oplocks):**
```
Client A: OPEN file.txt (request exclusive oplock) → granted
Client B: OPEN file.txt → triggers oplock break
Server: Send oplock break to Client A
Client A: ACK oplock break
Server: Grant open to Client B

Happens-before relationships:
1. A.open → A.oplock_granted
2. B.open → server.oplock_break_sent
3. server.oplock_break_sent → A.oplock_ack
4. A.oplock_ack → B.open_granted
```

**Key Insight:** Your hybrid model MUST respect happens-before for oplocks.

#### Pattern 3: History Validation

**Jepsen validates operation history:**
```clojure
; Check if observed history is linearizable
(defn linearizable? [history]
  ; Build partial order from happens-before
  ; Check if total order exists that respects partial order
  ...)
```

**Application to SMBench:**
```python
def validate_replay(original_pcap, replay_log):
    """Validate replay preserved critical orderings"""
    
    # Extract oplock sequences
    original_oplocks = extract_oplock_events(original_pcap)
    replay_oplocks = extract_oplock_events(replay_log)
    
    # Check happens-before preserved
    for (event_a, event_b) in original_oplocks.happens_before_pairs():
        assert replay_oplocks.preserves_order(event_a, event_b)
```

**Recommendation:** Build validation tools to verify replay correctness.

#### Pattern 4: Client State Isolation

**Jepsen maintains per-client state:**
```clojure
{:client-states {
  :client-0 {:connection conn-0, :pending-ops [...]}
  :client-1 {:connection conn-1, :pending-ops [...]}
}}
```

**Application to SMBench:**
```python
class ClientState:
    user_id: str
    smb_session: SMBSession
    open_handles: Dict[str, FileHandle]  # fid → handle
    pending_oplocks: Set[str]  # Files with active oplocks
    operation_queue: PriorityQueue[ScheduledOp]
    
# Each client has isolated state
# Scheduler coordinates across clients
```

### Learnings for SMBench

| Jepsen Concept | SMBench Application | Benefit |
|----------------|---------------------|---------|
| **Logical clocks** | Relative timestamps in IR | Time scaling |
| **Happens-before** | Oplock ordering constraints | Correctness |
| **History validation** | Replay verification | Debugging |
| **Client isolation** | Per-user state tracking | Concurrency |
| **Nemesis (failure injection)** | Future: connection drops | Resilience testing |

**Recommendation:** Adopt Jepsen's logical clock model for your scheduler. This enables time scaling while preserving causality.

---

## 3. tcpreplay & PCAP Parsing

### Tools Analyzed
- **tcpreplay**: Packet replay at Layer 2/3
- **Scapy**: Python packet manipulation
- **Wireshark/tshark**: Protocol dissection
- **Pcapy-NG**: Python PCAP library

### Key Architectural Patterns

#### Pattern 1: Streaming PCAP Parser

**tcpreplay approach:**
```c
// Don't load entire PCAP into memory
while (pcap_next(pcap_handle, &header, &packet)) {
    process_packet(packet, header.ts);
}
```

**Application to SMBench:**
```python
import dpkt
import socket

def parse_pcap_streaming(pcap_file):
    """Stream PCAP, yield SMB operations"""
    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        
        tcp_streams = {}  # Track TCP reassembly
        smb_sessions = {}  # Track SMB state
        
        for timestamp, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    
                    # Reassemble TCP stream
                    stream_key = (ip.src, ip.dst, tcp.sport, tcp.dport)
                    stream = tcp_streams.setdefault(stream_key, TCPStream())
                    stream.add_segment(tcp.seq, tcp.data)
                    
                    # Parse SMB from reassembled stream
                    for smb_packet in stream.get_complete_packets():
                        yield parse_smb_packet(smb_packet, timestamp)
```

**Why this matters:** Customer PCAPs can be GBs. Streaming parser prevents OOM.

#### Pattern 2: TCP Stream Reassembly

**Challenge:** SMB packets span multiple TCP segments
```
TCP Segment 1: [SMB Header][Partial SMB Command]
TCP Segment 2: [Rest of SMB Command][Partial Next Command]
TCP Segment 3: [Rest of Next Command]
```

**Solution: Reassembly Buffer**
```python
class TCPStream:
    def __init__(self):
        self.segments = {}  # seq_num → data
        self.next_seq = None
        
    def add_segment(self, seq, data):
        self.segments[seq] = data
        
    def get_complete_packets(self):
        """Yield complete SMB packets from reassembled stream"""
        # Sort segments by sequence number
        # Detect SMB packet boundaries (NetBIOS header)
        # Yield complete SMB packets
```

**Recommendation:** Use existing library (Scapy, dpkt) for TCP reassembly. Don't implement from scratch.

#### Pattern 3: Protocol State Machine

**SMB3 requires state tracking:**
```
Session Setup → Tree Connect → Create → Read/Write → Close → Tree Disconnect → Logoff
```

**State machine for PCAP compiler:**
```python
class SMBStateMachine:
    def __init__(self):
        self.sessions = {}     # SessionId → Session
        self.trees = {}        # TreeId → TreeConnect
        self.opens = {}        # FileId → Open
        
    def process_packet(self, smb_packet):
        if smb_packet.command == SMB2_SESSION_SETUP:
            self.sessions[smb_packet.session_id] = Session(...)
            
        elif smb_packet.command == SMB2_TREE_CONNECT:
            self.trees[smb_packet.tree_id] = TreeConnect(...)
            
        elif smb_packet.command == SMB2_CREATE:
            self.opens[smb_packet.file_id] = Open(
                path=smb_packet.path,
                session=self.sessions[smb_packet.session_id],
                tree=self.trees[smb_packet.tree_id]
            )
            
        elif smb_packet.command == SMB2_WRITE:
            open_file = self.opens[smb_packet.file_id]
            yield WriteOperation(
                path=open_file.path,
                offset=smb_packet.offset,
                data=smb_packet.data
            )
```

**Key Insight:** PCAP compiler is a state machine that translates packets → operations.

#### Pattern 4: Timing Reconstruction

**tcpreplay timing modes:**
```bash
# Replay at original speed
tcpreplay --intf eth0 capture.pcap

# Replay at 2x speed
tcpreplay --multiplier 2.0 --intf eth0 capture.pcap

# Replay as fast as possible
tcpreplay --topspeed --intf eth0 capture.pcap
```

**Application to SMBench:**
```python
class TimingMode(Enum):
    ORIGINAL = "original"      # Preserve exact timing
    SCALED = "scaled"          # Multiply all delays by factor
    COMPRESSED = "compressed"  # Remove idle time, preserve busy periods
    FAST = "fast"              # No delays, sequential execution

def apply_timing_mode(operations, mode, scale_factor=1.0):
    if mode == TimingMode.ORIGINAL:
        return operations
        
    elif mode == TimingMode.SCALED:
        for op in operations:
            op.delay *= scale_factor
            
    elif mode == TimingMode.COMPRESSED:
        # Remove gaps > threshold, preserve operation bursts
        ...
```

### Learnings for SMBench

| tcpreplay Concept | SMBench Application | Benefit |
|-------------------|---------------------|---------|
| **Streaming parser** | PCAP → IR compiler | Memory efficiency |
| **TCP reassembly** | SMB packet reconstruction | Correctness |
| **State machine** | Session/Tree/File tracking | Protocol fidelity |
| **Timing modes** | Time scaling options | Flexibility |
| **Packet filtering** | Client/operation filtering | Focus |

**Recommendation:** Use Scapy or dpkt for PCAP parsing. Build SMB state machine on top.

---

## Synthesis: SMBench Architecture

### Combined Architecture Pattern

```
┌─────────────────────────────────────────────────────────────┐
│                  CAPTURE PHASE (PCAP)                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Customer PCAP (GB)                                         │
│         │                                                   │
│         ▼                                                   │
│  ┌──────────────────┐                                       │
│  │ Streaming Parser │  ← tcpreplay pattern                 │
│  │  (dpkt/Scapy)    │                                       │
│  └────────┬─────────┘                                       │
│           │                                                 │
│           ▼                                                 │
│  ┌──────────────────┐                                       │
│  │ TCP Reassembly   │  ← tcpreplay pattern                 │
│  └────────┬─────────┘                                       │
│           │                                                 │
│           ▼                                                 │
│  ┌──────────────────┐                                       │
│  │ SMB State Machine│  ← tcpreplay pattern                 │
│  │ (Session/Tree/   │                                       │
│  │  File tracking)  │                                       │
│  └────────┬─────────┘                                       │
└───────────┼─────────────────────────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────────────────────────┐
│              NORMALIZATION PHASE (IR)                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────────┐                                       │
│  │ Operation        │  ← Database replay pattern           │
│  │ Fingerprinting   │                                       │
│  └────────┬─────────┘                                       │
│           │                                                 │
│           ▼                                                 │
│  ┌──────────────────┐                                       │
│  │ Dependency Graph │  ← Database replay pattern           │
│  │ (Handle lifecycle│                                       │
│  │  Oplock ordering)│                                       │
│  └────────┬─────────┘                                       │
│           │                                                 │
│           ▼                                                 │
│  ┌──────────────────┐                                       │
│  │ Logical Clock    │  ← Jepsen pattern                    │
│  │ Assignment       │                                       │
│  └────────┬─────────┘                                       │
│           │                                                 │
│           ▼                                                 │
│  ┌──────────────────┐                                       │
│  │ Workload IR      │                                       │
│  │ (JSON + blobs/)  │                                       │
│  └────────┬─────────┘                                       │
└───────────┼─────────────────────────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────────────────────────┐
│                 REPLAY PHASE (Execution)                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────────┐                                       │
│  │ Scheduler        │  ← Jepsen pattern                    │
│  │ (Logical clock   │                                       │
│  │  Priority queue) │                                       │
│  └────────┬─────────┘                                       │
│           │                                                 │
│           ▼                                                 │
│  ┌──────────────────┐                                       │
│  │ Client State     │  ← Jepsen pattern                    │
│  │ Manager          │                                       │
│  │ (Per-user state) │                                       │
│  └────────┬─────────┘                                       │
│           │                                                 │
│           ▼                                                 │
│  ┌──────────────────┐                                       │
│  │ SMB Executor     │  ← Database replay pattern           │
│  │ (smbprotocol)    │                                       │
│  └────────┬─────────┘                                       │
│           │                                                 │
│           ▼                                                 │
│  ┌──────────────────┐                                       │
│  │ Oplock Handler   │  ← Jepsen pattern (reactive)         │
│  │ (Hybrid model)   │                                       │
│  └────────┬─────────┘                                       │
└───────────┼─────────────────────────────────────────────────┘
            │
            ▼
    Nutanix Files (Target)
```

### Key Design Decisions from Adjacent Domains

| Decision | Inspired By | Rationale |
|----------|-------------|-----------|
| **Three-phase architecture** | Database replay | Separation of concerns |
| **Streaming PCAP parser** | tcpreplay | Memory efficiency |
| **Logical clocks** | Jepsen | Time scaling support |
| **Happens-before tracking** | Jepsen | Oplock correctness |
| **Client state isolation** | Jepsen | Multi-client coordination |
| **Operation fingerprinting** | Database replay | Pattern detection |
| **State machine compiler** | tcpreplay | Protocol fidelity |

---

## Recommendations

### Immediate (Phase 0)

1. **Adopt logical clock model** from Jepsen
   - Store relative timestamps in IR (not absolute)
   - Enables time scaling without breaking causality

2. **Use existing PCAP library** from tcpreplay domain
   - Scapy or dpkt for Python
   - Don't build TCP reassembly from scratch

3. **Design IR schema** inspired by database replay
   - Include operation fingerprints
   - Track dependencies (file handles, oplocks)
   - Store timing as logical clocks

### Medium-term (Phase 1-2)

4. **Build SMB state machine** following tcpreplay patterns
   - Session/Tree/File tracking
   - Oplock state management
   - Async operation correlation

5. **Implement scheduler** using Jepsen patterns
   - Priority queue by logical time
   - Per-client state isolation
   - Happens-before enforcement for oplocks

6. **Add validation tools** inspired by Jepsen
   - Verify operation ordering preserved
   - Check oplock sequences correct
   - Compare original vs. replay timing

### Long-term (Phase 3+)

7. **Workload fingerprinting** from database replay
   - Identify common operation patterns
   - Enable intelligent filtering
   - Support workload synthesis

8. **Failure injection** inspired by Jepsen nemesis
   - Connection drops during replay
   - Network delays
   - Server errors

---

## Conclusion

While no direct SMB trace replay tools exist, adjacent domains provide proven architectural patterns:

- **Database replay** → Workload capture & normalization
- **Jepsen** → Multi-client coordination & correctness
- **tcpreplay** → PCAP parsing & timing

By synthesizing these patterns, SMBench can avoid common pitfalls and build on established best practices.

**Next step:** Use these patterns to design the Workload IR schema (v1).

---

*This analysis was conducted February 1, 2026, using Context7, web research, and domain expertise.*
