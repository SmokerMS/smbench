# SMBench Architecture: Current Implementation (v1.2.1)

**Status:** PRIMARY ARCHITECTURE DOCUMENT  
**Last Updated:** 2026-02-03  
**Implementation:** Rust-only, smb-rs backend

---

## Table of Contents

1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [Core Components](#core-components)
4. [IR Schema](#ir-schema)
5. [Scheduler Design](#scheduler-design)
6. [Backend Abstraction](#backend-abstraction)
7. [Testing Strategy](#testing-strategy)
8. [Future Roadmap](#future-roadmap)

---

## Overview

SMBench is a high-fidelity SMB workload replay system implemented in Rust. It enables:

- **Bug Reproduction:** Capture customer workloads → Replay in lab → Reproduce issues
- **Load Testing:** Scale to thousands of concurrent users with realistic timing
- **Protocol Validation:** Test SMB2/3 feature compliance against real servers

### Current Capabilities

✅ **Implemented:**
- Rust-based IR (Intermediate Representation) schema
- Event-driven scheduler with per-client ordering
- smb-rs backend with full SMB3 protocol support
- Comprehensive test suite (45+ validation tests)
- CLI tool (`smbench replay`)

❌ **Not Yet Implemented:**
- PCAP compiler (planned for Phase 6)
- Provisioning tools (AD/LDAP integration)
- Path/user mapping for customer → lab translation
- Analysis tools for PCAP comparison

---

## System Architecture

```mermaid
graph LR
    PCAP[PCAP File] -.->|Future| Compiler[PCAP Compiler]
    Compiler -.->|Future| IR[WorkloadIr JSON]
    IR -->|smbench replay| Scheduler[Scheduler]
    Scheduler --> Backend[SMB Backend]
    Backend --> Server[SMB Server]
    
    Scheduler --> Observability[Observability]
    Observability --> Logs[Logs]
    Observability --> Metrics[Metrics]
```

### Data Flow

1. **Input:** WorkloadIr JSON file (manually created or future PCAP compilation)
2. **Scheduler:** Reads IR, schedules operations with timing fidelity
3. **Backend:** Executes SMB operations via smb-rs
4. **Observability:** Logs operations, collects metrics
5. **Output:** Execution results, timing data, error reports

---

## Core Components

### 1. IR (Intermediate Representation)

**Location:** `src/ir/mod.rs`

The IR is a JSON-based format that describes SMB workloads:

```rust
pub struct WorkloadIr {
    pub version: u32,
    pub metadata: Metadata,
    pub clients: Vec<ClientSpec>,
    pub operations: Vec<Operation>,
}
```

**Key Features:**
- Client-centric: Operations grouped by client_id
- Timestamp-based: Microsecond precision for timing
- Extensible: JSON extensions for SMB-specific features
- Blob references: External files for read/write data

**Supported Operations:**
- `Open` - File/directory open with create options
- `Close` - Close handle
- `Read` - Read data from file
- `Write` - Write data to file
- `Delete` - Delete file/directory
- `Rename` - Rename file/directory
- `Mkdir` - Create directory
- `Rmdir` - Remove directory
- `Fsctl` - File system control operations
- `Ioctl` - I/O control operations

### 2. Scheduler

**Location:** `src/scheduler/mod.rs`

Event-driven scheduler that replays operations with timing fidelity.

**Key Features:**
- **Per-client ordering:** Operations from same client execute in order
- **Cross-client parallelism:** Different clients run concurrently
- **Time scaling:** Configurable time_scale for faster/slower replay
- **Invariant checking:** Detects handle leaks, ordering violations
- **Watchdog:** Monitors for stuck operations

**Configuration:**

```rust
pub struct SchedulerConfig {
    pub max_concurrent: usize,      // Max concurrent operations
    pub time_scale: f64,            // Time scaling factor (0.1 = 10x faster)
    pub worker_count: usize,        // Worker threads
    pub backend_mode: BackendMode,  // Development vs Production
    pub invariant_mode: InvariantMode, // Panic vs LogAndContinue
    pub debug_dump_on_error: bool,  // Dump state on error
    pub watchdog_interval: Duration, // Watchdog check interval
    pub inflight_timeout: Duration,  // Max operation duration
}
```

**Invariants:**
- No handle leaks (all Opens have matching Closes)
- Per-client operation ordering preserved
- No operations on closed handles
- Timestamps monotonically increasing per client

### 3. Backend Abstraction

**Location:** `src/backend/mod.rs`

Trait-based abstraction for SMB backends:

```rust
#[async_trait]
pub trait SMBBackend: Send + Sync {
    async fn execute_operation(
        &self,
        client_id: &str,
        operation: &Operation,
        state: &mut ClientState,
    ) -> Result<OperationResult>;
}
```

**Implementations:**
- **smb-rs:** Full SMB2/3 protocol (current)
- **Impacket:** Python-based (future)

### 4. smb-rs Backend

**Location:** `src/backend/smbrs.rs`

Rust-native SMB2/3 client implementation.

**Features:**
- SMB 3.1.1 with encryption
- Oplocks & Leases
- Durable handles
- Multichannel support
- RDMA transport (optional)
- Comprehensive FSCTL/IOCTL support

**Connection Management:**
- Per-client connection pooling
- Automatic reconnection
- Lease break handling
- Session multiplexing

**Extensions Supported:**

```json
{
  "oplock_level": "Batch",
  "lease_state": {"read_caching": true, "write_caching": true},
  "create_disposition": "OpenIf",
  "file_attributes": {"hidden": true, "archive": true},
  "share_access": {"read": true, "write": false},
  "create_options": {"delete_on_close": true},
  "durable_handle": true
}
```

---

## IR Schema

### WorkloadIr Structure

```json
{
  "version": 1,
  "metadata": {
    "source": "manual | pcap_compiler",
    "duration_seconds": 120.5,
    "client_count": 100
  },
  "clients": [
    {
      "client_id": "user001",
      "operation_count": 1500
    }
  ],
  "operations": [
    {
      "op_id": "op_000001",
      "client_id": "user001",
      "timestamp_us": 1000000,
      "operation": "Open",
      "path": "/share/file.txt",
      "mode": "Write",
      "handle_ref": "h_1",
      "extensions": {
        "oplock_level": "Batch"
      }
    }
  ]
}
```

### Operation Types

#### Open

```json
{
  "operation": "Open",
  "path": "/path/to/file",
  "mode": "Read | Write | ReadWrite",
  "handle_ref": "h_1",
  "extensions": {
    "create_disposition": "OpenIf",
    "oplock_level": "Batch",
    "file_attributes": {"archive": true}
  }
}
```

#### Write

```json
{
  "operation": "Write",
  "handle_ref": "h_1",
  "offset": 0,
  "length": 4096,
  "blob_path": "/tmp/blob_001.bin"
}
```

#### Fsctl

```json
{
  "operation": "Fsctl",
  "handle_ref": "h_1",
  "control_code": "SrvRequestResumeKey",
  "input_blob_path": null,
  "max_output_response": 4096
}
```

---

## Scheduler Design

### Event Loop

```mermaid
sequenceDiagram
    participant Scheduler
    participant Queue
    participant Worker
    participant Backend
    
    Scheduler->>Queue: Enqueue operations by timestamp
    loop Until complete
        Queue->>Scheduler: Next operation ready?
        Scheduler->>Worker: Dispatch to worker
        Worker->>Backend: Execute operation
        Backend-->>Worker: Result
        Worker-->>Scheduler: Update state
        Scheduler->>Scheduler: Check invariants
    end
```

### Timing Model

**Absolute Timestamps:**
- Operations have absolute timestamps (microseconds since workload start)
- Scheduler waits until timestamp before dispatching
- Time scaling applied: `actual_wait = (target_ts - current_ts) * time_scale`

**Per-Client Ordering:**
- Operations from same client execute in timestamp order
- Next operation waits for previous to complete
- Cross-client operations run in parallel

**Example:**

```
Client A: Open(t=0) → Write(t=100ms) → Close(t=200ms)
Client B: Open(t=50ms) → Read(t=150ms) → Close(t=250ms)

Execution timeline:
t=0:    Client A Open starts
t=50ms: Client B Open starts (parallel)
t=100ms: Client A Write starts (after Open completes)
t=150ms: Client B Read starts (after Open completes)
...
```

### Invariant Checking

**Handle Leak Detection:**
```rust
// At workload end, all handles must be closed
assert!(state.open_handles.is_empty(), "Handle leak detected");
```

**Ordering Validation:**
```rust
// Per-client timestamps must be monotonic
assert!(op.timestamp_us >= last_timestamp, "Timestamp ordering violation");
```

**State Consistency:**
```rust
// Can't operate on closed handle
assert!(state.handles.contains_key(&handle_ref), "Handle not found");
```

---

## Backend Abstraction

### SMBBackend Trait

```rust
#[async_trait]
pub trait SMBBackend: Send + Sync {
    /// Execute a single operation
    async fn execute_operation(
        &self,
        client_id: &str,
        operation: &Operation,
        state: &mut ClientState,
    ) -> Result<OperationResult>;
}
```

### ClientState

```rust
pub struct ClientState {
    pub handles: HashMap<String, HandleInfo>,
    pub connection: Option<BackendConnection>,
    pub last_operation_time: Option<Instant>,
}

pub struct HandleInfo {
    pub path: String,
    pub mode: OpenMode,
    pub backend_handle: Box<dyn Any + Send>,
}
```

### Error Handling

```rust
pub enum BackendError {
    ConnectionFailed(String),
    OperationFailed { op_id: String, error: String },
    InvalidHandle(String),
    ProtocolError(String),
}
```

---

## Testing Strategy

### Test Pyramid

```
                    /\
                   /  \
                  / E2E \          3 use case tests
                 /______\
                /        \
               / Integration \     45 smb-rs validation tests
              /______________\
             /                \
            /   Unit Tests      \  (in src/)
           /____________________\
```

### Test Categories

#### 1. Unit Tests (src/)
- IR parsing/serialization
- Scheduler logic
- Backend abstraction

#### 2. Integration Tests (tests/)

**smb_rs_validation.rs** (45 tests):
- Basic operations (open, read, write, close)
- Oplocks & leases
- FSCTL operations (DFS, snapshots, offload, hashing)
- IPC operations (share enumeration, network interfaces)
- Multichannel capabilities
- Directory operations
- File/FS info queries

**backend_mode.rs:**
- Development vs Production mode behavior

**scheduler_invariant.rs:**
- Handle leak detection
- Ordering validation

**timing_precision.rs:**
- Scheduler timing accuracy

#### 3. Use Case Tests (tests/)

**use_case_bug_reproduction.rs:**
- Oplock break race condition
- Multi-client write ordering
- Durable handle reconnection

**use_case_load_testing.rs:**
- 100-user scaled workload
- Sustained load (1 hour)

**protocol_fidelity.rs:**
- Oplock levels (None, Level2, Exclusive, Batch)
- Lease states (R, W, H, RW, RH, RWH)
- Create dispositions
- File attributes

### Running Tests

```bash
# All tests (non-SMB)
cargo test

# SMB backend tests (requires server)
export SMBENCH_SMB_SERVER=10.10.10.79
export SMBENCH_SMB_SHARE=testshare
export SMBENCH_SMB_USER=testuser
export SMBENCH_SMB_PASS=testpass

cargo test --features smb-rs-backend

# Use case tests (ignored by default)
cargo test --features smb-rs-backend -- --ignored

# Specific test
cargo test --features smb-rs-backend test_oplock_break_race_condition -- --ignored
```

---

## Future Roadmap

### Phase 6: PCAP Compiler (Planned)

**Goal:** Extract SMB operations from PCAP files → Generate WorkloadIr

**Components:**
- PCAP reader (pcap-parser or pcap-rs)
- TCP stream reassembly
- SMB2/3 message parsing (reuse smb-msg crate)
- Protocol state machine
- Operation extraction
- IR generation

**Command:**
```bash
smbench compile capture.pcap -o workload.json
smbench replay workload.json --server 10.10.10.79 --share testshare
```

### Phase 7: Provisioning Tools

**Goal:** Automate test environment setup

- AD/LDAP user creation
- Directory structure provisioning
- Permission assignment
- Path mapping (customer → lab)

### Phase 8: Analysis Tools

**Goal:** Compare replay results to original PCAP

- Timing analysis (latency distribution)
- Operation success/failure comparison
- Protocol compliance validation
- Performance regression detection

---

## References

### Microsoft Specifications

- **[MS-SMB2]** Server Message Block (SMB) Protocol Versions 2 and 3
  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/
- **[MS-FSCC]** File System Control Codes
  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/
- **[MS-PCCRC]** Peer Content Caching and Retrieval: Content Identification
  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pccrc/

### Implementation Notes

- **smb-rs:** https://github.com/avivnaaman/smb-rs
- **problem-definition.md:** Original requirements and use cases
- **architecture-v1.2.2-locked.md:** Previous architecture (superseded)

---

## Appendix: CLI Usage

### Replay Command

```bash
smbench replay <IR_FILE> [OPTIONS]

Options:
  --server <HOST>       SMB server hostname/IP
  --share <SHARE>       Share name
  --user <USER>         Username
  --pass <PASS>         Password
  --time-scale <SCALE>  Time scaling factor (default: 1.0)
  --workers <N>         Worker threads (default: 4)
  --max-concurrent <N>  Max concurrent operations (default: 100)
  --validate-only       Validate IR without executing
```

### Example

```bash
# Replay workload at 10x speed
smbench replay workload.json \
  --server 10.10.10.79 \
  --share testshare \
  --user testuser \
  --pass testpass \
  --time-scale 0.1 \
  --workers 8

# Validate IR only
smbench replay workload.json --validate-only
```

---

**End of Document**
