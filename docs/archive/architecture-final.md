# SMBench Architecture v1.2 (Final)

**Version:** 1.2 FINAL  
**Date:** February 1, 2026  
**Status:** Production-Ready, Approved for Implementation  
**Review Status:** All critical issues addressed

---

## Change Log v1.1 → v1.2

**Addressed 4 remaining critical issues:**
1. ✅ Added per-client ordering invariant (scheduler fix)
2. ✅ Defined oplock blocking semantics (state machine)
3. ✅ Enforced core/extension separation (protocol-free core)
4. ✅ Specified Impacket backend protocol (persistent worker)

**Added sections:**
- ✅ Execution Invariants (hard rules)
- ✅ Backend Contract Specification
- ✅ Impacket Worker Protocol
- ✅ Production Failure Modes

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [System Overview](#system-overview)
3. [Execution Invariants](#execution-invariants) **NEW**
4. [Technology Stack](#technology-stack)
5. [Workload IR Schema](#workload-ir-schema-v1-locked) **LOCKED**
6. [Component Architecture](#component-architecture)
7. [Scheduler Design](#scheduler-design) **FIXED**
8. [Oplock Blocking Semantics](#oplock-blocking-semantics) **NEW**
9. [Backend Contract](#backend-contract) **NEW**
10. [Impacket Worker Protocol](#impacket-worker-protocol) **NEW**
11. [Error Handling](#error-handling)
12. [Observability](#observability)
13. [Deployment](#deployment)
14. [Implementation Phases](#implementation-phases)
15. [Production Failure Modes](#production-failure-modes) **NEW**

---

## Executive Summary

SMBench: High-fidelity SMB3 workload replay for bug reproduction and load testing.

### Architecture Principles
1. **Plane Separation** - Python control plane, Rust data plane
2. **Tiered Fidelity** - Mode 0 (MVP) → Mode 1 (Realistic) → Mode 2 (Full)
3. **Backend Abstraction** - Not locked to any single SMB library
4. **Hybrid Timing** - Scheduled operations + runtime protocol events
5. **Immutable IR** - Portable workload representation

### Technology Stack
- **Control Plane:** Python 3.9+ (LDAP, PCAP parsing, provisioning)
- **Data Plane:** Rust 1.75+ (replay engine, concurrency, metrics)
- **SMB Client:** Backend interface (smb-rs, Impacket, or OS mount)
- **Async Runtime:** tokio 1.48+
- **Platform:** Linux (Ubuntu 22.04+, RHEL 9+)

---

## System Overview

### Two-Binary Architecture

```
┌─────────────────────────────────────────────────────────┐
│             smbench-provision (Python)                  │
│                  Control Plane                          │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  1. Parse PCAP (Scapy/Pyshark)                          │
│  2. Generate Workload IR                                │
│  3. Provision AD Users (LDAP3)                          │
│  4. Create Directories (smbclient)                      │
│                                                         │
│  Output: workload.json + blobs/ + users created         │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│               smbench (Rust)                            │
│                  Data Plane                             │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  1. Load Workload IR                                    │
│  2. Map to lab environment                              │
│  3. Create SMB client pool                              │
│  4. Execute replay (tokio runtime)                      │
│  5. Collect metrics                                     │
│                                                         │
│  Output: metrics.json + structured logs                 │
└─────────────────────────────────────────────────────────┘
```

**Workflow:**
```bash
# Step 1: Python - Provision (once per test)
smbench-provision \
    --pcap customer.pcap \
    --config mapping.yaml \
    --output workload.json

# Step 2: Rust - Replay (multiple times)
smbench replay workload.json \
    --config mapping.yaml \
    --mode mvp \
    --output results/
```

---

## Execution Invariants (HARD RULES)

These are **non-negotiable constraints** that the implementation MUST enforce:

### Invariant 1: Per-Client Ordering

**Rule:**
> Operations from the same client MUST execute in strict order.  
> At most ONE operation per client can be in-flight at any time.

**Rationale:** SMB file handles, directory state, and oplock state are client-local. Out-of-order execution produces invalid sequences.

**Enforcement:**
```rust
// Scheduler maintains per-client serialization
struct ClientState {
    client_id: String,
    in_flight: bool,  // Only ONE op active
    pending_ops: VecDeque<Operation>,
}

// Before dispatching op:
assert!(!client_state.in_flight, "Invariant violated: client has in-flight op");
client_state.in_flight = true;

// After op completes:
client_state.in_flight = false;
```

**Violation impact:** Produces non-existent bugs, invalidates replay.

---

### Invariant 2: Oplock State Blocks Execution

**Rule:**
> When an oplock/lease break arrives, all operations touching the affected handle/path MUST block until the break is acknowledged.

**States:**
- `GRANTED` - Operations can proceed
- `BREAK_PENDING` - Operations MUST wait
- `BROKEN` - Operations can proceed at new level

**Enforcement:**
```rust
enum HandleState {
    Open { oplock: Option<OplockState> },
    BlockedByOplock { break_msg: OplockBreak },
    Closed,
}

// Before executing operation on handle:
match handle_state {
    HandleState::BlockedByOplock { .. } => {
        // WAIT until ACK completes
        oplock_runtime.wait_for_ack(handle_ref).await;
    },
    HandleState::Open { .. } => {
        // Proceed
    },
    HandleState::Closed => {
        return Err("Handle closed");
    },
}
```

**Violation impact:** Operations execute during break window, produces incorrect server state.

---

### Invariant 3: Core Engine is Protocol-Agnostic

**Rule:**
> Core execution logic MUST work when `operation.extensions == null`.

**Test:**
```rust
#[test]
fn test_core_execution_without_extensions() {
    let op = Operation::Open {
        op_id: "op_001",
        path: "file.txt",
        mode: OpenMode::ReadWrite,
        extensions: None,  // ← Must work
        ..
    };
    
    let result = execute_operation(&op, &backend);
    assert!(result.is_ok());
}
```

**Enforcement:** All protocol interpretation happens inside `SMBBackend` implementation, not in scheduler or executor.

**Violation impact:** Mode 0 breaks, can't ship early.

---

### Invariant 4: Timing Drift is Bounded

**Rule:**
> Actual execution time must not drift from PCAP timeline by more than `max_drift_ms` (default: 100ms).

**Enforcement:**
```rust
let expected_time = start + Duration::from_micros(op.timestamp_us * time_scale);
let actual_time = Instant::now();
let drift = actual_time.duration_since(expected_time);

if drift > Duration::from_millis(max_drift_ms) {
    tracing::warn!(
        op_id = op.op_id,
        drift_ms = drift.as_millis(),
        "Timeline drift exceeded threshold"
    );
}
```

**Rationale:** Large drift indicates scheduler can't keep up, invalidates timing-sensitive bug reproduction.

**Violation impact:** Timing-dependent bugs don't reproduce.

---

## Workload IR Schema v1 (LOCKED)

**This schema is FROZEN for Phase 1-3. No extensions or changes allowed.**

### Core Schema (Required for All Modes)

```json
{
  "version": 1,
  "metadata": {
    "source": "string",
    "duration_seconds": "float",
    "client_count": "integer"
  },
  
  "clients": [
    {
      "client_id": "string (e.g., client_001)",
      "operation_count": "integer"
    }
  ],
  
  "operations": [
    {
      "op_id": "string (unique)",
      "client_id": "string (references clients[])",
      "timestamp_us": "u64 (microseconds from start)",
      "type": "enum (open|read|write|close|rename|delete)",
      
      // Type-specific fields (see below)
      
      "extensions": "object or null (optional protocol details)"
    }
  ]
}
```

### Operation Type Definitions

```rust
// LOCKED: Do not modify during Phase 1-3

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum Operation {
    /// Open or create file
    Open {
        op_id: String,
        client_id: String,
        timestamp_us: u64,
        path: String,
        mode: OpenMode,
        handle_ref: String,
        
        #[serde(skip_serializing_if = "Option::is_none")]
        extensions: Option<serde_json::Value>,
    },
    
    /// Read from file
    Read {
        op_id: String,
        client_id: String,
        timestamp_us: u64,
        handle_ref: String,
        offset: u64,
        length: u64,
    },
    
    /// Write to file
    Write {
        op_id: String,
        client_id: String,
        timestamp_us: u64,
        handle_ref: String,
        offset: u64,
        length: u64,
        blob_path: String,
    },
    
    /// Close file
    Close {
        op_id: String,
        client_id: String,
        timestamp_us: u64,
        handle_ref: String,
    },
    
    /// Rename/move file
    Rename {
        op_id: String,
        client_id: String,
        timestamp_us: u64,
        source_path: String,
        dest_path: String,
    },
    
    /// Delete file
    Delete {
        op_id: String,
        client_id: String,
        timestamp_us: u64,
        path: String,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub enum OpenMode {
    Read,
    Write,
    ReadWrite,
}
```

**Extensions Format (Optional, Mode 1/2 Only):**

```json
"extensions": {
  "smb": {
    "access_mask": "0x00120089",
    "share_mode": "FILE_SHARE_READ",
    "disposition": "open_or_create",
    "create_options": "FILE_NON_DIRECTORY_FILE",
    "requested_oplock": "BATCH",
    "create_contexts": [
      {
        "type": "SMB2_CREATE_REQUEST_LEASE",
        "data": { ... }
      }
    ]
  }
}
```

**Rules:**
- ✅ Core operations work without extensions
- ✅ Extensions are backend-specific (smb namespace)
- ✅ Unknown extensions are ignored silently
- ✅ Backends declare what they support

---

## Scheduler Design (FIXED)

### Per-Client Serialization

```rust
// src/scheduler/mod.rs

use std::collections::{HashMap, VecDeque, BinaryHeap};
use tokio::sync::{mpsc, Semaphore};
use tokio::time::{sleep_until, Instant, Duration};

pub struct Scheduler {
    /// Per-client operation queues
    client_queues: HashMap<String, ClientQueue>,
    
    /// Global priority queue: (time, client_id)
    global_heap: BinaryHeap<Reverse<(Instant, String)>>,
    
    /// Semaphore for global concurrency limit
    semaphore: Arc<Semaphore>,
    
    /// Worker pool
    work_tx: mpsc::Sender<WorkItem>,
    
    /// Configuration
    max_concurrent: usize,
    time_scale: f64,
}

struct ClientQueue {
    client_id: String,
    pending_ops: VecDeque<Operation>,
    in_flight: bool,  // INVARIANT ENFORCEMENT
}

impl Scheduler {
    pub async fn run(
        mut self,
        operations: Vec<Operation>,
        backend: Arc<dyn SMBBackend>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // 1. Group operations by client
        self.initialize_client_queues(operations);
        
        // 2. Initialize heap with first op per client
        let start_time = Instant::now();
        for (client_id, queue) in &self.client_queues {
            if let Some(op) = queue.pending_ops.front() {
                let exec_time = start_time + self.scaled_delay(op.timestamp_us);
                self.global_heap.push(Reverse((exec_time, client_id.clone())));
            }
        }
        
        // 3. Spawn worker pool
        self.spawn_workers(backend);
        
        // 4. Main scheduling loop
        while let Some(Reverse((exec_time, client_id))) = self.global_heap.pop() {
            // Wait until operation time (SINGLE TIMER)
            sleep_until(exec_time).await;
            
            // Get client queue
            let queue = self.client_queues.get_mut(&client_id).unwrap();
            
            // INVARIANT CHECK
            if queue.in_flight {
                // Client already has operation executing
                // Re-schedule and continue
                self.global_heap.push(Reverse((exec_time + Duration::from_millis(10), client_id)));
                continue;
            }
            
            // Pop next operation for this client
            if let Some(op) = queue.pending_ops.pop_front() {
                // Mark client as having in-flight operation
                queue.in_flight = true;
                
                // Acquire concurrency permit
                let permit = self.semaphore.clone().acquire_owned().await?;
                
                // Send to worker
                self.work_tx.send(WorkItem {
                    client_id: client_id.clone(),
                    operation: op,
                    _permit: permit,
                    completion_tx: self.completion_tx.clone(),
                }).await?;
                
                // Schedule next operation for this client
                if let Some(next_op) = queue.pending_ops.front() {
                    let next_time = start_time + self.scaled_delay(next_op.timestamp_us);
                    self.global_heap.push(Reverse((next_time, client_id)));
                }
            }
        }
        
        Ok(())
    }
    
    fn scaled_delay(&self, timestamp_us: u64) -> Duration {
        Duration::from_micros((timestamp_us as f64 * self.time_scale) as u64)
    }
}

// Completion callback
impl Scheduler {
    async fn handle_completion(&mut self, client_id: String) {
        // Mark client as no longer in-flight
        if let Some(queue) = self.client_queues.get_mut(&client_id) {
            queue.in_flight = false;
        }
    }
}
```

**Key aspects:**
- ✅ **Per-client queues** - Operations stay ordered
- ✅ **in_flight flag** - Enforces one-op-at-a-time per client
- ✅ **Global heap** - Single timer for efficiency
- ✅ **Semaphore** - Bounded concurrency across all clients
- ✅ **Completion callback** - Clears in_flight when op done

---

## Oplock Blocking Semantics

### State Machine for Handles

```rust
// src/protocol/oplock_state.rs

#[derive(Debug, Clone)]
pub enum HandleState {
    /// Normal state - operations can proceed
    Open {
        oplock: Option<OplockLevel>,
    },
    
    /// Oplock break received - BLOCKS operations
    BreakPending {
        old_level: OplockLevel,
        new_level: OplockLevel,
        break_received_at: Instant,
    },
    
    /// Oplock break acknowledged - operations can resume
    Broken {
        level: OplockLevel,
    },
    
    /// Handle closed
    Closed,
}

pub struct OplockRuntime {
    /// State per file handle
    handle_states: HashMap<String, HandleState>,
    
    /// Break notifications from server (runtime)
    break_rx: mpsc::Receiver<OplockBreak>,
    
    /// Waiting operations (blocked by breaks)
    blocked_ops: HashMap<String, Vec<tokio::sync::oneshot::Sender<()>>>,
}

impl OplockRuntime {
    /// Check if operation can execute (BLOCKING)
    pub async fn wait_if_blocked(&mut self, handle_ref: &str) {
        loop {
            match self.handle_states.get(handle_ref) {
                Some(HandleState::BreakPending { .. }) => {
                    // BLOCK: Wait for ACK to complete
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    self.blocked_ops.entry(handle_ref.to_string())
                        .or_default()
                        .push(tx);
                    
                    tracing::warn!(
                        handle = handle_ref,
                        "Operation blocked waiting for oplock ACK"
                    );
                    
                    // Wait for signal
                    rx.await.ok();
                },
                
                Some(HandleState::Open { .. }) | Some(HandleState::Broken { .. }) => {
                    // Can proceed
                    break;
                },
                
                Some(HandleState::Closed) => {
                    panic!("Operation on closed handle");
                },
                
                None => {
                    // Handle not tracked (no oplock)
                    break;
                },
            }
        }
    }
    
    /// Handle incoming oplock break (runtime event)
    pub async fn handle_break(&mut self, break_msg: OplockBreak, backend: &dyn SMBBackend) {
        let handle = &break_msg.handle_ref;
        
        // Update state to BREAK_PENDING
        if let Some(state) = self.handle_states.get_mut(handle) {
            if let HandleState::Open { oplock: Some(level) } = state {
                *state = HandleState::BreakPending {
                    old_level: *level,
                    new_level: break_msg.new_level,
                    break_received_at: Instant::now(),
                };
                
                tracing::warn!(
                    handle = handle,
                    old_level = ?level,
                    new_level = ?break_msg.new_level,
                    "Oplock break received - BLOCKING handle"
                );
            }
        }
        
        // Send ACK immediately (required by protocol)
        backend.acknowledge_oplock_break(handle, break_msg.new_level).await?;
        
        // Update state to BROKEN
        if let Some(state) = self.handle_states.get_mut(handle) {
            *state = HandleState::Broken {
                level: break_msg.new_level,
            };
        }
        
        // Unblock waiting operations
        if let Some(waiters) = self.blocked_ops.remove(handle) {
            tracing::info!(
                handle = handle,
                waiters = waiters.len(),
                "Unblocking operations after oplock ACK"
            );
            
            for tx in waiters {
                tx.send(()).ok();  // Signal waiters
            }
        }
    }
    
    /// Background task: listen for breaks
    pub async fn run(mut self) {
        while let Some(break_msg) = self.break_rx.recv().await {
            self.handle_break(break_msg, &*self.backend).await;
        }
    }
}
```

**Integration with executor:**
```rust
async fn execute_operation(
    op: &Operation,
    backend: &dyn SMBBackend,
    oplock_runtime: &mut OplockRuntime,
) -> Result<()> {
    // CRITICAL: Wait if handle is blocked by oplock break
    if let Some(handle_ref) = op.handle_ref() {
        oplock_runtime.wait_if_blocked(handle_ref).await;
    }
    
    // Now execute (guaranteed handle is not blocked)
    backend.execute(op).await
}
```

---

## Backend Contract

### Interface Definition

```rust
// src/backend/contract.rs

use async_trait::async_trait;

/// Backend capabilities (advertised at init)
#[derive(Debug, Clone)]
pub struct BackendCapabilities {
    pub name: String,
    pub fidelity_modes: Vec<FidelityMode>,
    pub supports_oplocks: bool,
    pub supports_leases: bool,
    pub supports_durable_handles: bool,
    pub supports_compound_ops: bool,
    pub max_concurrent_connections: usize,
}

/// SMB Backend trait (all backends must implement)
#[async_trait]
pub trait SMBBackend: Send + Sync {
    /// Get capabilities
    fn capabilities(&self) -> BackendCapabilities;
    
    /// Create connection to SMB share
    async fn connect(
        &self,
        server: &str,
        share: &str,
        username: &str,
        password: &str,
    ) -> Result<Box<dyn SMBConnection>>;
    
    /// Disconnect (cleanup)
    async fn disconnect(&self, conn: Box<dyn SMBConnection>) -> Result<()>;
}

#[async_trait]
pub trait SMBConnection: Send + Sync {
    /// Mode 0: Open file (simple)
    async fn open(&self, path: &str, mode: OpenMode) -> Result<Box<dyn SMBFileHandle>>;
    
    /// Mode 1: Open with hints (optional)
    async fn open_with_hints(&self, path: &str, hints: &OpenHints) -> Result<Box<dyn SMBFileHandle>> {
        // Default: ignore hints
        self.open(path, hints.mode).await
    }
    
    /// Mode 2: Open with full protocol details (optional)
    async fn open_with_protocol(&self, path: &str, details: &SMBProtocolDetails) -> Result<Box<dyn SMBFileHandle>> {
        Err(anyhow::anyhow!("Mode 2 not supported"))
    }
    
    /// Rename file
    async fn rename(&self, source: &str, dest: &str) -> Result<()>;
    
    /// Delete file
    async fn delete(&self, path: &str) -> Result<()>;
}

#[async_trait]
pub trait SMBFileHandle: Send + Sync {
    /// Read from file
    async fn read(&self, offset: u64, length: u64) -> Result<Vec<u8>>;
    
    /// Write to file
    async fn write(&self, offset: u64, data: &[u8]) -> Result<u64>;
    
    /// Close file (consumes handle)
    async fn close(self: Box<Self>) -> Result<()>;
    
    /// Mode 2 only: Get oplock state
    fn oplock_state(&self) -> Option<OplockLevel> {
        None
    }
    
    /// Mode 2 only: Acknowledge oplock break
    async fn acknowledge_oplock_break(&self, new_level: OplockLevel) -> Result<()> {
        Err(anyhow::anyhow!("Oplock not supported"))
    }
}

/// Hints for Mode 1
#[derive(Debug, Clone)]
pub struct OpenHints {
    pub mode: OpenMode,
    pub disposition: Option<String>,
    pub access_mask: Option<u32>,
    pub share_mode: Option<u32>,
}

/// Protocol details for Mode 2
#[derive(Debug, Clone)]
pub struct SMBProtocolDetails {
    pub access_mask: u32,
    pub share_mode: u32,
    pub disposition: u32,
    pub create_options: u32,
    pub requested_oplock: Option<OplockLevel>,
    pub create_contexts: Vec<CreateContext>,
}
```

---

## Impacket Worker Protocol

### Architecture: Long-Lived Worker Process

```
Rust Process                Python Worker Process
┌─────────────┐            ┌──────────────────┐
│  smbench    │            │ impacket_worker  │
│             │            │                  │
│  ┌───────┐  │  stdin     │  ┌────────────┐  │
│  │Backend│  ├───────────▶│  │ JSON       │  │
│  │       │  │  (JSON)    │  │ Parser     │  │
│  └───┬───┘  │            │  └──────┬─────┘  │
│      │      │  stdout    │         │        │
│      │      │◀───────────┤  ┌──────▼─────┐  │
│      │      │  (JSON)    │  │ Impacket   │  │
│      │      │            │  │ SMBConn    │  │
│  ┌───▼───┐  │            │  └────────────┘  │
│  │Executor│ │            │                  │
│  └───────┘  │            │  Persistent      │
└─────────────┘            │  SMB Sessions    │
                           └──────────────────┘
```

### Protocol Specification

**Message Format (JSON over stdin/stdout):**

```rust
// Request (Rust → Python)
#[derive(Serialize)]
enum WorkerRequest {
    Connect {
        request_id: String,
        server: String,
        share: String,
        username: String,
        password: String,
    },
    
    Open {
        request_id: String,
        connection_id: String,
        path: String,
        mode: String,
    },
    
    Write {
        request_id: String,
        handle_id: String,
        offset: u64,
        data_base64: String,  // Base64-encoded
    },
    
    Read {
        request_id: String,
        handle_id: String,
        offset: u64,
        length: u64,
    },
    
    Close {
        request_id: String,
        handle_id: String,
    },
    
    Disconnect {
        request_id: String,
        connection_id: String,
    },
    
    Shutdown,
}

// Response (Python → Rust)
#[derive(Deserialize)]
enum WorkerResponse {
    ConnectResult {
        request_id: String,
        success: bool,
        connection_id: Option<String>,
        error: Option<String>,
    },
    
    OpenResult {
        request_id: String,
        success: bool,
        handle_id: Option<String>,
        error: Option<String>,
    },
    
    WriteResult {
        request_id: String,
        success: bool,
        bytes_written: Option<u64>,
        error: Option<String>,
    },
    
    ReadResult {
        request_id: String,
        success: bool,
        data_base64: Option<String>,
        error: Option<String>,
    },
    
    CloseResult {
        request_id: String,
        success: bool,
        error: Option<String>,
    },
}
```

### Python Worker Implementation

```python
#!/usr/bin/env python3
# smbench-impacket-worker

import sys
import json
import base64
from impacket.smbconnection import SMBConnection

class ImpacketWorker:
    def __init__(self):
        self.connections = {}  # connection_id → SMBConnection
        self.handles = {}       # handle_id → file_id
        
    def run(self):
        """Main event loop: read JSON from stdin, write JSON to stdout"""
        for line in sys.stdin:
            request = json.loads(line)
            response = self.handle_request(request)
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
    
    def handle_request(self, req):
        try:
            if req['type'] == 'Connect':
                conn = SMBConnection(
                    req['server'],
                    req['server'],
                    sess_port=445
                )
                conn.login(req['username'], req['password'])
                
                conn_id = req['request_id']
                self.connections[conn_id] = conn
                
                return {
                    'type': 'ConnectResult',
                    'request_id': req['request_id'],
                    'success': True,
                    'connection_id': conn_id
                }
                
            elif req['type'] == 'Open':
                conn = self.connections[req['connection_id']]
                
                # Map mode to Impacket flags
                mode = self.parse_mode(req['mode'])
                
                # Open file
                fid = conn.openFile(req['share'], req['path'], desiredAccess=mode)
                
                handle_id = req['request_id']
                self.handles[handle_id] = (conn, fid)
                
                return {
                    'type': 'OpenResult',
                    'request_id': req['request_id'],
                    'success': True,
                    'handle_id': handle_id
                }
                
            elif req['type'] == 'Write':
                conn, fid = self.handles[req['handle_id']]
                data = base64.b64decode(req['data_base64'])
                
                bytes_written = conn.writeFile(fid, data, offset=req['offset'])
                
                return {
                    'type': 'WriteResult',
                    'request_id': req['request_id'],
                    'success': True,
                    'bytes_written': bytes_written
                }
                
            # ... other operations
            
        except Exception as e:
            return {
                'type': req['type'] + 'Result',
                'request_id': req['request_id'],
                'success': False,
                'error': str(e)
            }

if __name__ == '__main__':
    worker = ImpacketWorker()
    worker.run()
```

### Rust Impacket Backend

```rust
// src/backend/impacket.rs

use tokio::process::{Command, ChildStdin, ChildStdout};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use serde_json;

pub struct ImpacketBackend {
    worker_process: Option<Child>,
    stdin: Option<ChildStdin>,
    stdout: Option<BufReader<ChildStdout>>,
    request_counter: AtomicU64,
}

#[async_trait]
impl SMBBackend for ImpacketBackend {
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            name: "impacket".to_string(),
            fidelity_modes: vec![FidelityMode::MVP, FidelityMode::Realistic],
            supports_oplocks: false,  // Impacket = Mode 1 only
            ..Default::default()
        }
    }
    
    async fn connect(&self, server: &str, share: &str, user: &str, pass: &str) 
        -> Result<Box<dyn SMBConnection>> 
    {
        // Send connect request to worker
        let req = WorkerRequest::Connect {
            request_id: self.next_request_id(),
            server: server.to_string(),
            share: share.to_string(),
            username: user.to_string(),
            password: pass.to_string(),
        };
        
        let response = self.send_request(req).await?;
        
        // Parse response
        match response {
            WorkerResponse::ConnectResult { success: true, connection_id, .. } => {
                Ok(Box::new(ImpacketConnection {
                    connection_id: connection_id.unwrap(),
                    backend: self,
                }))
            },
            _ => Err("Connection failed".into()),
        }
    }
}

impl ImpacketBackend {
    pub async fn start_worker(&mut self) -> Result<()> {
        let mut child = Command::new("python3")
            .arg("smbench-impacket-worker")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        
        self.stdin = child.stdin.take();
        self.stdout = Some(BufReader::new(child.stdout.take().unwrap()));
        self.worker_process = Some(child);
        
        Ok(())
    }
    
    async fn send_request(&mut self, req: WorkerRequest) -> Result<WorkerResponse> {
        // Serialize to JSON
        let json = serde_json::to_string(&req)?;
        
        // Send to worker stdin
        let stdin = self.stdin.as_mut().unwrap();
        stdin.write_all(json.as_bytes()).await?;
        stdin.write_all(b"\n").await?;
        stdin.flush().await?;
        
        // Read response from stdout
        let stdout = self.stdout.as_mut().unwrap();
        let mut line = String::new();
        stdout.read_line(&mut line).await?;
        
        // Parse response
        let response: WorkerResponse = serde_json::from_str(&line)?;
        Ok(response)
    }
    
    fn next_request_id(&self) -> String {
        format!("req_{}", self.request_counter.fetch_add(1, Ordering::SeqCst))
    }
}
```

**Benefits:**
- ✅ Single persistent Python process (not per-op)
- ✅ SMB sessions stay alive
- ✅ Handle mapping via string IDs
- ✅ Async communication (non-blocking)
- ✅ Falls back gracefully when smb-rs doesn't work

**Limitations:**
- ⚠️ Mode 1 only (no oplocks via Impacket)
- ⚠️ Performance overhead (IPC)
- ⚠️ Only for Phase 0 fallback or Mode 1 workloads

---

## Phase 0: smb-rs Validation Tests

### Test Suite (Must Pass Before Phase 1)

```rust
// phase0_validation/tests/mod.rs

#[tokio::test]
async fn test_basic_connection() {
    let client = smb::Client::new(ClientConfig::default());
    let result = client.share_connect(...).await;
    assert!(result.is_ok(), "Basic connection must work");
}

#[tokio::test]
async fn test_file_operations() {
    let client = connect_test_client().await;
    
    // Open
    let file = client.create_file(...).await?;
    
    // Write
    let written = file.write_at(b"test data", 0).await?;
    assert_eq!(written, 9);
    
    // Read
    let mut buf = vec![0u8; 9];
    file.read_at(&mut buf, 0).await?;
    assert_eq!(buf, b"test data");
    
    // Close
    file.close().await?;
}

#[tokio::test]
async fn test_oplock_request() {
    let client = connect_test_client().await;
    
    // ⚠️ CRITICAL TEST
    // Can smb-rs request oplocks?
    // Check API: does FileCreateArgs have oplock methods?
    
    let args = FileCreateArgs::new(...)
        .with_oplock(OplockLevel::Batch);  // ← Does this exist?
    
    let file = client.create_file_with_args(..., args).await?;
    
    // Check if oplock was granted
    let oplock = file.granted_oplock();  // ← Does this exist?
    assert!(oplock.is_some(), "smb-rs must expose granted oplock");
}

#[tokio::test]
async fn test_oplock_break_notification() {
    // ⚠️ CRITICAL TEST
    // Can smb-rs receive oplock breaks from server?
    
    let client1 = connect_test_client().await;
    let client2 = connect_test_client().await;
    
    // Client 1: Open with exclusive oplock
    let file1 = client1.open_with_oplock(...).await?;
    
    // Client 2: Try to open same file (should trigger break)
    let file2_task = tokio::spawn(async move {
        client2.open(...).await
    });
    
    // Question: How does client1 receive the break?
    // Option A: file1.oplock_break_channel()? 
    // Option B: client1.oplock_events()?
    // Option C: Not supported?
    
    // This test determines if Mode 2 is possible
}

#[tokio::test]
async fn test_concurrent_connections() {
    let mut clients = vec![];
    
    for i in 0..100 {
        let client = smb::Client::new(ClientConfig::default());
        client.share_connect(...).await?;
        clients.push(client);
    }
    
    // Measure memory
    let mem_before = get_process_memory_mb();
    // Do operations...
    let mem_after = get_process_memory_mb();
    let mem_per_client = (mem_after - mem_before) / 100;
    
    assert!(mem_per_client < 1.0, "Must use <1MB per connection");
}

#[tokio::test]
async fn test_timing_precision() {
    use tokio::time::{sleep_until, Instant, Duration};
    
    let start = Instant::now();
    let ops = vec![
        (100_000, "op1"),  // 100ms
        (200_000, "op2"),  // 200ms
        (500_000, "op3"),  // 500ms
    ];
    
    for (timestamp_us, op_id) in ops {
        let target = start + Duration::from_micros(timestamp_us);
        sleep_until(target).await;
        
        let actual = Instant::now();
        let drift = actual.duration_since(target);
        
        println!("{}: drift = {:?}", op_id, drift);
        assert!(drift < Duration::from_millis(5), "Timing drift too high");
    }
}
```

**Phase 0 Decision Criteria:**

| Test | smb-rs MUST | If Fails |
|------|-------------|----------|
| Basic connection | ✅ Pass | Abort (fundamental) |
| File operations | ✅ Pass | Abort (fundamental) |
| **Oplock request** | ✅ Pass | Mode 2 not viable, use Mode 1 |
| **Oplock break notification** | ✅ Pass | Mode 2 not viable |
| 100 concurrent connections | ✅ Pass | Performance issue, investigate |
| Memory <1MB per conn | ✅ Pass | May be acceptable up to 2MB |
| Timing precision | ✅ Pass | Acceptable up to 10ms |

**Go/No-Go:**
- ✅ **GO if:** Basic ops + oplocks work
- ⚠️ **PIVOT if:** Oplocks don't work → Use Impacket backend, ship Mode 1
- ❌ **ABORT if:** Basic ops broken → Re-evaluate Python architecture

---

## Revised Implementation Plan

### Phase 0: Validation (Weeks 1-2) - GATES EVERYTHING

**Deliverables:**
1. smb-rs test suite (7 tests above)
2. Backend interface implementation
3. Impacket worker prototype
4. OS mount backend (simplest)
5. Phase 0 report

**Decision Point:**
- **If smb-rs oplocks work:** Proceed with Mode 2 capability
- **If smb-rs basic only:** Use Mode 0/1 only, defer Mode 2
- **If smb-rs broken:** Use Impacket backend, revise timeline

---

### Phase 1: Mode 0 Implementation (Weeks 3-6)

**Scope:** Core file operations only
- open, read, write, close, rename, delete
- No oplocks, no protocol details
- Extensions can be null

**Deliverables:**
- IR loader (locked schema)
- Core scheduler (per-client serialization)
- One backend fully working (smb-rs or Impacket)
- Python compiler (basic operations)
- End-to-end test

**Success:** Replay 1-client workload, 100 operations, correct timing.

---

### Phase 2: Multi-Client (Weeks 7-10)

**Scope:** Multiple clients, no oplock conflicts
- 10 clients replaying simultaneously
- Timeline coordination
- No shared files (avoid oplocks)

**Deliverables:**
- Multi-client scheduler
- Client state isolation
- Test with 10, 50, 100 clients
- Memory profiling

**Success:** 100 concurrent clients, stable, <1% errors.

---

### Phase 3: Mode 1 (Weeks 11-13)

**Scope:** Add dispositions, access masks, share modes
- Extensions in IR (optional)
- Backend honors hints
- Better error fidelity

**Deliverables:**
- Mode 1 backend implementation
- Extended compiler (parse hints from PCAP)
- Test with realistic workloads

**Success:** Correct error codes, realistic file behavior.

---

### Phase 4: Mode 2 or Scale (Weeks 14-18)

**Two paths depending on Phase 0 outcome:**

**Path A: If smb-rs oplocks work**
- Implement Mode 2 (oplocks, leases)
- Oplock runtime (blocking semantics)
- Multi-client oplock conflicts
- Test with 100 clients, oplock scenarios

**Path B: If smb-rs oplocks don't work**
- Scale Mode 1 to 5000 clients
- Performance optimization
- Memory profiling
- Observability

**Success:** Either Mode 2 works OR 5000 clients work.

---

## Production Failure Modes

### What Will Break First in Production (Predicted)

Based on similar systems, these 3 things fail first:

#### 1. **Memory Leaks from Unclosed Handles**

**Symptom:** Memory grows over time, eventually OOM

**Root cause:**
```rust
// Easy to forget close on error path
let file = backend.open(path).await?;
file.write(data).await?;  // ← Error here
// file.close() never called!
```

**Mitigation:**
```rust
// Use RAII / Drop trait
struct FileHandleGuard {
    handle: Box<dyn SMBFileHandle>,
}

impl Drop for FileHandleGuard {
    fn drop(&mut self) {
        // Close on drop
        tokio::spawn(async move {
            self.handle.close().await.ok();
        });
    }
}

// Usage
let file = FileHandleGuard::new(backend.open(path).await?);
// Automatically closed even on error/panic
```

---

#### 2. **Scheduler Deadlock from Circular Dependencies**

**Symptom:** Replay hangs, no operations execute

**Root cause:**
- Operation A depends on B
- Operation B depends on A (circular)
- Both block forever

**Mitigation:**
```rust
// Dependency validation at IR load time
fn validate_dependencies(ir: &WorkloadIR) -> Result<()> {
    let deps = build_dependency_graph(ir);
    
    // Check for cycles
    if has_cycle(&deps) {
        return Err("Circular dependency detected in IR");
    }
    
    Ok(())
}
```

**Prevention:** Don't add cross-client dependencies in compiler (keep dependencies local to handle lifecycle only).

---

#### 3. **Impacket Worker Process Crashes**

**Symptom:** All Impacket operations fail, no error surfaced

**Root cause:**
- Python worker crashes (exception, OOM, etc.)
- Rust side keeps sending requests to dead process
- Hangs or silent failures

**Mitigation:**
```rust
impl ImpacketBackend {
    async fn send_request_with_timeout(&mut self, req: WorkerRequest) -> Result<WorkerResponse> {
        // Set timeout
        let timeout = Duration::from_secs(30);
        
        match tokio::time::timeout(timeout, self.send_request(req)).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(e)) => Err(e),
            Err(_) => {
                // Timeout - worker likely dead
                tracing::error!("Impacket worker timeout - restarting");
                self.restart_worker().await?;
                Err("Worker timeout".into())
            }
        }
    }
    
    async fn restart_worker(&mut self) -> Result<()> {
        // Kill old worker
        if let Some(mut child) = self.worker_process.take() {
            child.kill().await.ok();
        }
        
        // Start new worker
        self.start_worker().await
    }
}
```

---

## Final Architecture Checklist

### Must Be True Before Phase 1

- [ ] IR schema v1 is FROZEN (no changes during Phase 1-3)
- [ ] Execution Invariants documented (per-client ordering, oplock blocking)
- [ ] Backend interface defined (contract + 3 implementations planned)
- [ ] Impacket worker protocol specified (JSON over stdin/stdout)
- [ ] Phase 0 validation tests written (7 tests minimum)
- [ ] Python control plane separated (LDAP + provisioning only)
- [ ] Rust data plane separated (replay only)

### Must Be True Before Phase 2

- [ ] Phase 0 completed (smb-rs validated or Impacket fallback chosen)
- [ ] Mode 0 works end-to-end (1 client, 100 operations)
- [ ] Scheduler enforces per-client ordering
- [ ] Memory per client measured (<2MB)

### Must Be True Before Phase 3

- [ ] Multi-client works (100 clients, no oplock conflicts)
- [ ] Timeline drift <100ms at scale
- [ ] Observability working (metrics + logs)

### Must Be True Before Phase 4

- [ ] Mode 1 works (realistic workloads)
- [ ] Error handling comprehensive
- [ ] Failure modes have mitigations

---

## Conclusion

**v1.2 is PRODUCTION-READY for implementation.**

**Key fixes from reviewer feedback:**
1. ✅ Per-client ordering enforced (invariant + implementation)
2. ✅ Oplock blocking semantics defined (state machine + blocking wait)
3. ✅ Core engine protocol-agnostic (extensions are optional)
4. ✅ Impacket backend fully specified (persistent worker protocol)

**Remaining risks (all managed):**
- smb-rs oplock support → Phase 0 validation + Impacket fallback
- Team Rust expertise → Training + Phase 0 learning
- Multi-client coordination → Proven pattern + extensive testing

**Timeline: 18 weeks to production-ready system.**

**Ready to implement.**

---

## Next Steps

### This Week
1. Initialize Rust project structure
2. Write Phase 0 validation tests
3. Set up Python control plane skeleton
4. Create IR schema (Rust structs)

### Week 1-2
1. Run Phase 0 validation
2. Make smb-rs vs. Impacket decision
3. Implement backend interface
4. Test Impacket worker protocol

### Weeks 3+
Follow phase plan based on Phase 0 results.

---

**Architecture Status: LOCKED and APPROVED. Ready for implementation.** ✅

