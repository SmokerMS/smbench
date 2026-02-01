# SMBench Architecture v1.1 (Revised)

**Version:** 1.1  
**Date:** February 1, 2026  
**Status:** Design Review Corrections Applied  
**Reviewer Feedback:** Addressed all critical concerns

---

## Executive Summary

SMBench is an SMB3 workload replay system with **tiered fidelity modes** for bug reproduction and load testing.

**Key Changes from v1.0:**
1. ✅ Separated control plane (Python) from data plane (Rust)
2. ✅ Added SMB backend interface (not locked to smb-rs)
3. ✅ Fixed scheduler (centralized, not per-client sleep)
4. ✅ Simplified IR (core + optional extensions)
5. ✅ Runtime oplock handling (not scheduled)
6. ✅ Tiered fidelity model (MVP → Realistic → Full)
7. ✅ Security/anonymization support

---

## Core Design Principles

### 1. Separation of Planes

```
Control Plane (Python):
- PCAP parsing
- LDAP provisioning (create AD users)
- Directory creation (mkdir via SMB or LDAP)
- IR generation

Data Plane (Rust):
- IR loading
- SMB replay execution
- Multi-client coordination
- Metrics collection

Observability Plane (Rust):
- Prometheus metrics
- Structured logging
- Real-time monitoring
```

**Key insight:** Don't mix provisioning logic with replay logic.

### 2. Tiered Fidelity Model

| Mode | Features | Use Case | Complexity |
|------|----------|----------|------------|
| **Mode 0 (MVP)** | open, read, write, close, rename, delete | Basic load testing | Low |
| **Mode 1 (Realistic)** | + dispositions, access masks, share modes | Realistic workloads | Medium |
| **Mode 2 (Full)** | + oplocks, leases, durable handles | Bug reproduction | High |

**Implementation:** Start with Mode 0, add Mode 1, then Mode 2.

### 3. Backend Interface (Not Locked to smb-rs)

```rust
// trait for SMB backends
pub trait SMBBackend: Send + Sync {
    async fn connect(&self, server: &str, share: &str, user: &str, pass: &str) -> Result<Connection>;
    async fn open(&self, conn: &Connection, path: &str, mode: OpenMode) -> Result<FileHandle>;
    async fn read(&self, handle: &FileHandle, offset: u64, length: u64) -> Result<Vec<u8>>;
    async fn write(&self, handle: &FileHandle, offset: u64, data: &[u8]) -> Result<u64>;
    async fn close(&self, handle: &FileHandle) -> Result<()>;
    
    // Optional for Mode 2
    fn supports_oplocks(&self) -> bool { false }
    async fn request_oplock(&self, handle: &FileHandle, level: OplockLevel) -> Result<OplockResponse> {
        Err("Not supported".into())
    }
}

// Implementations
struct SmbRsBackend;   // Mode 2 capable (if validated)
struct ImpacketBackend;  // Mode 1 (via Python subprocess)
struct OSMountBackend;   // Mode 0 (simplest)
```

**This prevents existential risk from smb-rs gaps.**

---

## Simplified Workload IR v1 (Core Only)

### Core Schema (Minimal)

```json
{
  "version": 1,
  "metadata": {
    "source": "customer_trace.pcap",
    "duration_seconds": 600.0,
    "client_count": 3
  },
  
  "clients": [
    {
      "client_id": "client_001",
      "operation_count": 1000
    }
  ],
  
  "operations": [
    {
      "op_id": "op_001",
      "client_id": "client_001",
      "timestamp_us": 0,
      "type": "open",
      "path": "Documents/file.txt",
      "mode": "read_write",
      "handle_ref": "h_001"
    },
    {
      "op_id": "op_002",
      "client_id": "client_001",
      "timestamp_us": 100000,
      "type": "write",
      "handle_ref": "h_001",
      "offset": 0,
      "length": 4096,
      "blob": "blobs/abc123.bin"
    },
    {
      "op_id": "op_003",
      "client_id": "client_001",
      "timestamp_us": 200000,
      "type": "close",
      "handle_ref": "h_001"
    }
  ],
  
  "extensions": {
    "smb_protocol": {
      "operations": {
        "op_001": {
          "access_mask": "0x00120089",
          "share_mode": "FILE_SHARE_READ",
          "disposition": "open_or_create",
          "requested_oplock": "BATCH",
          "create_contexts": [...]
        }
      }
    }
  }
}
```

**Key changes:**
- ✅ Core operations are simple
- ✅ Protocol details in `extensions` (optional)
- ✅ Can implement Mode 0 without parsing protocol details
- ✅ Can add Mode 1/2 incrementally

---

## Fixed Scheduler Architecture

### Centralized Scheduler (Not Per-Client Sleep)

```rust
// src/scheduler/centralized.rs

use tokio::sync::mpsc;
use tokio::time::{sleep_until, Instant};
use std::collections::BinaryHeap;

pub struct CentralizedScheduler {
    /// Min-heap of next operation per client
    heap: BinaryHeap<ScheduledOp>,
    
    /// Worker pool (bounded concurrency)
    workers: Vec<Worker>,
    
    /// Channel to send operations to workers
    work_tx: mpsc::Sender<WorkItem>,
    
    /// Maximum concurrent operations
    max_concurrent: usize,
}

impl CentralizedScheduler {
    pub async fn run(&mut self, operations: Vec<Operation>) {
        // Initialize heap with first op per client
        self.initialize_heap(operations);
        
        let start_time = Instant::now();
        
        // Main scheduling loop
        while let Some(scheduled_op) = self.heap.pop() {
            // Wait until operation time
            let target_time = start_time + Duration::from_micros(scheduled_op.timestamp_us);
            sleep_until(target_time).await;
            
            // Send to worker pool (bounded concurrency)
            self.work_tx.send(WorkItem {
                client_id: scheduled_op.client_id,
                operation: scheduled_op.operation,
            }).await?;
            
            // Schedule next operation for this client
            if let Some(next_op) = self.get_next_for_client(&scheduled_op.client_id) {
                self.heap.push(next_op);
            }
        }
    }
}

// Worker pool (bounded)
pub struct Worker {
    work_rx: mpsc::Receiver<WorkItem>,
    smb_backend: Arc<dyn SMBBackend>,
}

impl Worker {
    pub async fn run(mut self) {
        while let Some(work) = self.work_rx.recv().await {
            // Execute operation via backend
            let result = self.smb_backend.execute(&work.operation).await;
            // Handle result...
        }
    }
}
```

**Benefits:**
- ✅ Single timer at any time (not 5000)
- ✅ Bounded concurrency (backpressure)
- ✅ Better resource utilization
- ✅ Scales to 10K+ clients

---

## Runtime Oplock Handling (Fixed)

### Oplock Breaks are Runtime Events

```rust
// src/protocol/oplock.rs

pub struct OplockRuntime {
    /// Active oplocks (updated at runtime)
    active: HashMap<String, OplockState>,
    
    /// Break notifications from server (runtime)
    break_rx: mpsc::Receiver<OplockBreak>,
}

impl OplockRuntime {
    pub async fn handle_break(&mut self, break_msg: OplockBreak) {
        // Server sent break (RUNTIME event, not from PCAP)
        
        let oplock = self.active.get_mut(&break_msg.file_handle)
            .expect("Break for unknown file");
        
        tracing::warn!(
            handle = break_msg.file_handle,
            old_level = oplock.level,
            new_level = break_msg.new_level,
            "Oplock break received (runtime)"
        );
        
        // Must ACK immediately (blocking other ops on this handle)
        self.acknowledge_break(&break_msg).await?;
        
        // Update state
        oplock.level = break_msg.new_level;
    }
}

// In executor: check for breaks before each operation
async fn execute_operation(
    op: &Operation,
    backend: &dyn SMBBackend,
    oplock_runtime: &mut OplockRuntime
) -> Result<()> {
    // 1. Check for pending oplock breaks (non-blocking)
    while let Ok(break_msg) = oplock_runtime.break_rx.try_recv() {
        oplock_runtime.handle_break(break_msg).await?;
    }
    
    // 2. Execute scheduled operation
    backend.execute(op).await?;
    
    // 3. If this op granted an oplock, track it
    if let Operation::Open { protocol_details, .. } = op {
        if protocol_details.has_oplock() {
            oplock_runtime.track_grant(op);
        }
    }
    
    Ok(())
}
```

**Key fix:** Breaks are checked before each operation, not scheduled in timeline.

---

## Separation: Python Control Plane

### Control Plane (Python) - Separate Binary

```python
# smbench-provision (Python CLI)

import ldap3
import subprocess
from typing import List

class ControlPlane:
    """Handles all provisioning (LDAP + directories)"""
    
    def __init__(self, config):
        self.config = config
        self.ldap_conn = self.connect_ldap()
    
    def provision_users(self, workload_ir):
        """Create AD users via LDAP"""
        users_to_create = workload_ir['clients']
        
        # Parallel LDAP user creation
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [
                executor.submit(self.create_ldap_user, user)
                for user in users_to_create
            ]
            for future in as_completed(futures):
                future.result()
    
    def provision_directories(self, workload_ir):
        """Create directory structure on SMB share"""
        # Extract all unique paths
        paths = set()
        for op in workload_ir['operations']:
            if 'path' in op:
                paths.add(os.path.dirname(op['path']))
        
        # Create via SMB (using smbprotocol)
        import smbclient
        smbclient.register_session(...)
        for path in sorted(paths):
            smbclient.makedirs(path, exist_ok=True)

# CLI
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('workload_ir')
    parser.add_argument('--config')
    args = parser.parse_args()
    
    cp = ControlPlane(load_config(args.config))
    cp.provision_users(load_ir(args.workload_ir))
    cp.provision_directories(load_ir(args.workload_ir))
```

**Separate binary:** `smbench-provision` (Python) vs. `smbench` (Rust)

---

## Backend Interface Implementation

```rust
// src/backend/mod.rs

use async_trait::async_trait;

#[async_trait]
pub trait SMBBackend: Send + Sync {
    /// Connect to share
    async fn connect(&self, server: &str, share: &str, user: &str, pass: &str) -> Result<Box<dyn Connection>>;
    
    /// Get backend capabilities
    fn capabilities(&self) -> BackendCapabilities;
}

pub struct BackendCapabilities {
    pub fidelity_mode: FidelityMode,
    pub supports_oplocks: bool,
    pub supports_leases: bool,
    pub supports_durable_handles: bool,
    pub supports_credits: bool,
}

#[async_trait]
pub trait Connection: Send + Sync {
    /// Core operations (Mode 0)
    async fn open(&self, path: &str, mode: OpenMode) -> Result<Box<dyn FileHandle>>;
    
    /// Mode 1: With hints
    async fn open_with_hints(&self, path: &str, hints: &OpenHints) -> Result<Box<dyn FileHandle>> {
        // Default: ignore hints, call simple open
        self.open(path, hints.mode).await
    }
    
    /// Mode 2: With protocol details
    async fn open_with_protocol(&self, path: &str, details: &ProtocolDetails) -> Result<Box<dyn FileHandle>> {
        return Err("Mode 2 not supported by this backend".into());
    }
}

#[async_trait]
pub trait FileHandle: Send + Sync {
    async fn read(&self, offset: u64, length: u64) -> Result<Vec<u8>>;
    async fn write(&self, offset: u64, data: &[u8]) -> Result<u64>;
    async fn close(self: Box<Self>) -> Result<()>;
}

// Backend implementations
pub mod smbrs;      // smb-rs (Mode 2 if capable)
pub mod impacket;   // Impacket via subprocess (Mode 1)
pub mod osmount;    // OS mount + file I/O (Mode 0)
```

### Backend Selection at Runtime

```rust
// src/backend/factory.rs

pub struct BackendFactory;

impl BackendFactory {
    pub fn create(config: &Config) -> Result<Box<dyn SMBBackend>> {
        match config.backend.as_str() {
            "smbrs" => Ok(Box::new(SmbRsBackend::new())),
            "impacket" => Ok(Box::new(ImpacketBackend::new())),
            "osmount" => Ok(Box::new(OSMountBackend::new())),
            "auto" => {
                // Try backends in order of fidelity
                if SmbRsBackend::available() {
                    Ok(Box::new(SmbRsBackend::new()))
                } else if ImpacketBackend::available() {
                    Ok(Box::new(ImpacketBackend::new()))
                } else {
                    Ok(Box::new(OSMountBackend::new()))
                }
            },
            _ => Err("Unknown backend".into()),
        }
    }
}
```

---

## Simplified IR Schema v1 (Core Only)

### Core Operations (Required for Mode 0)

```rust
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Operation {
    Open {
        op_id: String,
        client_id: String,
        timestamp_us: u64,
        path: String,
        mode: OpenMode,  // Simple enum: Read, Write, ReadWrite
        handle_ref: String,
        
        #[serde(skip_serializing_if = "Option::is_none")]
        extensions: Option<serde_json::Value>,
    },
    
    Write {
        op_id: String,
        client_id: String,
        timestamp_us: u64,
        handle_ref: String,
        offset: u64,
        length: u64,
        blob_path: String,
    },
    
    Read {
        op_id: String,
        client_id: String,
        timestamp_us: u64,
        handle_ref: String,
        offset: u64,
        length: u64,
    },
    
    Close {
        op_id: String,
        client_id: String,
        timestamp_us: u64,
        handle_ref: String,
    },
    
    Rename {
        op_id: String,
        client_id: String,
        timestamp_us: u64,
        source_path: String,
        dest_path: String,
    },
    
    Delete {
        op_id: String,
        client_id: String,
        timestamp_us: u64,
        path: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum OpenMode {
    Read,
    Write,
    ReadWrite,
}

// Extensions (optional, in separate object)
#[derive(Debug, Serialize, Deserialize)]
pub struct SMBExtensions {
    pub access_mask: Option<String>,
    pub share_mode: Option<String>,
    pub disposition: Option<String>,
    pub create_options: Option<String>,
    pub requested_oplock: Option<String>,
    pub create_contexts: Option<Vec<CreateContext>>,
}
```

**Benefits:**
- ✅ Simple core operations (implement Mode 0 in days)
- ✅ Extensions can be null (backward compatible)
- ✅ Backend chooses what to honor
- ✅ Not coupled to SMB protocol details

---

## Fixed Scheduler: Centralized with Worker Pool

```rust
// src/scheduler/mod.rs

use tokio::sync::{mpsc, Semaphore};
use tokio::time::{sleep_until, Instant, Duration};
use std::collections::BinaryHeap;
use std::sync::Arc;

pub struct Scheduler {
    /// Priority queue: next op to execute
    heap: BinaryHeap<ScheduledOp>,
    
    /// Concurrency limiter
    semaphore: Arc<Semaphore>,
    
    /// Worker pool
    work_tx: mpsc::Sender<WorkItem>,
    work_rx: mpsc::Receiver<WorkItem>,
    
    /// Configuration
    max_concurrent: usize,
    time_scale: f64,
}

impl Scheduler {
    pub fn new(max_concurrent: usize, time_scale: f64) -> Self {
        let (work_tx, work_rx) = mpsc::channel(max_concurrent * 2);
        
        Self {
            heap: BinaryHeap::new(),
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            work_tx,
            work_rx,
            max_concurrent,
            time_scale,
        }
    }
    
    pub async fn run(
        &mut self,
        operations: Vec<Operation>,
        backend: Arc<dyn SMBBackend>
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Initialize heap
        for op in operations {
            self.heap.push(ScheduledOp::from(op));
        }
        
        // Spawn worker pool
        for _ in 0..self.max_concurrent {
            let work_rx = self.work_rx.clone();
            let backend = Arc::clone(&backend);
            let semaphore = Arc::clone(&self.semaphore);
            
            tokio::spawn(async move {
                Self::worker(work_rx, backend, semaphore).await
            });
        }
        
        // Main scheduler loop
        let start_time = Instant::now();
        
        while let Some(scheduled_op) = self.heap.pop() {
            // Calculate execution time
            let delay = (scheduled_op.timestamp_us as f64 * self.time_scale) as u64;
            let target_time = start_time + Duration::from_micros(delay);
            
            // Wait until time (single timer, not N timers)
            sleep_until(target_time).await;
            
            // Acquire semaphore (backpressure)
            let permit = self.semaphore.acquire().await?;
            
            // Send to worker
            self.work_tx.send(WorkItem {
                operation: scheduled_op.operation,
                _permit: permit,  // Released when work done
            }).await?;
        }
        
        Ok(())
    }
    
    async fn worker(
        mut work_rx: mpsc::Receiver<WorkItem>,
        backend: Arc<dyn SMBBackend>,
        semaphore: Arc<Semaphore>
    ) {
        while let Some(work) = work_rx.recv().await {
            // Execute operation
            let result = backend.execute(&work.operation).await;
            
            // work._permit drops here, releases semaphore
        }
    }
}
```

**Benefits:**
- ✅ Only 1 active timer (not 5000)
- ✅ Bounded concurrency via semaphore
- ✅ Worker pool reuse (no spawn per op)
- ✅ Scales to 10K+ clients

---

## Anonymization & Security

```rust
// src/anonymizer.rs

pub struct Anonymizer {
    user_map: HashMap<String, String>,  // real → anonymous
    path_map: HashMap<String, String>,
}

impl Anonymizer {
    pub fn anonymize_workload(&mut self, ir: &mut WorkloadIR) {
        // Anonymize usernames
        for client in &mut ir.clients {
            let anon_name = self.user_map.entry(client.username.clone())
                .or_insert_with(|| format!("user_{:03}", self.user_map.len()));
            client.username = anon_name.clone();
        }
        
        // Anonymize paths (strip PII)
        for op in &mut ir.operations {
            if let Some(path) = op.path_mut() {
                *path = self.anonymize_path(path);
            }
        }
        
        // Remove source IPs
        for client in &mut ir.clients {
            client.source_ip = None;
        }
    }
    
    fn anonymize_path(&mut self, path: &str) -> String {
        // Replace user-specific paths
        // e.g., "Users/jsmith/Documents" → "Users/user_001/Documents"
        path.to_string()
    }
}
```

### Credentials Management

```yaml
# credentials.yaml (separate from IR, not committed to git)
users:
  - source: "client_001"  # From IR
    username: testuser001@lab.local
    password: !env TESTUSER001_PASSWORD  # From env var

# Never store in IR or commit to repo
```

---

## Tiered Fidelity Implementation

```rust
// src/fidelity.rs

#[derive(Debug, Clone, Copy)]
pub enum FidelityMode {
    /// Mode 0: Basic file operations only
    MVP,
    
    /// Mode 1: Add dispositions, access masks, share modes
    Realistic,
    
    /// Mode 2: Full protocol (oplocks, leases, durable)
    Full,
}

pub struct FidelityManager {
    mode: FidelityMode,
    backend: Arc<dyn SMBBackend>,
}

impl FidelityManager {
    pub async fn execute_open(&self, op: &OpenOperation) -> Result<FileHandle> {
        match self.mode {
            FidelityMode::MVP => {
                // Simple open
                self.backend.open(&op.path, op.mode).await
            },
            
            FidelityMode::Realistic => {
                // With hints
                let hints = op.extensions.as_ref()
                    .and_then(|ext| ext.get("smb_protocol"))
                    .and_then(|smb| parse_hints(smb));
                
                if let Some(hints) = hints {
                    self.backend.open_with_hints(&op.path, &hints).await
                } else {
                    self.backend.open(&op.path, op.mode).await
                }
            },
            
            FidelityMode::Full => {
                // Full protocol
                if !self.backend.capabilities().supports_oplocks {
                    return Err("Backend doesn't support Mode 2".into());
                }
                
                let details = op.extensions.as_ref()
                    .and_then(|ext| ext.get("smb_protocol"))
                    .and_then(|smb| parse_protocol_details(smb))
                    .ok_or("Mode 2 requires protocol extensions")?;
                
                self.backend.open_with_protocol(&op.path, &details).await
            },
        }
    }
}
```

**Usage:**
```bash
# Mode 0: MVP (fastest to implement)
smbench replay workload.json --mode mvp

# Mode 1: Realistic
smbench replay workload.json --mode realistic

# Mode 2: Full fidelity (requires capable backend)
smbench replay workload.json --mode full --backend smbrs
```

---

## Revised Implementation Phases

### Phase 0: Technology Validation (Weeks 1-2) ⚠️ CRITICAL

**Must validate smb-rs capabilities:**

```rust
// phase0_validation/tests/oplock_test.rs

#[tokio::test]
async fn test_smb_rs_oplock_support() {
    let client = smb::Client::new(ClientConfig::default());
    client.share_connect(...).await?;
    
    // Test 1: Can we request oplock?
    let file = client.create_file_with_oplock(...).await;
    assert!(file.is_ok(), "smb-rs must support oplock requests");
    
    // Test 2: Can we receive oplock breaks?
    // (requires second client to trigger break)
    
    // Test 3: Can we acknowledge breaks?
}

#[tokio::test]
async fn test_concurrent_connections() {
    let mut clients = vec![];
    
    // Create 100 clients
    for i in 0..100 {
        let client = smb::Client::new(ClientConfig::default());
        client.share_connect(...).await?;
        clients.push(client);
    }
    
    // Measure memory
    let mem_usage = get_process_memory();
    assert!(mem_usage < 100 * 1024 * 1024, "Should use <1MB per client");
}
```

**Decision criteria:**
- ✅ **If smb-rs passes:** Continue with Rust + smb-rs
- ⚠️ **If smb-rs has gaps:** Implement Impacket backend (Python subprocess)
- ❌ **If smb-rs totally broken:** Fall back to Python architecture

---

### Phase 1: Mode 0 (MVP) - Core File Operations (Weeks 3-6)

**Goal:** Replay basic file operations WITHOUT protocol details

**Scope:**
- ✅ open, read, write, close, rename, delete
- ✅ Timing preservation
- ✅ Multi-client (no oplock coordination needed)
- ❌ No oplocks (yet)
- ❌ No leases (yet)
- ❌ No durable handles (yet)

**Deliverables:**
- Core IR loader
- Backend interface + one implementation
- Simple scheduler (centralized)
- Python compiler (basic operations)
- End-to-end test: PCAP → IR → Replay

**Success:** Replay 1-client workload, basic file ops work.

---

### Phase 2: Mode 1 (Realistic) - Dispositions & Hints (Weeks 7-10)

**Goal:** Add SMB dispositions, access masks, share modes

**Scope:**
- ✅ CREATE_NEW, OPEN_EXISTING, OPEN_OR_CREATE
- ✅ Access masks (READ, WRITE, DELETE)
- ✅ Share modes (SHARE_READ, SHARE_WRITE)
- ❌ Still no oplocks (deferred to Mode 2)

**Deliverables:**
- Extended IR with hints
- Backend implementations honor hints
- Test with realistic workloads
- 100 concurrent clients

**Success:** Realistic file operations, correct error codes.

---

### Phase 3: Mode 2 (Full) - Oplocks & Coordination (Weeks 11-14)

**Goal:** Add oplock/lease handling

**Scope:**
- ✅ Oplock requests (BATCH, EXCLUSIVE, LEVEL_II)
- ✅ Runtime oplock break handling
- ✅ Multi-client coordination
- ✅ Lease support (if backend capable)

**Deliverables:**
- Oplock runtime (channel-based)
- Protocol extensions in IR
- Multi-client oplock test scenarios
- smb-rs backend fully validated

**Success:** Reproduce multi-client oplock conflicts correctly.

---

### Phase 4: Scale & Production (Weeks 15-18)

**Goal:** 5000 users, production-ready

**Scope:**
- ✅ Performance optimization
- ✅ Memory profiling
- ✅ Comprehensive error handling
- ✅ Observability (Prometheus + tracing)
- ✅ Durable handles (if needed)

**Success:** 5000 users, stable for hours, <1% errors.

---

## Revised Risk Assessment

| Risk | v1.0 Assessment | v1.1 Assessment | Mitigation |
|------|-----------------|-----------------|------------|
| **smb-rs incomplete** | Existential | **Managed** | Backend interface + alternatives |
| **Scheduler complexity** | Medium | **Low** | Centralized design proven |
| **IR too complex** | Medium | **Low** | Simplified core + extensions |
| **Oplock handling** | High | **Medium** | Runtime-driven, clear model |
| **Team Rust expertise** | Medium | Medium | Training, Phase 0 learning |
| **Scope creep** | **High** | **Low** | Tiered fidelity prevents |

---

## Comparison: v1.0 vs. v1.1

| Aspect | v1.0 | v1.1 (Revised) | Improvement |
|--------|------|----------------|-------------|
| **Planes** | Mixed | Separated | ✅ Cleaner |
| **Backend** | smb-rs only | Interface + 3 impls | ✅ De-risked |
| **Scheduler** | Per-client sleep | Centralized | ✅ Scalable |
| **IR** | Protocol-heavy | Core + extensions | ✅ Simpler |
| **Oplocks** | Scheduled | Runtime | ✅ Correct |
| **Fidelity** | All-or-nothing | Tiered (0/1/2) | ✅ Shippable |
| **Security** | Not addressed | Anonymization | ✅ Production-ready |
| **Risk** | High (smb-rs) | Medium (mitigated) | ✅ Better |

---

## Answer to Your Rust + LDAP Question

### **Does Rust have what it needs to replace Python + LDAP?**

**Short answer: NO for provisioning, YES for replay.**

**Longer answer:**

**LDAP Provisioning (Control Plane):**
- Python has `ldap3` - mature, well-documented
- Rust has `ldap3` crate - exists but less mature
- **Recommendation:** Keep provisioning in Python
- **Benefit:** Team knows Python, LDAP libraries are proven

**SMB Replay (Data Plane):**
- Rust + smb-rs + tokio is MUCH better than Python for:
  - 5000 concurrent connections
  - SMB credit system
  - Memory efficiency
  - Timing precision
- **Recommendation:** Use Rust here

**Architecture:**
```
Python CLI (smbench-provision):
  - LDAP user creation
  - Directory creation
  - Config management

Rust Engine (smbench):
  - IR loading
  - SMB replay
  - Metrics/logging
```

**Two binaries, clean separation, best of both worlds.**

---

## Final Recommendation

**Build this in phases:**

1. **Week 1-2:** Validate smb-rs (oplock support, 100 connections, memory)
2. **Week 3-6:** Mode 0 (core file ops, no oplocks)
3. **Week 7-10:** Mode 1 (dispositions, share modes)
4. **Week 11-14:** Mode 2 (oplocks if smb-rs capable)
5. **Week 15-18:** Production hardening

**Use Python for:**
- PCAP compilation
- LDAP provisioning  
- User interface/CLI

**Use Rust for:**
- Replay engine
- High concurrency
- Performance-critical paths

**This addresses all reviewer concerns while maintaining the elegance of Rust where it matters most.**

---

**Should I update the main `architecture.md` with these fixes, or do you want to review v1.1 first?**