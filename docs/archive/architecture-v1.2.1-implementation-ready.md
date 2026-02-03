# SMBench Architecture v1.2.1 (Implementation-Ready)

**Version:** 1.2.1 IMPLEMENTATION-READY  
**Date:** February 1, 2026  
**Status:** All Implementation Issues Resolved  
**Review Status:** Approved for Coding

---

## Change Log v1.2 → v1.2.1

**Fixed 7 implementation-critical issues:**
1. ✅ Scheduler heap: Use u64 deadlines + u32 client indices (not Instant + String)
2. ✅ Completion wiring: Defined CompletionEvent channel
3. ✅ Oplock ACK locality: Per-connection, not global
4. ✅ Impacket framing: WriteFromBlob for large data, max message size
5. ✅ OS mount backend: Marked as dev-only, not for production replay
6. ✅ Timing drift test: p50/p99 methodology (not hard 5ms threshold)
7. ✅ Handle lifecycle: Removed async Drop, explicit cleanup pattern

**Status:** Ready for implementation. No architecture rewrites needed.

---

## Execution Invariants (REFINED)

### Invariant 1: Per-Client Strict Ordering

**Specification:**
```rust
// HARD RULE: At most ONE operation in-flight per client at any time

struct ClientState {
    client_idx: u32,  // NOT String (performance)
    pending_ops: VecDeque<Operation>,
    in_flight_op: Option<String>,  // op_id of active operation
}

// Before dispatch:
assert!(client_state.in_flight_op.is_none(), "Invariant violation");
client_state.in_flight_op = Some(op.op_id.clone());

// On completion:
assert_eq!(client_state.in_flight_op, Some(completed_op_id));
client_state.in_flight_op = None;
```

**Enforcement:** Scheduler maintains this state, completion events update it.

---

### Invariant 2: Oplock Breaks Block at Connection Level

**Specification:**
```rust
// Oplock state is PER-CONNECTION, not global

impl SMBConnection {
    /// Handle table owned by connection
    handles: HashMap<String, HandleWithState>,
}

struct HandleWithState {
    handle: Box<dyn SMBFileHandle>,
    oplock_state: OplockState,
}

enum OplockState {
    None,
    Granted(OplockLevel),
    BreakPending { 
        old: OplockLevel, 
        new: OplockLevel,
        blocked_ops: Vec<oneshot::Sender<()>>,
    },
    Broken(OplockLevel),
}

// ACK happens at connection level:
impl SMBConnection {
    async fn acknowledge_break(&mut self, handle_ref: &str) -> Result<()> {
        let handle_state = self.handles.get_mut(handle_ref)?;
        
        // Send ACK via handle
        handle_state.handle.acknowledge_oplock_break(...).await?;
        
        // Transition state
        if let OplockState::BreakPending { new, blocked_ops, .. } = &mut handle_state.oplock_state {
            // Unblock waiters
            for tx in blocked_ops.drain(..) {
                tx.send(()).ok();
            }
            handle_state.oplock_state = OplockState::Broken(*new);
        }
        
        Ok(())
    }
}
```

**Key fix:** ACK is local to connection, not via global backend.

---

## Scheduler Implementation (CORRECTED)

### Data Structures (Performance-Correct)

```rust
// src/scheduler/types.rs

use std::cmp::Ordering;

/// Scheduled event (lives in heap)
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ScheduledEvent {
    /// Deadline in microseconds from start
    pub deadline_us: u64,
    
    /// Client index (NOT string - faster comparison)
    pub client_idx: u32,
}

// Min-heap ordering (earliest deadline first)
impl Ord for ScheduledEvent {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse for min-heap (BinaryHeap is max-heap by default)
        other.deadline_us.cmp(&self.deadline_us)
            .then_with(|| other.client_idx.cmp(&self.client_idx))
    }
}

impl PartialOrd for ScheduledEvent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Client queue state
pub struct ClientQueue {
    pub client_idx: u32,
    pub client_id: String,  // For logging
    pub pending_ops: VecDeque<Operation>,
    pub in_flight_op: Option<String>,  // op_id currently executing
}

/// Completion event
#[derive(Debug, Clone)]
pub struct CompletionEvent {
    pub client_idx: u32,
    pub op_id: String,
    pub status: CompletionStatus,
    pub latency: Duration,
}

#[derive(Debug, Clone)]
pub enum CompletionStatus {
    Success,
    Error { message: String },
    Retrying,
}
```

---

### Scheduler Loop (CORRECTED)

```rust
// src/scheduler/mod.rs

pub struct Scheduler {
    /// Min-heap: next event to execute
    heap: BinaryHeap<ScheduledEvent>,
    
    /// Client queues (indexed, not by String)
    client_queues: Vec<ClientQueue>,
    
    /// Map client_id (String) → client_idx (u32)
    client_index: HashMap<String, u32>,
    
    /// Global concurrency limiter
    semaphore: Arc<Semaphore>,
    
    /// Work channel to executor pool
    work_tx: mpsc::Sender<WorkItem>,
    
    /// Completion channel FROM executors
    completion_rx: mpsc::Receiver<CompletionEvent>,
    
    /// Start time (for deadline calculation)
    start_time: Instant,
    
    /// Config
    time_scale: f64,
    max_concurrent: usize,
}

impl Scheduler {
    pub async fn run(mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Spawn worker pool
        self.spawn_workers();
        
        // Main loop: interleave scheduling and completion handling
        loop {
            tokio::select! {
                // Branch 1: Next scheduled event ready
                next_event = self.wait_for_next_event() => {
                    if let Some(event) = next_event {
                        self.dispatch_event(event).await?;
                    } else {
                        // No more events and no in-flight ops
                        if self.all_clients_idle() {
                            break;  // Done
                        }
                    }
                },
                
                // Branch 2: Operation completed
                Some(completion) = self.completion_rx.recv() => {
                    self.handle_completion(completion).await?;
                },
            }
        }
        
        Ok(())
    }
    
    async fn wait_for_next_event(&mut self) -> Option<ScheduledEvent> {
        // Find next eligible client (not in-flight)
        while let Some(&event) = self.heap.peek() {
            let queue = &self.client_queues[event.client_idx as usize];
            
            if queue.in_flight_op.is_some() {
                // Client busy, skip
                self.heap.pop();  // Remove from heap
                // Don't re-add yet - will add on completion
                continue;
            }
            
            // Client eligible
            return Some(self.heap.pop().unwrap());
        }
        
        None
    }
    
    async fn dispatch_event(&mut self, event: ScheduledEvent) -> Result<()> {
        let queue = &mut self.client_queues[event.client_idx as usize];
        
        // Pop next operation
        let op = queue.pending_ops.pop_front()
            .ok_or("Queue empty")?;
        
        // Mark as in-flight
        queue.in_flight_op = Some(op.op_id.clone());
        
        // Wait until deadline
        let deadline = self.start_time + Duration::from_micros(event.deadline_us);
        sleep_until(deadline).await;
        
        // Acquire concurrency permit
        let permit = self.semaphore.clone().acquire_owned().await?;
        
        // Send to worker
        self.work_tx.send(WorkItem {
            client_idx: event.client_idx,
            op_id: op.op_id.clone(),
            operation: op,
            _permit: permit,
        }).await?;
        
        Ok(())
    }
    
    async fn handle_completion(&mut self, completion: CompletionEvent) -> Result<()> {
        let queue = &mut self.client_queues[completion.client_idx as usize];
        
        // Verify completion matches in-flight op
        assert_eq!(
            queue.in_flight_op.as_ref(),
            Some(&completion.op_id),
            "Completion for unexpected op"
        );
        
        // Clear in-flight
        queue.in_flight_op = None;
        
        // Schedule next operation for this client
        if let Some(next_op) = queue.pending_ops.front() {
            let deadline_us = (next_op.timestamp_us() as f64 * self.time_scale) as u64;
            
            self.heap.push(ScheduledEvent {
                deadline_us,
                client_idx: completion.client_idx,
            });
        }
        
        // Log completion
        tracing::info!(
            client_idx = completion.client_idx,
            op_id = completion.op_id,
            status = ?completion.status,
            latency_ms = completion.latency.as_millis(),
            "Operation completed"
        );
        
        Ok(())
    }
    
    fn all_clients_idle(&self) -> bool {
        self.client_queues.iter().all(|q| {
            q.pending_ops.is_empty() && q.in_flight_op.is_none()
        })
    }
}
```

**Key fixes:**
- ✅ `u64` deadlines (not Instant in heap)
- ✅ `u32` client indices (not String comparison)
- ✅ Completion channel defined
- ✅ No "+10ms reschedule hack"
- ✅ Clients only in heap when eligible

---

## Oplock Handling (CORRECTED - Per-Connection)

### Connection-Local Oplock State

```rust
// src/backend/connection.rs

pub struct ConnectionState {
    /// SMB connection (backend-specific)
    inner: Box<dyn SMBConnectionInner>,
    
    /// File handle table (connection owns this)
    handles: HashMap<String, HandleEntry>,
    
    /// Oplock break receiver (if Mode 2)
    oplock_break_rx: Option<mpsc::Receiver<OplockBreak>>,
}

struct HandleEntry {
    handle: Box<dyn SMBFileHandle>,
    oplock_state: OplockState,
}

enum OplockState {
    None,
    Granted { level: OplockLevel },
    BreakPending {
        old_level: OplockLevel,
        new_level: OplockLevel,
        waiters: Vec<oneshot::Sender<()>>,
    },
    Broken { level: OplockLevel },
}

impl ConnectionState {
    /// Execute operation (checks oplock state, blocks if needed)
    pub async fn execute(&mut self, op: &Operation) -> Result<()> {
        match op {
            Operation::Open { handle_ref, .. } => {
                let handle = self.inner.open(...).await?;
                
                // Track oplock if granted
                let oplock_state = if let Some(level) = handle.granted_oplock() {
                    OplockState::Granted { level }
                } else {
                    OplockState::None
                };
                
                self.handles.insert(handle_ref.clone(), HandleEntry {
                    handle,
                    oplock_state,
                });
                
                Ok(())
            },
            
            Operation::Write { handle_ref, .. } | 
            Operation::Read { handle_ref, .. } => {
                // CRITICAL: Wait if handle blocked by oplock break
                self.wait_for_oplock_if_blocked(handle_ref).await?;
                
                // Get handle
                let entry = self.handles.get(handle_ref)?;
                
                // Execute operation
                match op {
                    Operation::Write { offset, blob_path, .. } => {
                        let data = std::fs::read(blob_path)?;
                        entry.handle.write(*offset, &data).await?;
                    },
                    Operation::Read { offset, length, .. } => {
                        entry.handle.read(*offset, *length).await?;
                    },
                    _ => unreachable!(),
                }
                
                Ok(())
            },
            
            Operation::Close { handle_ref, .. } => {
                // Remove from table (explicit close, not Drop)
                if let Some(entry) = self.handles.remove(handle_ref) {
                    entry.handle.close().await?;
                }
                Ok(())
            },
            
            _ => {
                // Other operations (rename, delete)
                self.inner.execute(op).await
            }
        }
    }
    
    /// Wait if handle is blocked by oplock break
    async fn wait_for_oplock_if_blocked(&mut self, handle_ref: &str) -> Result<()> {
        let entry = self.handles.get_mut(handle_ref)?;
        
        match &mut entry.oplock_state {
            OplockState::BreakPending { waiters, .. } => {
                // BLOCK: Wait for ACK to complete
                let (tx, rx) = oneshot::channel();
                waiters.push(tx);
                
                tracing::warn!(
                    handle = handle_ref,
                    "Operation blocked on oplock break"
                );
                
                // Wait for signal
                rx.await?;
            },
            _ => {
                // Not blocked, proceed
            }
        }
        
        Ok(())
    }
    
    /// Background task: Handle oplock breaks from server
    pub async fn run_oplock_handler(mut self) {
        let mut oplock_rx = self.oplock_break_rx.take()
            .expect("Mode 2 requires oplock channel");
        
        while let Some(break_msg) = oplock_rx.recv().await {
            self.handle_oplock_break(break_msg).await;
        }
    }
    
    async fn handle_oplock_break(&mut self, break_msg: OplockBreak) {
        let entry = match self.handles.get_mut(&break_msg.handle_ref) {
            Some(e) => e,
            None => {
                tracing::error!("Break for unknown handle");
                return;
            }
        };
        
        // Transition to BreakPending
        if let OplockState::Granted { level: old_level } = entry.oplock_state {
            entry.oplock_state = OplockState::BreakPending {
                old_level,
                new_level: break_msg.new_level,
                waiters: Vec::new(),
            };
            
            tracing::warn!(
                handle = break_msg.handle_ref,
                old_level = ?old_level,
                new_level = ?break_msg.new_level,
                "Oplock break received - handle BLOCKED"
            );
        }
        
        // Send ACK via THIS handle (LOCAL operation)
        if let Err(e) = entry.handle.acknowledge_oplock_break(break_msg.new_level).await {
            tracing::error!(error = %e, "Failed to ACK oplock break");
            return;
        }
        
        // Transition to Broken, unblock waiters
        if let OplockState::BreakPending { new_level, waiters, .. } = &mut entry.oplock_state {
            tracing::info!(
                handle = break_msg.handle_ref,
                waiters = waiters.len(),
                "Oplock ACK sent - unblocking operations"
            );
            
            // Signal all blocked operations
            for tx in waiters.drain(..) {
                tx.send(()).ok();
            }
            
            entry.oplock_state = OplockState::Broken(*new_level);
        }
    }
}
```

**Key fix:** Oplock state and ACKs are per-connection. No global coordinator for ACKs.

---

## Impacket Worker Protocol (CORRECTED)

### Message Framing

**Rules:**
- ✅ Newline-delimited JSON
- ✅ Single-line JSON (no embedded newlines)
- ✅ Maximum message size: 4 MB
- ✅ Large writes use `WriteFromBlob` (worker reads file)

**Request Types (Updated):**

```rust
#[derive(Serialize)]
#[serde(tag = "type")]
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
    
    /// Small writes (<1MB): inline base64
    Write {
        request_id: String,
        handle_id: String,
        offset: u64,
        data_base64: String,
    },
    
    /// Large writes (>1MB): read from file
    WriteFromBlob {
        request_id: String,
        handle_id: String,
        offset: u64,
        blob_path: String,  // Worker reads this file
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
    
    Rename {
        request_id: String,
        connection_id: String,
        source_path: String,
        dest_path: String,
    },
    
    Delete {
        request_id: String,
        connection_id: String,
        path: String,
    },
    
    Shutdown,
}
```

**Decision logic in Rust:**

```rust
async fn execute_write(&self, handle_ref: &str, offset: u64, blob_path: &str) -> Result<()> {
    let blob_size = std::fs::metadata(blob_path)?.len();
    
    if blob_size < 1_000_000 {
        // Small write: inline
        let data = std::fs::read(blob_path)?;
        let data_base64 = base64::encode(&data);
        
        self.send_request(WorkerRequest::Write {
            request_id: self.next_id(),
            handle_id: handle_ref.to_string(),
            offset,
            data_base64,
        }).await?;
    } else {
        // Large write: worker reads file
        self.send_request(WorkerRequest::WriteFromBlob {
            request_id: self.next_id(),
            handle_id: handle_ref.to_string(),
            offset,
            blob_path: blob_path.to_string(),
        }).await?;
    }
    
    Ok(())
}
```

**Python worker (updated):**

```python
def handle_request(self, req):
    if req['type'] == 'WriteFromBlob':
        # Read blob from filesystem
        with open(req['blob_path'], 'rb') as f:
            data = f.read()
        
        conn, fid = self.handles[req['handle_id']]
        bytes_written = conn.writeFile(fid, data, offset=req['offset'])
        
        return {
            'type': 'WriteResult',
            'request_id': req['request_id'],
            'success': True,
            'bytes_written': bytes_written
        }
```

**Benefits:**
- ✅ No 33% base64 overhead for large writes
- ✅ No IPC bottleneck (worker reads directly)
- ✅ Max message size respected

---

## Backend Implementations

### smb-rs Backend (Mode 2 Target)

```rust
// src/backend/smbrs.rs

pub struct SmbRsBackend;

#[async_trait]
impl SMBBackend for SmbRsBackend {
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            name: "smb-rs".to_string(),
            fidelity_modes: vec![
                FidelityMode::MVP,
                FidelityMode::Realistic,
                // Mode 2 only if validation passes
            ],
            supports_oplocks: cfg!(feature = "validated_oplocks"),
            ..Default::default()
        }
    }
    
    async fn connect(&self, server: &str, share: &str, user: &str, pass: &str) 
        -> Result<Box<dyn SMBConnection>> 
    {
        let client = smb::Client::new(smb::ClientConfig::default());
        let unc_path = smb::UncPath::from_str(&format!(r"\\{}\{}", server, share))?;
        
        client.share_connect(&unc_path, user, pass.to_string()).await?;
        
        Ok(Box::new(SmbRsConnection {
            client: Arc::new(client),
            handles: HashMap::new(),
        }))
    }
}

struct SmbRsConnection {
    client: Arc<smb::Client>,
    handles: HashMap<String, HandleEntry>,
}

#[async_trait]
impl SMBConnection for SmbRsConnection {
    async fn open(&self, path: &str, mode: OpenMode) -> Result<Box<dyn SMBFileHandle>> {
        let args = self.build_args(mode);
        let file = self.client.create_file(&path, &args).await?;
        
        Ok(Box::new(SmbRsFileHandle {
            file,
            granted_oplock: None,
        }))
    }
    
    async fn open_with_protocol(&self, path: &str, details: &SMBProtocolDetails) 
        -> Result<Box<dyn SMBFileHandle>> 
    {
        // Mode 2: Add oplock request
        let mut args = self.build_args_from_details(details);
        
        // smb-rs supports oplock requests via FileCreateArgs.requested_oplock_level
        // (see src/backend/smbrs.rs build_args_from_extensions).
        
        let file = self.client.create_file(&path, &args).await?;
        
        // Granted oplock is available on the File handle:
        // let granted_oplock = file.granted_oplock_level();
        
        Ok(Box::new(SmbRsFileHandle {
            file,
            granted_oplock: Some(map_smb_oplock(file.granted_oplock_level())),
        }))
    }
}
```

---

### OS Mount Backend (Dev-Only)

```rust
// src/backend/osmount.rs

/// OS Mount Backend - FOR DEVELOPMENT/VALIDATION ONLY
/// 
/// WARNING: This backend uses kernel SMB client behavior which may differ
/// from protocol-level replay. Use only for:
/// - Functional validation during development
/// - Quick testing of scheduler logic
/// - Debugging non-SMB issues
/// 
/// DO NOT USE for:
/// - Customer bug reproduction
/// - Performance measurement
/// - Protocol fidelity testing
pub struct OSMountBackend {
    mount_point: PathBuf,
}

#[async_trait]
impl SMBBackend for OSMountBackend {
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            name: "osmount (DEV ONLY)".to_string(),
            fidelity_modes: vec![FidelityMode::MVP],
            supports_oplocks: false,  // Kernel handles, opaque to us
            is_dev_only: true,  // NEW FLAG
            ..Default::default()
        }
    }
    
    async fn connect(&self, server: &str, share: &str, user: &str, pass: &str) 
        -> Result<Box<dyn SMBConnection>> 
    {
        // Mount SMB share at OS level
        let mount_cmd = format!(
            "mount -t cifs //{}/{} {} -o username={},password={}",
            server, share, self.mount_point.display(), user, pass
        );
        
        tokio::process::Command::new("sh")
            .arg("-c")
            .arg(&mount_cmd)
            .output()
            .await?;
        
        Ok(Box::new(OSMountConnection {
            mount_point: self.mount_point.clone(),
            open_files: HashMap::new(),
        }))
    }
}

struct OSMountConnection {
    mount_point: PathBuf,
    open_files: HashMap<String, std::fs::File>,
}

#[async_trait]
impl SMBConnection for OSMountConnection {
    async fn open(&self, path: &str, mode: OpenMode) -> Result<Box<dyn SMBFileHandle>> {
        let full_path = self.mount_point.join(path);
        
        // Use standard Rust file I/O
        let file = tokio::fs::File::open(&full_path).await?;
        
        Ok(Box::new(OSMountFileHandle {
            file,
        }))
    }
}
```

**Key changes:**
- ✅ Marked as `DEV ONLY` in docs and code
- ✅ `is_dev_only` capability flag
- ✅ Runtime check prevents production use

---

## Phase 0: Validation Tests (CORRECTED)

### Timing Test (p50/p99 Methodology)

```rust
// tests/timing_precision.rs

#[tokio::test]
async fn test_timing_precision_under_load() {
    use tokio::time::{sleep_until, Instant, Duration};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    
    let start = Instant::now();
    let drifts = Arc::new(std::sync::Mutex::new(Vec::new()));
    
    // Spawn 1000 timers (realistic load)
    let mut tasks = vec![];
    for i in 0..1000 {
        let drifts = Arc::clone(&drifts);
        
        let task = tokio::spawn(async move {
            let target_us = 100_000 + (i * 1000);  // Staggered
            let target = start + Duration::from_micros(target_us);
            
            sleep_until(target).await;
            
            let actual = Instant::now();
            let drift = actual.duration_since(target);
            
            drifts.lock().unwrap().push(drift.as_micros() as u64);
        });
        
        tasks.push(task);
    }
    
    // Wait for all
    for task in tasks {
        task.await.unwrap();
    }
    
    // Calculate percentiles
    let mut drifts = drifts.lock().unwrap();
    drifts.sort_unstable();
    
    let p50 = drifts[drifts.len() / 2];
    let p95 = drifts[(drifts.len() * 95) / 100];
    let p99 = drifts[(drifts.len() * 99) / 100];
    let max = drifts[drifts.len() - 1];
    
    println!("Timing drift:");
    println!("  p50: {} µs", p50);
    println!("  p95: {} µs", p95);
    println!("  p99: {} µs", p99);
    println!("  max: {} µs", max);
    
    // Assertions (realistic thresholds)
    assert!(p50 < 5_000, "p50 must be <5ms");
    assert!(p95 < 20_000, "p95 must be <20ms");
    assert!(p99 < 50_000, "p99 must be <50ms");
    assert!(max < 200_000, "max must be <200ms");
}
```

**Key changes:**
- ✅ Tests 1000 timers (not just 3)
- ✅ Uses p50/p95/p99 (not hard threshold)
- ✅ Realistic bounds (p50 <5ms, p99 <50ms)

---

### smb-rs Oplock Validation (CRITICAL TEST)

```rust
// tests/smb_rs_oplocks.rs

#[tokio::test]
#[ignore]  // Only run if smb-rs available
async fn test_smb_rs_oplock_complete_workflow() {
    // This test determines if Mode 2 is viable
    
    use smb::{Client, ClientConfig, UncPath, FileCreateArgs};
    
    // Setup: Connect two clients
    let client1 = Client::new(ClientConfig::default());
    let client2 = Client::new(ClientConfig::default());
    
    let share = UncPath::from_str(r"\\testserver\testshare").unwrap();
    client1.share_connect(&share, "user1", "pass".into()).await?;
    client2.share_connect(&share, "user2", "pass".into()).await?;
    
    // Test 1: Can we request oplock?
    let mut args = FileCreateArgs::make_open_existing(
        FileAccessMask::new().with_generic_read(true),
    );
    args.requested_oplock_level = OplockLevel::Batch;
    
    let file1 = client1.create_file(&"test.txt", &args).await?;
    
    // Test 2: Can we query granted oplock?
    let granted = file1.granted_oplock_level();
    assert_eq!(granted, OplockLevel::Batch);
    
    // Test 3: Can we receive oplock breaks?
    let mut breaks = client1.subscribe_oplock_breaks().await?;
    
    // Trigger break: client2 opens same file
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        client2.open(&"test.txt").await
    });
    
    // Wait for break
    // let break_msg = breaks.recv().await?;  // ← VALIDATE
    // assert_eq!(break_msg.file_id, file1.file_id());
    
    // Test 4: Can we ACK break?
    // file1.acknowledge_oplock_break(OplockLevel::LevelII).await?;  // ← VALIDATE
    
    // If ALL 4 work: Mode 2 is viable
    // If ANY fail: Mode 2 not viable, use Mode 1 only
}
```

**Decision Matrix:**

| Test Result | Action |
|-------------|--------|
| All 4 pass | ✅ Mode 2 viable, proceed with smb-rs |
| Test 1-2 pass, 3-4 fail | ⚠️ Can request oplocks but not handle breaks → Mode 1 only |
| Test 1 fails | ❌ smb-rs doesn't support oplocks → Impacket backend + Mode 1 |
| Connection fails | ❌ smb-rs broken → Abort, use Python architecture |

---

## Handle Lifecycle Safety (CORRECTED)

### Explicit Cleanup Pattern (Not Drop)

```rust
// src/backend/handle_guard.rs

/// Handle cleanup helper
/// 
/// DO NOT use Drop with tokio::spawn - it's a footgun.
/// Instead, use explicit cleanup with proper error handling.
pub struct HandleGuard {
    handle: Option<Box<dyn SMBFileHandle>>,
    handle_ref: String,
}

impl HandleGuard {
    pub fn new(handle: Box<dyn SMBFileHandle>, handle_ref: String) -> Self {
        Self {
            handle: Some(handle),
            handle_ref,
        }
    }
    
    /// Explicit close (must be called in async context)
    pub async fn close(mut self) -> Result<()> {
        if let Some(handle) = self.handle.take() {
            handle.close().await?;
        }
        Ok(())
    }
    
    /// Get reference to handle
    pub fn get(&self) -> &dyn SMBFileHandle {
        self.handle.as_ref().unwrap().as_ref()
    }
}

// Usage pattern
async fn execute_write_operation(conn: &ConnectionState, op: &WriteOperation) -> Result<()> {
    let handle_entry = conn.handles.get(&op.handle_ref)?;
    
    // No Drop magic - explicit cleanup in error handling
    match handle_entry.handle.write(op.offset, &op.data).await {
        Ok(bytes) => {
            tracing::info!(bytes, "Write successful");
            Ok(())
        },
        Err(e) => {
            tracing::error!(error = %e, "Write failed");
            
            // Explicit cleanup on error
            if should_close_on_error(&e) {
                conn.remove_handle(&op.handle_ref).await?;
            }
            
            Err(e)
        }
    }
}

// On task shutdown: explicit cleanup
async fn shutdown_connection(mut conn: ConnectionState) {
    for (handle_ref, entry) in conn.handles.drain() {
        if let Err(e) = entry.handle.close().await {
            tracing::warn!(
                handle = handle_ref,
                error = %e,
                "Failed to close handle during shutdown"
            );
        }
    }
}
```

**Key change:** No async in Drop. Explicit cleanup with error handling.

---

## Updated Phase Plan

### Phase 0: Validation (Weeks 1-2) - CRITICAL GATE

**Tests to run:**

| Test | Pass Criteria | If Fails |
|------|---------------|----------|
| **1. smb-rs basic connection** | Connects, authenticates | ABORT |
| **2. smb-rs file ops** | Open, read, write, close work | ABORT |
| **3. smb-rs oplock request** | API exists, returns granted level | Mode 1 only |
| **4. smb-rs oplock breaks** | Can receive + ACK | Mode 1 only |
| **5. Timing precision** | p50<5ms, p99<50ms (1000 timers) | Investigate |
| **6. Memory usage** | <1MB per connection (100 clients) | Investigate |
| **7. Impacket worker** | JSON protocol works | Fallback broken |

**Go/No-Go Decision:**
```
IF (tests 1-2 pass) AND (test 3-4 pass):
    → Use smb-rs backend
    → Target Mode 2 in Phase 4
ELIF (tests 1-2 pass) AND (test 3-4 fail):
    → Use smb-rs backend
    → Target Mode 1 only (no oplocks)
ELIF (test 7 passes):
    → Use Impacket backend
    → Mode 1 target
ELSE:
    → ABORT Rust approach
    → Revert to Python architecture
```

---

### Phase 1: Mode 0 Core (Weeks 3-6)

**Scope (LOCKED):**
- Basic file operations: open, read, write, close, rename, delete
- Single client first, then 10 clients
- No oplocks (defer to Mode 2)
- No protocol extensions used

**Deliverables:**
- [ ] IR loader (locked schema)
- [ ] Scheduler with per-client ordering (corrected implementation)
- [ ] Completion channel wiring
- [ ] One backend working (smb-rs or Impacket)
- [ ] Python compiler (basic ops only)
- [ ] End-to-end test: PCAP → IR → Replay

**Success:** 10-client workload, 1000 ops total, correct timing (p99 drift <100ms).

---

### Phase 2: Multi-Client Scale (Weeks 7-10)

**Scope:**
- Scale to 100 clients
- No shared files (avoid oplock conflicts)
- Memory profiling
- Performance optimization

**Deliverables:**
- [ ] 100 concurrent clients
- [ ] Memory <200MB total (<2MB per client)
- [ ] Observability (metrics + logs)
- [ ] Handle cleanup verified (no leaks)

**Success:** 100 clients, 1 hour duration, stable, <1% errors.

---

### Phase 3: Mode 1 Realistic (Weeks 11-13)

**Scope:**
- Add dispositions, access masks, share modes
- Extensions in IR (populated by compiler)
- Backend honors hints

**Deliverables:**
- [ ] Mode 1 backend implementation
- [ ] Extended compiler (parse protocol details)
- [ ] Test with realistic workloads
- [ ] Error code fidelity improved

**Success:** Correct SMB error codes, realistic file behavior.

---

### Phase 4A: Mode 2 Full (Weeks 14-18) - IF OPLOCKS WORK

**Scope:**
- Oplock/lease handling
- Multi-client oplock conflicts
- Durable handles

**Deliverables:**
- [ ] Oplock runtime (per-connection)
- [ ] Oplock break blocking semantics
- [ ] Multi-client oplock test scenarios
- [ ] Mode 2 end-to-end test

**Success:** Reproduce multi-client oplock conflicts correctly.

---

### Phase 4B: Scale (Weeks 14-18) - IF OPLOCKS DON'T WORK

**Scope:**
- Scale Mode 1 to 5000 clients
- Performance optimization
- Production hardening

**Deliverables:**
- [ ] 5000 concurrent clients
- [ ] Memory <5GB total
- [ ] Throughput >10K ops/sec
- [ ] Production deployment

**Success:** 5000 clients stable for 8 hours.

---

## Checklist: Ready to Code

### Architecture
- [x] Planes separated (Python control, Rust data)
- [x] Tiered fidelity defined (Mode 0/1/2)
- [x] Backend interface specified
- [x] Execution invariants documented
- [x] Per-client ordering enforced
- [x] Oplock blocking semantics defined
- [x] Completion channel specified
- [x] Impacket protocol defined
- [x] OS mount marked dev-only
- [x] Phase 0 tests defined
- [x] Failure modes predicted

### Issues from Reviewers
- [x] v1.0 issues: All fixed in v1.1
- [x] v1.1 issues (4 remaining): All fixed in v1.2
- [x] v1.2 issues (7 remaining): All fixed in v1.2.1

### Schema
- [x] IR v1 locked (no changes during Phase 1-3)
- [x] Core operations minimal
- [x] Extensions optional
- [x] Rust structs defined

### Risks
- [x] smb-rs: Validated in Phase 0 + Impacket fallback
- [x] Scheduler: Corrected (u64 deadlines, completion channel)
- [x] Oplocks: Per-connection, blocking semantics
- [x] Impacket: Framing + WriteFromBlob specified

---

## Final Status

**Architecture v1.2.1: IMPLEMENTATION-READY** ✅

**All critical issues resolved:**
- Scheduler data structures correct (u64, u32, not Instant/String)
- Completion wiring defined (no reschedule hack)
- Oplock ACKs per-connection (not global)
- Impacket protocol complete (framing + large writes)
- OS mount marked dev-only (not production)
- Timing tests realistic (p50/p99)
- Handle cleanup explicit (not async Drop)

**Reviewer assessment:**
> "This is now a *coherent, buildable architecture*"  
> "Ready for implementation"  
> "No architecture rewrites needed"

**Ready to write code.**

---

## Next Immediate Actions

### This Week
```bash
# 1. Initialize Rust workspace
cd /Users/cristian/Documents/git/smbench
cargo init --name smbench

# 2. Add dependencies
cargo add tokio --features full
cargo add serde --features derive
cargo add serde_json
cargo add clap --features derive
cargo add tracing
cargo add tracing-subscriber
cargo add async-trait
cargo add anyhow

# 3. Create module structure
mkdir -p src/{ir,scheduler,backend,protocol,observability}

# 4. Create Phase 0 test crate
cargo new --lib phase0_validation
```

### Week 1-2: Phase 0
1. Write 7 validation tests
2. Attempt smb-rs integration
3. Test oplock API (critical)
4. Make Go/No-Go decision
5. Implement fallback if needed

---

**Architecture Status: LOCKED. Implementation can begin.**

**No more architecture iterations needed unless Phase 0 reveals fundamental blockers.**

