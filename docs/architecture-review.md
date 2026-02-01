# SMB3 Workload Replay Architecture - Technical Review

**Review Date:** February 1, 2026  
**Reviewer:** AI Architecture Analysis (via Context7 + Technical Research)  
**Document Status:** Comprehensive Assessment

---

## Executive Summary

This architecture represents a **well-thought-out, production-grade design** for SMB3 workload generation at scale. The core principles are sound, the technology choices are appropriate, and the scaling model is correct. However, there are several **critical implementation risks** and **missing specifications** that must be addressed before implementation.

**Overall Assessment:** ⭐⭐⭐⭐☆ (4/5) - Implementable with clarifications

---

## Architecture Strengths

### 1. **Semantic Replay Philosophy** ✅
The decision to replay *filesystem semantics* rather than raw packets is architecturally correct and demonstrates deep understanding of the problem space.

**Why this matters:**
- Avoids brittleness of packet replay (sequence numbers, timing dependencies)
- Enables true horizontal scaling across users
- Makes the IR portable and reusable

### 2. **Plane Separation** ✅
The strict separation of Control, Data, and Observability planes is textbook distributed systems design.

```
Control (LDAP/Provisioning) ≠ Data (SMB Execution) ≠ Observability (Metrics)
```

This prevents:
- LDAP bottlenecks during execution
- Observability overhead affecting performance
- State pollution between provisioning and runtime

### 3. **Scheduler-Driven Concurrency Model** ✅ ✅
**This is the crown jewel of the design.**

The event-driven scheduler with priority queue avoids the classic pitfall of 5000 OS threads:

```python
# Traditional approach (WRONG):
for user in users:
    threading.Thread(target=execute_workload, args=(user,)).start()
    # → 5000 threads = disaster

# Your approach (CORRECT):
while not done:
    user, next_op = scheduler.pop_next()
    execute_op(user, next_op)
    scheduler.schedule_next(user, next_op_time + jitter)
```

**Comparison to production systems:**
- This is how Locust, JMeter, and k6 handle scale
- Matches the cooperative multitasking model of asyncio
- Minimal memory per user (~few KB for state)

### 4. **Immutable IR Contract** ✅
Making the Workload IR immutable, versioned, and content-addressed is excellent engineering:

- **Immutable:** Enables replay reproducibility
- **Versioned:** Allows schema evolution without breaking existing workloads
- **Content-addressed blobs:** Deduplication and integrity verification

This is how Docker images work. It's a proven pattern.

---

## Critical Gaps & Implementation Risks

### 🔴 **CRITICAL: Impacket Suitability Assessment**

**Based on Context7 research of Impacket documentation:**

#### ✅ **What Impacket DOES provide:**
1. **SMB3 protocol support** (including 3.1.1)
   - Version auto-negotiation via `SMBConnection` layer
   - Signing support
   - SMB3 encryption (pending as of latest docs, verify current status)

2. **Basic file operations:**
   ```python
   from impacket.smbconnection import SMBConnection
   
   conn = SMBConnection('target_ip', 445, 'remote_name', 
                        'username', 'password', sign=True)
   # Supports: open, read, write, close, rename, delete
   ```

3. **Connection lifecycle management**
   - Long-lived connections supported
   - NTLM/Kerberos authentication
   - SMB signing/sealing

#### ⚠️ **What Impacket MAY NOT provide adequately:**

1. **Concurrent connection pool management**
   - Impacket is primarily a **penetration testing library**, not a load generator
   - No evidence of built-in connection pooling for 5000+ concurrent sessions
   - You'll need to implement:
     - Connection pool with health checks
     - Reconnection logic on timeout/failure
     - SMB session keep-alive strategy

2. **FileId/TreeId state tracking at scale**
   - Impacket tracks per-connection state
   - **Risk:** State leaks or handle exhaustion over long runs
   - **Mitigation needed:** Periodic handle cleanup, explicit close operations

3. **Error recovery semantics**
   - Impacket will raise exceptions on SMB errors
   - **Your scheduler MUST handle:**
     - `STATUS_FILE_LOCK_CONFLICT` → retry with backoff
     - `STATUS_SHARING_VIOLATION` → user-local retry or skip
     - `STATUS_NETWORK_NAME_DELETED` → full reconnection
     - `STATUS_NOT_FOUND` → graceful skip (path may not exist in scaled namespace)

4. **Rename operation atomicity**
   - **You identified this risk correctly**
   - SMB `SetFileInformation` with rename is **not atomic** like POSIX
   - Windows can report success but leave file in intermediate state
   - **Mitigation:** Verify existence after rename, implement retry logic

#### 🎯 **Recommendation:**
**Create a thin SMBExecutor wrapper** (as you proposed) with:
```python
class SMBExecutor:
    def __init__(self, connection_pool, max_retries=3):
        self.pool = connection_pool
        self.retries = max_retries
    
    def open(self, user, path, mode):
        """Wrap Impacket open with retry logic and handle tracking"""
        
    def write(self, user, fid, offset, data):
        """Wrap write with offset validation and chunking"""
        
    def rename(self, user, src, dst):
        """Wrap rename with verification and rollback"""
```

**Alternative technology stack to consider:**
- **pysmb** (higher-level API, better for application use)
- **smbprotocol** (pure Python SMB2/3, more modern than Impacket)
- **Direct Windows SMB client via subprocess** (if running on Windows)

---

### 🟡 **HIGH PRIORITY: PCAP Compiler State Machine**

**The document says "Track protocol state" but doesn't specify HOW.**

#### Required state tracking for SMB3 PCAP parsing:

1. **Session State:**
   ```
   SessionId → (Username, TargetShare)
   ```

2. **Tree Connect State:**
   ```
   (SessionId, TreeId) → Share path
   ```

3. **Open File State:**
   ```
   (SessionId, TreeId, FileId) → Relative path
   ```

4. **Compound Requests:**
   - SMB3 uses chained operations (CREATE + WRITE in one packet)
   - Your parser must handle:
     - `SMB2_CREATE` → allocates FileId
     - `SMB2_WRITE` → references that FileId *in same packet*
     - Correlation via `MessageId` or inline reference

5. **Async Operations:**
   - SMB3 supports async I/O with `STATUS_PENDING`
   - Completion may arrive in different packet
   - **Decision needed:** How to handle in IR? 
     - Option A: Collapse async to sync in IR
     - Option B: Preserve async semantics (complex)

#### **Missing specification: IR Schema v1**

**You MUST define:**

```json
{
  "version": 1,
  "metadata": {
    "source_pcap": "capture.pcapng",
    "compile_time": "2026-02-01T00:00:00Z",
    "duration_seconds": 3600
  },
  "operations": [
    {
      "op_id": "op_00001",
      "timestamp_us": 1234567890,
      "type": "open",
      "path": "Documents/report.docx",
      "mode": "rw",
      "flags": ["create_if_not_exist"],
      "fid": "fid_00001"  // synthetic handle reference
    },
    {
      "op_id": "op_00002",
      "timestamp_us": 1234568000,
      "type": "write",
      "fid": "fid_00001",
      "offset": 0,
      "length": 4096,
      "blob": "sha256:abcdef..."  // reference to blobs/ directory
    },
    {
      "op_id": "op_00003",
      "timestamp_us": 1234569000,
      "type": "close",
      "fid": "fid_00001"
    }
  ]
}
```

**Critical IR design decisions:**

| Decision | Recommended | Rationale |
|----------|-------------|-----------|
| Handle representation | Synthetic FID strings | Avoid Windows HANDLE confusion |
| Timestamp precision | Microseconds | SMB latency can be sub-ms |
| Blob storage | Content-addressed separate files | Deduplication + streaming |
| Path normalization | Forward slashes, UTF-8 | Cross-platform compatibility |
| Operation ordering | Global sequence, per-user partition | Enables scheduler optimization |

---

### 🟡 **MEDIUM PRIORITY: Control Plane LDAP Operations**

**Your User Map schema is good, but provisioning logic needs detail:**

#### Questions to answer:

1. **OU Creation Strategy:**
   ```
   CN=LoadTest-Run-20260201-001,OU=LoadTesting,DC=domain,DC=com
   ```
   - Parent OU permissions?
   - Cleanup policy on failure?
   - Naming collision handling?

2. **User Creation Performance:**
   - LDAP has no bulk user creation API
   - Creating 5000 users sequentially takes time
   - **Optimization:** Parallelize LDAP binds (10-50 concurrent)
   ```python
   async def create_users_parallel(ldap_conn, users, concurrency=20):
       semaphore = asyncio.Semaphore(concurrency)
       async def create_one(user):
           async with semaphore:
               await ldap_conn.add(user.dn, user.attributes)
       await asyncio.gather(*[create_one(u) for u in users])
   ```

3. **TLD Directory Creation:**
   - **Race condition:** SMB `mkdir` by user 0 and user 4999 simultaneously
   - **Solution:** Control plane creates *all* TLDs before runner starts
   - **Verification:** List share, confirm 5000 directories exist

4. **Password Complexity:**
   - Your example: `"Secret!"` 
   - **Risk:** AD password policy rejection
   - **Solution:** Generate compliant passwords:
     ```python
     import secrets, string
     def generate_ad_password():
         # 12 chars: upper, lower, digit, special
         chars = string.ascii_letters + string.digits + "!@#$"
         return ''.join(secrets.choice(chars) for _ in range(12))
     ```

---

### 🟡 **MEDIUM: Scheduler Implementation Semantics**

**You say "priority queue by next-op time" but don't specify heap structure.**

#### Recommended Implementation:

```python
import heapq
from dataclasses import dataclass, field
from typing import Any

@dataclass(order=True)
class ScheduledOp:
    execute_at: float  # Timestamp in seconds (for heap ordering)
    user_id: str = field(compare=False)
    op_index: int = field(compare=False)
    
class Scheduler:
    def __init__(self):
        self.heap = []  # Min-heap by execute_at
        self.user_states = {}  # user_id → UserState
        
    def schedule(self, user_id: str, op_index: int, delay: float):
        """Schedule next operation for user"""
        execute_at = time.time() + delay
        heapq.heappush(self.heap, ScheduledOp(execute_at, user_id, op_index))
        
    def get_next(self) -> tuple[str, int]:
        """Get next operation to execute (blocks until ready)"""
        while self.heap:
            op = heapq.heappop(self.heap)
            now = time.time()
            if op.execute_at > now:
                # Not ready yet, sleep briefly
                time.sleep(min(0.01, op.execute_at - now))
                heapq.heappush(self.heap, op)  # Re-insert
            else:
                return op.user_id, op.op_index
```

**Jitter Application:**
```python
def apply_jitter(delay: float, jitter_pct: float = 0.1) -> float:
    """Add random jitter to avoid thundering herd"""
    import random
    jitter = delay * jitter_pct * (2 * random.random() - 1)
    return max(0, delay + jitter)
```

**Time Scaling:**
```python
# If original PCAP has 1-hour duration but you want 10-minute replay:
time_scale = 10 * 60 / (60 * 60)  # 0.1667
scaled_delay = original_delay * time_scale
```

---

### 🟢 **LOW PRIORITY: Observability Schema**

**Your metrics list is good. Here's a concrete implementation guide:**

#### Metric Collection Strategy:

```python
from dataclasses import dataclass
from collections import defaultdict
import time

@dataclass
class OpMetric:
    op_type: str
    latency_ms: float
    status_code: int  # SMB NT status
    timestamp: float
    user_id: str

class MetricsCollector:
    def __init__(self):
        self.metrics = []
        self.counters = defaultdict(int)
        
    def record_op(self, user_id: str, op_type: str, 
                  latency: float, status: int):
        self.metrics.append(OpMetric(
            op_type=op_type,
            latency_ms=latency * 1000,
            status_code=status,
            timestamp=time.time(),
            user_id=user_id
        ))
        self.counters[f"{op_type}_count"] += 1
        
    def get_summary(self):
        """Compute percentiles, throughput, error rates"""
        import numpy as np
        
        latencies = [m.latency_ms for m in self.metrics]
        errors = [m for m in self.metrics if m.status_code != 0]
        
        return {
            "total_ops": len(self.metrics),
            "error_rate": len(errors) / len(self.metrics),
            "p50_latency_ms": np.percentile(latencies, 50),
            "p95_latency_ms": np.percentile(latencies, 95),
            "p99_latency_ms": np.percentile(latencies, 99),
            "ops_per_sec": len(self.metrics) / (time.time() - start_time)
        }
```

#### Prometheus Integration (Recommended):

```python
from prometheus_client import Counter, Histogram, Gauge

smb_ops_total = Counter('smb_operations_total', 
                        'Total SMB operations', 
                        ['op_type', 'status'])
smb_op_duration = Histogram('smb_operation_duration_seconds',
                            'SMB operation latency',
                            ['op_type'])
active_users = Gauge('smb_active_users', 'Currently active users')
```

---

## Technology Stack Validation

### ✅ **Python + Impacket**
- **Pros:** Mature SMB3 support, Kerberos integration, well-documented
- **Cons:** Not designed for 5000 concurrent connections, may need tuning
- **Verdict:** Acceptable with custom connection pooling

### ✅ **LDAP for AD provisioning**
- **Recommended library:** `python-ldap` or `ldap3`
- **Note:** Use `ldap3` for better Python 3 support and async operations

### ⚠️ **PCAP parsing**
- **Recommended:** `scapy` or `pyshark`
- **Challenge:** SMB3 reassembly across fragmented TCP
- **Note:** May need to handle:
  - TCP stream reassembly
  - SMB2 chained responses
  - Encrypted SMB3 (if present in capture)

---

## Risk Matrix

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Impacket connection limits | High | Critical | Implement connection pooling + health checks |
| SMB rename semantics | Medium | High | Add verification step after rename |
| LDAP provisioning time | Medium | Medium | Parallelize user creation (20-50 concurrent) |
| Scheduler correctness | Low | Critical | Extensive unit testing + formal verification |
| Handle leaks at scale | Medium | High | Implement periodic handle audit |
| PCAP state tracking bugs | High | Critical | Comprehensive test suite with known PCAPs |

---

## Missing Specifications (Must Define Before Implementation)

### 1. **Workload IR v1 Schema** (CRITICAL)
   - JSON schema with all operation types
   - Blob reference format
   - Handle/FID representation
   - Error semantics

### 2. **Failure & Retry Policy** (HIGH)
   ```
   - Transient errors (network): Retry 3x with exponential backoff
   - Semantic errors (file not found): Skip, log, continue
   - Fatal errors (auth failure): Abort user, continue others
   - Connection loss: Reconnect, resume from last checkpoint
   ```

### 3. **Resource Limits** (HIGH)
   - Max concurrent SMB sessions per runner process
   - Memory limit per user (target: <10KB)
   - Blob cache size (if caching write payloads)
   - LDAP connection pool size

### 4. **Checkpoint/Resume Strategy** (MEDIUM)
   - For 5000-user runs that take hours, you need:
     - Periodic state snapshots
     - Resume from last checkpoint on crash
     - Progress reporting (X% complete)

---

## Recommended Implementation Phases

### Phase 1: Proof of Concept (2-3 weeks)
- [ ] Define IR v1 schema (JSON)
- [ ] Build minimal PCAP compiler (1 user, basic ops)
- [ ] Implement SMBExecutor wrapper around Impacket
- [ ] Test with 10 users, 100 operations

**Success Criteria:** Replay 1 simple PCAP with 10 users, collect metrics

### Phase 2: Scaling Infrastructure (3-4 weeks)
- [ ] Implement event-driven scheduler
- [ ] Add connection pooling
- [ ] Build Control Plane (LDAP provisioning)
- [ ] Test with 100 users, 10,000 operations

**Success Criteria:** 100 concurrent users, stable for 1 hour

### Phase 3: Production Hardening (4-6 weeks)
- [ ] Error handling & retry logic
- [ ] Observability (Prometheus + Grafana)
- [ ] Checkpoint/resume
- [ ] Test with 5000 users, 1M operations

**Success Criteria:** 5000 concurrent users, stable for 8 hours, <1% error rate

---

## Final Recommendations

### ✅ **Do This:**
1. **Lock the IR schema next** (as document suggests)
2. Build SMBExecutor abstraction layer (don't couple to Impacket internals)
3. Start with 10 users, then 100, then 1000 (never jump to 5000 immediately)
4. Implement comprehensive logging from day 1
5. Build a synthetic workload generator (don't wait for real PCAPs)

### ❌ **Don't Do This:**
1. Don't skip the PoC phase (tempting but dangerous)
2. Don't assume Impacket handles connection pooling (it doesn't)
3. Don't ignore SMB error codes (they contain critical state info)
4. Don't try to replay encrypted SMB3 (decrypt first or capture unencrypted)
5. Don't run 5000 users without connection limits (you'll DOS your AD)

---

## Architectural Diagram (Refined)

```
┌─────────────────────────────────────────────────────────────┐
│                    CONTROL PLANE (Pre-Run)                  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────┐    ┌──────────────┐    ┌────────────────┐   │
│  │   PCAP   │───▶│   Compiler   │───▶│  Workload IR   │   │
│  │   File   │    │  (Scapy +    │    │  + Blobs/      │   │
│  └──────────┘    │   StateMgr)  │    └────────┬───────┘   │
│                  └──────────────┘             │           │
│                                               │           │
│  ┌──────────────────────────────┐            │           │
│  │   Provisioner (LDAP Client)  │            │           │
│  ├──────────────────────────────┤            │           │
│  │ 1. Create OU                 │            │           │
│  │ 2. Create 5000 users (async) │            │           │
│  │ 3. Create TLD dirs (SMB)     │            │           │
│  │ 4. Emit User Map JSON        │            │           │
│  └──────────┬───────────────────┘            │           │
│             │                                │           │
│             ▼                                ▼           │
│     ┌────────────┐                  ┌──────────────┐    │
│     │  User Map  │                  │ Workload IR  │    │
│     │   JSON     │                  │  (immutable) │    │
│     └────────────┘                  └──────────────┘    │
└──────────┬────────────────────────────────┬─────────────┘
           │                                │
           └────────────┬───────────────────┘
                        ▼
┌─────────────────────────────────────────────────────────────┐
│                    DATA PLANE (Runtime)                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│              ┌─────────────────────────┐                    │
│              │  Event-Driven Scheduler │                    │
│              │  (Min-Heap by Time)     │                    │
│              └──────────┬──────────────┘                    │
│                         │                                   │
│           ┌─────────────┼─────────────┐                     │
│           ▼             ▼             ▼                     │
│      ┌────────┐    ┌────────┐    ┌────────┐               │
│      │ User 1 │    │ User N │    │User5000│               │
│      │ State  │    │ State  │    │ State  │               │
│      └───┬────┘    └───┬────┘    └───┬────┘               │
│          │             │             │                     │
│          └─────────────┼─────────────┘                     │
│                        ▼                                   │
│              ┌──────────────────┐                          │
│              │   SMBExecutor    │                          │
│              │  (Connection     │                          │
│              │   Pool Manager)  │                          │
│              └────────┬─────────┘                          │
│                       │                                    │
│                       ▼                                    │
│              ┌──────────────────┐                          │
│              │  Impacket SMB3   │                          │
│              │   Client Library │                          │
│              └────────┬─────────┘                          │
└───────────────────────┼─────────────────────────────────────┘
                        │
                        ▼
              ┌─────────────────────┐
              │   Nutanix Files     │
              │   (SMB3 Share)      │
              └─────────────────────┘
                        ▲
                        │
┌───────────────────────┼─────────────────────────────────────┐
│           OBSERVABILITY PLANE (Continuous)                  │
├───────────────────────┼─────────────────────────────────────┤
│                       │                                     │
│  Every operation ─────┘                                     │
│           │                                                 │
│           ▼                                                 │
│  ┌──────────────────┐     ┌────────────────┐              │
│  │ Metrics Collector│────▶│  Prometheus    │              │
│  │ (in-process)     │     │   Exporter     │              │
│  └──────────────────┘     └────────────────┘              │
│                                    │                       │
│  ┌──────────────────┐              ▼                       │
│  │ Structured Logs  │     ┌────────────────┐              │
│  │ (JSON, per-op)   │────▶│   Grafana +    │              │
│  └──────────────────┘     │   Loki         │              │
│                           └────────────────┘              │
└─────────────────────────────────────────────────────────────┘
```

---

## Conclusion

**This architecture is fundamentally sound.** You've made the right high-level decisions:

✅ Semantic replay over packet replay  
✅ Plane separation  
✅ Event-driven scheduler for scale  
✅ Immutable IR contract  

**However, you're at an inflection point.** The next steps require:

1. **Locking the IR schema** (as you identified)
2. **Prototyping the Impacket wrapper** to validate connection assumptions
3. **Building the PCAP compiler state machine** with proper SMB3 tracking

**You are NOT in the "idea phase" anymore.** This is implementable. But don't skip the foundational work:
- IR schema definition
- Error handling policy
- Connection pooling architecture

**Estimated effort to production:**
- Phase 1 (PoC): 2-3 weeks
- Phase 2 (100 users): 3-4 weeks  
- Phase 3 (5000 users): 4-6 weeks
- **Total:** 10-13 weeks with 1-2 engineers

**This is ambitious but achievable.** The design is solid. Now execute systematically.

---

## Next Actions (Prioritized)

1. **Define Workload IR v1 schema** (2 days)
2. **Build minimal PCAP compiler** (5 days)
3. **Prototype SMBExecutor with 10 users** (5 days)
4. **Validate Impacket connection limits** (3 days)
5. **Define failure/retry policy** (2 days)

**After these 5 items, you'll know if this design is production-viable.**

---

*Review completed via Context7 MCP (Impacket documentation), web research (SMB3 protocol), and distributed systems architecture analysis.*
