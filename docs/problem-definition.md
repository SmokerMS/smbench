# SMBench: Problem Definition & Requirements

**Version:** 1.0  
**Date:** February 1, 2026  
**Status:** Foundational Document

---

## Executive Summary

**Problem:** Reproducing and debugging SMB file server issues reported by customers is time-consuming, manual, and cannot scale to multi-user scenarios.

**Solution:** SMBench - A tool to capture, analyze, and replay SMB3 workloads with high fidelity for bug reproduction and scaled load testing.

---

## Users & Use Cases

### Primary Users
1. **Developers** (primary) - Debugging file server code, reproducing customer issues
2. **SRE/Support Engineers** - Initial triage, gathering reproduction data
3. **QA Engineers** - Validation testing, regression testing

### Use Case 1: Bug Reproduction (Primary)
**Scenario:** Customer reports issue with application behavior on file server

**Workflow:**
1. SRE captures simultaneous packet trace + server logs at customer site
2. Developer receives PCAP (typically minutes duration, GBs of data, mixed workload)
3. Developer analyzes trace, identifies problematic client/operation sequence
4. Developer uses SMBench to replay in lab environment
5. Bug reproduces → Developer debugs with full server visibility
6. Fix implemented and validated with replay

**Success Criteria:**
- Same operations executed in same order
- Same SMB protocol features used (oplocks, leases, create options)
- Same error conditions manifest
- Server logs show expected behavior

### Use Case 2: Load Testing (Secondary)
**Scenario:** Stress test file server with realistic workload at scale

**Workflow:**
1. Start with representative workload PCAP (1 user)
2. Scale to 5000 concurrent users
3. Each user gets isolated namespace (user1/files, user2/files, etc.)
4. Measure throughput, latency, error rates
5. Identify bottlenecks and scaling limits

**Success Criteria:**
- 5000 concurrent users sustained
- Realistic operation mix preserved
- Performance metrics collected
- System remains stable

---

## Input: Packet Traces

### Capture Details
- **Format:** PCAP/PCAPNG (Wireshark, tcpdump)
- **Content:** Full wire capture - TCP, SMB3, LDAP, DNS, NetBIOS
- **Encryption:** Cleartext (or pre-decrypted with session keys)
- **Duration:** Typically minutes to hours
- **Size:** Gigabytes
- **Clients:** Single or multiple clients in one capture

### Trace Characteristics
- **Mixed workload:** Multiple applications, file types, operation patterns
- **Multiple protocols:** SMB3 (primary), LDAP (authentication), DNS (resolution)
- **Real-world complexity:** Retries, errors, timeouts, oplock breaks, reconnections

### What Needs to Be Extracted
From raw PCAP, identify and extract:
- Client IP addresses and usernames
- SMB session establishment and teardown
- File operation sequences (open, read, write, close, rename, delete, etc.)
- SMB protocol details:
  - Oplock/lease requests and breaks
  - Create contexts (durable handles, leases)
  - Access masks and share modes
  - Error codes and retry patterns
- Timing information:
  - Absolute timestamps
  - Relative delays between operations
  - Multi-client timing relationships

---

## Replay Environment

### Target File Servers
- **Nutanix Files** (primary) - Lab cluster
- **Samba** - Developer workstations
- **Windows Server SMB** - Test VMs

### Environment Differences from Customer
| Aspect | Customer | Lab | Handling |
|--------|----------|-----|----------|
| **AD Domain** | customer.com | lab.local | User mapping |
| **Server Name** | customer-fs01 | lab-files | Path mapping |
| **Share Names** | sales, marketing | testshare | Path mapping |
| **Network** | Customer topology | Lab network | Accept differences |
| **File Paths** | Customer structure | Auto-created | Directory creation |
| **SMB Dialect** | 3.1.1 | 3.1.1 | Must match |

---

## Replay Model: Hybrid Interactive

### Core Principle
**"Preserve recorded timeline, react to real-time protocol events"**

### Scheduled Operations (from PCAP)
Operations are replayed at their recorded timestamps:
```
T=0.000s: Client A opens file.txt (with oplock request)
T=1.000s: Client B opens file.txt
T=2.500s: Client A writes 4KB
T=3.000s: Client A closes file.txt
```

**Timing Preservation:**
- Exact delays between operations are preserved
- Multi-client synchronization maintained
- Can scale timeline (e.g., 0.1x speed, 10x speed) but preserve relative timing

### Reactive Responses (to server)
Tool must respond immediately to server-initiated protocol events:

**Oplock/Lease Breaks:**
```
Server sends oplock break at T=1.05s (not in PCAP timeline)
→ Tool immediately sends oplock break ACK
→ Resume scheduled operations
```

**Connection Failures:**
```
Server drops connection at T=2.3s
→ Tool attempts reconnection with durable handle
→ Resume operations when reconnected
```

**Error Conditions:**
```
Server returns STATUS_SHARING_VIOLATION at T=1.5s
→ Tool logs error
→ May retry based on PCAP behavior or continue
```

### Key Characteristics
- ✅ **Operations:** Scheduled from PCAP timeline
- ✅ **Protocol responses:** Immediate reaction to server
- ✅ **Multi-client:** All clients replayed simultaneously with timing preserved
- ✅ **Fidelity:** Protocol features (oplocks, leases) preserved
- ⚠️ **Timeline drift:** Server responses may cause minor timeline shifts

---

## Mapping & Translation

### Path Mapping
**Customer PCAP:**
```
\\customer-fs01\sales\FY2026\reports\Q1.xlsx
\\customer-fs01\marketing\campaigns\banner.psd
```

**Lab Environment:**
```
\\lab-files\testshare\sales\FY2026\reports\Q1.xlsx
\\lab-files\testshare\marketing\campaigns\banner.psd
```

**Requirements:**
- ✅ User provides mapping: `customer-fs01/sales → lab-files/testshare/sales`
- ✅ Tool auto-creates directory structure before replay
- ✅ Share names can differ (not preserved from PCAP)
- ✅ Relative path structure preserved within share

**DFS Handling:**
- Customer may use DFS namespace paths
- Tool should resolve DFS referrals OR accept direct target mapping
- Lab may or may not have DFS configured

### User Mapping
**Customer PCAP:**
```
User: jsmith@customer.com (SID: S-1-5-21-xxx)
User: mjones@customer.com (SID: S-1-5-21-yyy)
User: alee@customer.com (SID: S-1-5-21-zzz)
```

**Lab Environment:**
```
User: testuser001@lab.local (SID: S-1-5-21-aaa)
User: testuser002@lab.local (SID: S-1-5-21-bbb)
User: testuser003@lab.local (SID: S-1-5-21-ccc)
```

**Requirements:**
- ✅ Map customer users to generic test users (testuser001, testuser002, etc.)
- ✅ Test users pre-created in lab AD
- ✅ Maintain user count (3 customer users → 3 test users)
- ⚠️ Group memberships: Nice to match structure, but not critical
- ❌ Usernames don't need to match
- ❌ SIDs will differ (acceptable)

**For Single-User Debugging:**
- Can map all customer users to one test user (e.g., developer's account)
- Useful for isolating one client's behavior

### File Content
**Customer operations write real data:**
- PowerPoint files (50MB)
- Word documents (2MB)
- Excel spreadsheets (5MB)
- Images, videos, databases

**Replay requirements:**
- ✅ Synthetic data acceptable (zeros, random bytes, patterns)
- ✅ File format structure should match (valid PowerPoint header, etc.)
- ✅ File sizes must match exactly
- ⚠️ Content-aware generation helpful (realistic file structure)
- ❌ Actual customer data NOT required (privacy/security concern)

**Pre-existing files:**
- Tool should NOT require pre-creating files
- Create on first write or lazily as needed

---

## Fidelity Requirements

### Must Preserve (High Fidelity)
| Aspect | Requirement | Rationale |
|--------|-------------|-----------|
| **Operation Sequence** | Exact order | Dependencies, race conditions |
| **Operation Timing** | Exact delays | Timeout scenarios, performance bugs |
| **Multi-client Timing** | Synchronized | Locking conflicts, concurrency bugs |
| **SMB Protocol Features** | Oplocks, leases, create options | Often the source of bugs |
| **Access Patterns** | Read/write offsets, sizes | Data corruption bugs |
| **Error Codes** | Exact NT status codes | Error handling bugs |
| **Retry Behavior** | If client retried, replay retries | Retry logic bugs |

### Can Differ (Acceptable Variance)
| Aspect | Acceptable Difference | Rationale |
|--------|----------------------|-----------|
| **User SIDs** | Different SIDs | Mapped to test users |
| **File Handles** | Server-assigned | Not controlled by client |
| **IP Addresses** | Lab network IPs | Network topology differs |
| **Absolute Timestamps** | Lab time != customer time | Relative timing preserved |
| **Server Names** | lab-files != customer-fs01 | Path mapping handles |
| **Share Names** | Can differ | Path mapping handles |

### Reactive Elements (Runtime Behavior)
| Aspect | Behavior | Rationale |
|--------|----------|-----------|
| **Oplock Breaks** | React immediately to server | Protocol compliance |
| **Lease State Changes** | Handle server notifications | Protocol compliance |
| **Connection Drops** | Reconnect with durable handles | Test resilience |
| **Server Errors** | Log and optionally retry | Test error handling |

---

## Success Criteria

### For Bug Reproduction
**Successful reproduction means:**
1. ✅ All operations from PCAP executed in correct order
2. ✅ Same error conditions manifest (if bug involves errors)
3. ✅ Server logs show expected/problematic behavior
4. ✅ Performance characteristics match (if performance bug)
5. ✅ Protocol state matches (e.g., oplocks granted/broken as expected)

**Observability during replay:**
- Detailed operation log (timestamp, operation, result, latency)
- SMB error codes logged
- Server-side logs correlated by timestamp
- Optional: Capture new PCAP during replay for comparison
- Metrics: operation latency, throughput, error rate

**Validation approach:**
- Compare replay results against expected behavior from PCAP
- Diff analysis: original PCAP vs. replay PCAP
- Server log analysis: expected errors/warnings present

### For Load Testing
**Successful load test means:**
1. ✅ Scaled to target user count (e.g., 5000 users)
2. ✅ System remains stable for test duration
3. ✅ Realistic operation mix preserved across users
4. ✅ Performance metrics collected (latency percentiles, throughput, errors)
5. ✅ Resource utilization measured (CPU, memory, network, IOPS)

---

## Technical Constraints

### Client Platform
- **Primary:** Linux (Ubuntu, RHEL)
- **Secondary:** Windows, macOS (nice to have)
- **Language:** Python 3.9+ (for development velocity)

### Authentication
- **Methods:** Kerberos (primary), NTLM (fallback)
- **Test Users:** Pre-created in lab AD
- **Credentials:** Supplied via config or credential store
- **No:** Password capture from PCAP (security concern)

### Network
- **Connectivity:** Direct L2/L3 connectivity to file server
- **Latency:** Accept lab network latency (different from customer)
- **Bandwidth:** Sufficient for scaled workload
- **No:** Network simulation/throttling (out of scope for v1)

### Scale Targets
- **Bug Reproduction:** 1-10 concurrent users typically
- **Load Testing:** Up to 5000 concurrent users
- **Duration:** Minutes to hours
- **Operation Rate:** Thousands of ops/second aggregate

---

## Workflow & Tool Interface

### Typical Bug Reproduction Workflow

```bash
# Step 1: Extract and compile PCAP to IR
$ smbench compile customer.pcap \
    --filter-client 192.168.1.50 \
    --output workload.ir

# Output: workload.ir (JSON) + blobs/ directory

# Step 2: Configure mapping
$ cat mapping.yaml
server: lab-files.local
share: testshare
users:
  - jsmith@customer.com: testuser001@lab.local
  - mjones@customer.com: testuser002@lab.local
paths:
  - "\\\\customer-fs01\\sales": "\\\\lab-files\\testshare\\sales"

# Step 3: Provision environment (create users, directories)
$ smbench provision \
    --config mapping.yaml \
    --workload workload.ir

# Output: Creates AD users, share directories

# Step 4: Replay workload
$ smbench replay workload.ir \
    --config mapping.yaml \
    --log replay.log \
    --metrics metrics.json

# Output: Executes operations, logs results

# Step 5: Analyze results
$ smbench analyze replay.log \
    --compare customer.pcap \
    --server-logs /var/log/fileserver/
```

### Load Testing Workflow

```bash
# Step 1: Compile single-user workload
$ smbench compile user_workload.pcap -o workload.ir

# Step 2: Generate scaled workload (5000 users)
$ smbench scale workload.ir \
    --users 5000 \
    --user-prefix testuser \
    --path-isolation \
    --time-scale 1.0 \
    --jitter 0.1 \
    -o scaled_workload.ir

# Step 3: Provision 5000 users + directories
$ smbench provision \
    --workload scaled_workload.ir \
    --parallel 50

# Step 4: Run load test
$ smbench replay scaled_workload.ir \
    --duration 3600 \
    --metrics-interval 10 \
    --output results/

# Real-time monitoring
$ smbench monitor results/metrics.json
```

---

## Out of Scope (v1)

### Explicitly NOT Supported
- ❌ **Other protocols:** NFS, S3, iSCSI (SMB3 only)
- ❌ **Packet-perfect replay:** Exact TCP sequence numbers, timing to microsecond
- ❌ **Network simulation:** Latency injection, packet loss, bandwidth throttling
- ❌ **Real-time capture-replay:** Simultaneous capture and replay
- ❌ **Workload generation:** Creating synthetic workloads without PCAP
- ❌ **Server implementation:** Building SMB server (client only)
- ❌ **GUI:** Command-line only
- ❌ **Windows API calls:** No direct Win32 file operations (protocol-level only)

### Future Enhancements (Post-v1)
- ⏳ **Workload synthesis:** Generate workloads from templates
- ⏳ **Network conditions:** Add latency/packet loss simulation
- ⏳ **Multi-server:** Replay against multiple file servers simultaneously
- ⏳ **Continuous replay:** Loop workload for endurance testing
- ⏳ **Record and compare:** Built-in PCAP diff tools
- ⏳ **Encrypted PCAP:** Decrypt using session keys

---

## Key Architectural Implications

### From Bug Reproduction Requirements
1. **High protocol fidelity needed**
   - Must support oplocks, leases, durable handles
   - Must handle server-initiated events (oplock breaks)
   - SMB library must expose low-level protocol details

2. **Hybrid replay model**
   - Scheduler maintains timeline from PCAP
   - Protocol handler reacts to server events
   - Both must coordinate (complex!)

3. **Multi-client coordination**
   - Need true parallel execution (not just async)
   - Shared timeline for synchronization
   - Per-client state tracking

4. **PCAP compiler complexity**
   - Full SMB3 state machine required
   - Oplock/lease state tracking
   - Async operation correlation
   - Error scenario preservation

### From Load Testing Requirements
1. **Scaling mechanism**
   - Clone workload across 5000 users
   - Path isolation per user
   - Efficient connection pooling

2. **Resource constraints**
   - <10KB memory per user state
   - Thousands of operations/second
   - Minimal CPU per operation

3. **Observability at scale**
   - Aggregate metrics (not per-operation logs)
   - Real-time monitoring
   - Percentile calculations

---

## Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| **SMB library incomplete** | High | Critical | Phase 0 validation against real PCAPs |
| **Oplock handling complexity** | High | High | Hybrid model design, extensive testing |
| **Multi-client synchronization** | Medium | High | asyncio + threading model, careful design |
| **PCAP parsing brittleness** | Medium | Medium | Comprehensive test suite, multiple PCAP sources |
| **Scale limits (5000 users)** | Medium | Medium | Connection pooling, resource monitoring |
| **DFS complexity** | Low | Medium | Support direct targets first, DFS later |
| **Authentication issues** | Low | High | Use NTLM fallback, test early |

---

## Success Metrics (Project-Level)

### Development
- ✅ Can replay 95% of customer PCAPs in Phase 1
- ✅ Reproduce known bugs with high fidelity (>90% success rate)
- ✅ Scale to 1000 users in Phase 2, 5000 in Phase 3

### Usage
- ✅ Reduces time to reproduce bug from hours to minutes
- ✅ Enables reproduction of multi-client scenarios (previously impossible)
- ✅ Provides actionable debugging data (logs, metrics, traces)

### Quality
- ✅ <5% false negatives (bug exists but doesn't reproduce)
- ✅ <5% false positives (bug reproduces but not in customer environment)
- ✅ Stable for multi-hour load tests

---

## Next Steps

1. **Review and validate** this problem definition with stakeholders
2. **Lock down** specific PCAP examples to use for Phase 0 validation
3. **Evaluate SMB libraries** (smbprotocol vs. Impacket) against real PCAPs
4. **Design IR schema v1** based on fidelity requirements
5. **Prototype hybrid replay model** with simple PCAP

---

*This document is the foundation for all architectural decisions. Changes require review and approval.*
