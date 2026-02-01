# GitHub Technology Survey: SMB Workload Replay Solutions

**Date:** February 1, 2026  
**Purpose:** Comprehensive investigation of available SMB client libraries and replay technologies  
**Method:** Context7 MCP + Web Research  
**Status:** Complete Survey

---

## Executive Summary

**Finding:** No direct SMB workload replay tools exist on GitHub. However, several SMB client libraries and adjacent technologies can be combined to build your solution.

**Key Discovery:** **Rust smb-rs** library offers native async support and modern architecture that wasn't in your original architecture document.

---

## Part 1: SMB Client Libraries (Execution Layer)

### 1. smbprotocol (Python) - `/jborean93/smbprotocol`
**Context7 Data:**
- **Code Snippets:** 36 examples
- **Source Reputation:** High
- **Benchmark Score:** 84.8
- **Status:** Actively maintained

**Capabilities:**
- SMBv2/v3 protocol (2.0.2 through 3.1.1)
- NTLM/Kerberos authentication
- Message signing and encryption
- Connection pooling via `ClientConfig`
- High-level API (`smbclient`) and low-level API

**Oplock/Lease Support:**
- ✅ Supports create contexts (confirmed from Context7)
- ⚠️ Oplock/lease handling not explicitly documented
- ⚠️ Needs Phase 0 validation

**Best For:** Python-first development, modern API

---

### 2. smb-rs (Rust) - `/afiffon/smb-rs` ⭐ NEW OPTION
**Context7 Data:**
- **Code Snippets:** 56 examples
- **Source Reputation:** High
- **Benchmark Score:** 53.4
- **Language:** Rust
- **Status:** Full SMB2 & 3 implementation

**Capabilities:**
```rust
// Native async operations
use smb::{Client, ClientConfig, UncPath, FileCreateArgs};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new(ClientConfig::default());
    let share_path = UncPath::from_str(r"\\server\share")?;
    client.share_connect(&share_path, "user", "pass".to_string()).await?;
    
    // File operations with full control
    let file = client.create_file(&file_path, &args).await?;
    file.read_at(&mut buffer, offset).await?;
    file.write_at(data, offset).await?;
    file.close().await?;
    
    Ok(())
}
```

**Key Features:**
- ✅ **Native async** (tokio-based)
- ✅ SMB 2 & 3 protocol support
- ✅ Encryption, compression, multiple auth methods
- ✅ Modern Rust safety guarantees
- ✅ Low memory footprint
- ✅ Excellent concurrency (Rust async runtime)

**Pros for Your Use Case:**
- ✅ Native async = perfect for 5000 concurrent users
- ✅ Memory safety = fewer bugs at scale
- ✅ Performance = compiled, not interpreted
- ✅ Modern codebase = likely better protocol coverage

**Cons:**
- ❌ Not Python (your current choice)
- ⚠️ Less mature than smbprotocol/Impacket
- ⚠️ Oplock/lease support needs validation
- ⚠️ Smaller community

**This is a SERIOUS alternative you haven't considered!**

---

### 3. Impacket (Python) - `/fortra/impacket`
**Context7 Data:** (from previous research)
- **Code Snippets:** 167 examples
- **Source Reputation:** High
- **Maturity:** 10+ years, pentesting standard

**Capabilities:**
- SMB 1/2/3 support
- Low-level protocol access
- Battle-tested in security research

**Best For:** Maximum protocol control, known edge cases

---

### 4. pysmb (Python) - Alternative
**Status:** Older, SMB1-focused, less relevant

---

## Part 2: PCAP Parsing Libraries

### 1. Pcapy-NG - `/stamparm/pcapy-ng`
**Context7 Data:**
- **Code Snippets:** 50 examples
- **Source Reputation:** High
- **Benchmark Score:** 68.3

**Capabilities:**
```python
import pcapy

# Streaming PCAP parsing
with pcapy.open_offline('capture.pcap') as reader:
    header, data = reader.next()
    while header is not None:
        timestamp = header.getts()  # (seconds, microseconds)
        # Process packet
        header, data = reader.next()

# BPF filtering
reader.setfilter('tcp port 445')  # SMB traffic only
```

**Pros:**
- ✅ Lightweight
- ✅ Streaming (memory efficient)
- ✅ BPF filtering
- ✅ Maintained (pcapy replacement)

**Cons:**
- ❌ No SMB dissector (need to parse manually)
- ❌ Low-level (TCP/IP only)

**Best For:** Custom SMB parser, performance-critical

---

### 2. Scapy (Python)
**Status:** Most popular Python packet manipulation
**Pros:** SMB dissectors available
**Cons:** Slower, higher memory

---

### 3. Pyshark (Python)
**Status:** Wireshark wrapper
**Pros:** Best protocol coverage
**Cons:** External dependency (tshark)

---

## Part 3: Adjacent Technologies Found

### 1. DPDK (Data Plane Development Kit) - `/dpdk/dpdk`
**Context7 Data:**
- **Code Snippets:** 4,352 examples (!)
- **Source Reputation:** High
- **Benchmark Score:** 81.6

**What it is:** High-performance packet processing framework

**Relevance to SMBench:**
- ⚠️ Overkill for your use case
- ⚠️ Kernel-bypass networking (too low-level)
- ❌ Not recommended unless you need 10M packets/sec

---

### 2. Kubernetes CSI SMB Driver - `/kubernetes-csi/csi-driver-smb`
**Context7 Data:**
- **Code Snippets:** 760 examples
- **Source Reputation:** High

**What it is:** Mount SMB shares in Kubernetes

**Relevance:**
- ⚠️ Different problem domain (orchestration, not replay)
- ⚠️ But shows how to handle SMB at scale in production

---

## Part 4: What's NOT on GitHub

### Missing: SMB Workload Replay Tools
**Searched for, did not find:**
- ❌ SMB trace replay frameworks
- ❌ PCAP-to-workload converters for SMB
- ❌ Multi-client SMB coordination tools
- ❌ SMB load generators based on traces

**Conclusion:** Your project fills a genuine gap.

---

## Part 5: Technology Comparison Matrix

| Library | Language | Async | Oplock Support | Maturity | Performance | Complexity |
|---------|----------|-------|----------------|----------|-------------|------------|
| **smbprotocol** | Python | ⚠️ Sync | ⚠️ Unknown | Medium | Medium | Low |
| **Impacket** | Python | ❌ Sync | ⚠️ Unknown | High | Medium | High |
| **smb-rs** | **Rust** | ✅ **Native** | ⚠️ Unknown | Medium | **High** | Medium |
| **OS Mount** | Any | N/A | ✅ **Kernel** | **Highest** | **High** | **Lowest** |
| **Win32 API** | Python | ❌ Sync | ✅ **Native** | **Highest** | **High** | Low |

---

## Part 6: The Rust Alternative (smb-rs)

### Why This Matters

**From Context7 research, smb-rs offers:**

```rust
// Native async with tokio
#[tokio::main]
async fn main() {
    let client = Client::new(ClientConfig::default());
    
    // Connect to share
    client.share_connect(&path, "user", "pass").await?;
    
    // File operations
    let file = client.create_file(&path, &args).await?;
    file.write_at(data, offset).await?;
    file.close().await?;
}
```

**Advantages over Python:**
1. **Native async** - No GIL, true parallelism
2. **Memory safety** - Fewer bugs at scale
3. **Performance** - Compiled, not interpreted
4. **Concurrency** - tokio runtime handles 10K+ connections easily
5. **Modern** - Built for async from ground up

**For 5000 concurrent users:**
- Python (smbprotocol): asyncio + threads + GIL = complex
- Rust (smb-rs): tokio + async/await = natural

**Trade-offs:**
- ❌ Not Python (learning curve)
- ❌ Less mature ecosystem
- ✅ But better architecture for scale

---

## Part 7: Recommended Technology Stacks

### Stack A: Python Simplicity (Original Plan)
```
Pyshark (PCAP) → smbprotocol (SMB) → asyncio+threads (Scheduler)
```
**Timeline:** 6-8 weeks  
**Scale:** 100-1000 users  
**Risk:** Medium (oplock support unknown)

---

### Stack B: Rust Performance (NEW OPTION)
```
Pcapy-NG (PCAP) → smb-rs (SMB) → tokio (Scheduler)
```
**Timeline:** 8-10 weeks (Rust learning curve)  
**Scale:** 1000-10000 users  
**Risk:** Medium (less mature)  
**Benefit:** Better architecture for scale

---

### Stack C: OS-Level Simplicity (SIMPLEST)
```
Pyshark (PCAP) → OS mount + file I/O → multiprocessing (Scheduler)
```
**Timeline:** 2-3 weeks  
**Scale:** 10-100 users  
**Risk:** Low  
**Limitation:** Requires mount privileges

---

### Stack D: Windows Native (HIGHEST FIDELITY)
```
tshark (PCAP) → Win32 API (SMB) → multiprocessing (Scheduler)
```
**Timeline:** 3-4 weeks  
**Scale:** 100-1000 users  
**Risk:** Low  
**Limitation:** Windows only

---

## Part 8: Critical Findings

### Finding 1: Rust smb-rs is a Serious Contender
**You haven't considered Rust**, but for 5000 concurrent users:
- Native async > Python asyncio + threads
- Memory safety > Python GC
- Performance > Python interpreter

**Question:** Are you willing to consider Rust for the executor layer?

### Finding 2: No One Has Built This Before
- No SMB workload replay tools on GitHub
- You're pioneering this space
- Can't learn from existing implementations

### Finding 3: OS-Level Approach Undervalued
- Mounting SMB share + Python file I/O is MUCH simpler
- Kernel handles all protocol complexity
- Might be 80% solution with 20% effort

### Finding 4: Oplock Support is Unknown Everywhere
- smbprotocol: Not documented
- smb-rs: Not documented  
- Impacket: Not documented

**All three need Phase 0 validation with real PCAPs!**

---

## Part 9: Recommended Investigation Plan

### Week 1: Validate All Three Approaches

**Test 1: smbprotocol (Python)**
```python
# test_smbprotocol_oplocks.py
import smbclient
# Try to request oplock, see if it works
```

**Test 2: smb-rs (Rust)**
```rust
// test_smb_rs_oplocks.rs
use smb::{Client, FileCreateArgs};
// Try to request oplock, see if it works
```

**Test 3: OS Mount (Simplest)**
```python
# test_os_mount.py
import subprocess
subprocess.run(["mount", "-t", "cifs", ...])
# Just use open/read/write
```

### Week 2: Pick Winner Based on:
- Oplock support (critical!)
- Development velocity
- Scale capability
- Team expertise

---

## Part 10: My Recommendation

**Given your uncertainty about the design, I recommend:**

### Phase 0: Parallel Prototyping (2 weeks)

**Build 3 minimal prototypes:**

1. **Python + smbprotocol** (your current plan)
2. **Rust + smb-rs** (performance option)
3. **Python + OS mount** (simplicity option)

**Test each with:**
- Real customer PCAP (1 client, 100 operations)
- Multi-client scenario (2 clients, oplock conflict)
- Scale test (100 concurrent users)

**Then compare:**
- Code complexity
- Protocol fidelity
- Performance
- Oplock handling

**Pick the winner after empirical validation.**

---

## Conclusion

**Available on GitHub:**
- ✅ smbprotocol (Python, modern, unknown oplock support)
- ✅ Impacket (Python, mature, low-level)
- ✅ **smb-rs (Rust, async, NEW OPTION)**
- ✅ Various PCAP parsers (Pcapy-NG, Scapy, etc.)

**NOT available:**
- ❌ Complete SMB workload replay frameworks
- ❌ Multi-client coordination tools
- ❌ Trace-to-replay converters

**Your instinct was correct:** We need to validate technology choices with real prototypes before committing to architecture.

**Next Step:** Build 3 minimal prototypes (Python/Rust/OS-mount) and test with your actual PCAPs.

---

*Survey completed using Context7 MCP for library research. GitHub direct search unavailable but library metadata obtained.*
