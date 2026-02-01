# SMBench: Technology Options Matrix

**Date:** February 1, 2026  
**Purpose:** Explore ALL technical approaches before committing to architecture  
**Status:** Decision Matrix

---

## Overview

Before implementing, let's systematically evaluate ALL technology options at each layer of the system.

---

## Layer 1: PCAP Capture → Semantic Operations (COMPILER)

### Option 1A: Scapy (Python)
**What it does:** Parse PCAP, dissect SMB protocol
```python
from scapy.all import rdpcap, SMB2_Header
packets = rdpcap("capture.pcap")
for pkt in packets:
    if pkt.haslayer(SMB2_Header):
        # Extract SMB operation
```

**Pros:**
- ✅ Pure Python, easy to integrate
- ✅ SMB2/3 dissectors available
- ✅ Active community

**Cons:**
- ⚠️ Slow for large PCAPs (GB+)
- ⚠️ TCP reassembly can be tricky
- ⚠️ SMB3 encrypted packets need decryption first

**Best for:** Prototyping, moderate PCAP sizes (<1GB)

---

### Option 1B: Pyshark (Wireshark wrapper)
**What it does:** Use Wireshark's tshark as backend
```python
import pyshark
cap = pyshark.FileCapture('capture.pcap', display_filter='smb2')
for pkt in cap:
    operation = extract_smb_operation(pkt.smb2)
```

**Pros:**
- ✅ Uses Wireshark's battle-tested dissectors
- ✅ Handles SMB3 encryption (if keys available)
- ✅ Excellent protocol coverage

**Cons:**
- ❌ Requires Wireshark/tshark installed
- ❌ External dependency (subprocess calls)
- ⚠️ Slower than native libraries

**Best for:** Maximum protocol fidelity, complex traces

---

### Option 1C: dpkt (Lightweight Python)
**What it does:** Fast, lightweight PCAP parsing
```python
import dpkt
with open('capture.pcap', 'rb') as f:
    pcap = dpkt.pcap.Reader(f)
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        # Manual SMB parsing
```

**Pros:**
- ✅ Very fast
- ✅ Low memory
- ✅ Pure Python

**Cons:**
- ❌ No SMB dissector (must implement yourself)
- ❌ More low-level work

**Best for:** Custom SMB parser, performance-critical

---

### Option 1D: tshark (Direct CLI)
**What it does:** Export PCAP to JSON, parse JSON
```bash
tshark -r capture.pcap -T json > operations.json
python parse_operations.py operations.json
```

**Pros:**
- ✅ Simplest implementation
- ✅ Wireshark's protocol knowledge
- ✅ No Python PCAP library needed

**Cons:**
- ❌ External dependency
- ❌ Less flexible
- ❌ Large JSON files

**Best for:** Quick prototyping, validation

---

### Option 1E: Custom C/C++ Parser with Python Bindings
**What it does:** High-performance parser
**Pros:** Maximum speed
**Cons:** High complexity
**Best for:** Production at massive scale

---

### **COMPILER RECOMMENDATION:**
**Start with:** Pyshark (Option 1B) - maximum protocol coverage  
**Fall back to:** Scapy (Option 1A) if Wireshark dependency is problem  
**Production:** Consider dpkt (Option 1C) with custom SMB parser

---

## Layer 2: Semantic Operations → Execution (EXECUTOR)

### Option 2A: smbprotocol (Pure Python SMB Client)
**What it does:** Python SMB2/3 client library
```python
import smbclient
smbclient.register_session("server", username="user", password="pass")
with smbclient.open_file(r"\\server\share\file.txt", "w") as f:
    f.write(data)
```

**Pros:**
- ✅ Pure Python (easy deployment)
- ✅ MS-SMB2 spec compliant
- ✅ Connection pooling built-in
- ✅ Modern API

**Cons:**
- ⚠️ Oplock/lease support uncertain (needs validation)
- ⚠️ Performance vs. native clients
- ⚠️ Maturity vs. Impacket

**Best for:** Python-first shops, modern API preference

---

### Option 2B: Impacket (Mature Python SMB)
**What it does:** SMB protocol implementation
```python
from impacket.smbconnection import SMBConnection
conn = SMBConnection(...)
fid = conn.openFile(...)
conn.writeFile(fid, data)
```

**Pros:**
- ✅ Very mature (10+ years)
- ✅ Battle-tested in pentesting
- ✅ Low-level control
- ✅ Known to handle edge cases

**Cons:**
- ❌ No connection pooling (manual)
- ❌ Lower-level API (more code)
- ⚠️ Designed for pentesting not load generation

**Best for:** Maximum control, known edge cases

---

### Option 2C: OS-Level Mount + Python File I/O
**What it does:** Use kernel SMB client
```python
# One-time setup
subprocess.run(["mount", "-t", "cifs", "//server/share", "/mnt/test"])

# Then standard file operations
with open("/mnt/test/file.txt", "w") as f:
    f.write(data)
```

**Pros:**
- ✅ Perfect protocol fidelity (kernel client)
- ✅ Simplest code
- ✅ Automatic oplock/lease handling
- ✅ Leverages OS optimizations

**Cons:**
- ❌ Requires mount privileges (root/sudo)
- ❌ One mount per user (complexity for multi-user)
- ⚠️ Less visibility into protocol details

**Best for:** Simple bug reproduction, single user scenarios

---

### Option 2D: Windows SMB Client (Run on Windows)
**What it does:** Use Windows native SMB via Win32 API
```python
import win32file

# Direct Win32 file operations over UNC paths
handle = win32file.CreateFile(r"\\server\share\file.txt", ...)
win32file.WriteFile(handle, data)
win32file.CloseHandle(handle)
```

**Pros:**
- ✅ **Perfect protocol fidelity** (Windows SMB client)
- ✅ Native oplock/lease/durable handle support
- ✅ Battle-tested (billions of users)
- ✅ Full control via Win32 API

**Cons:**
- ❌ Windows only
- ⚠️ Requires pywin32 or ctypes

**Best for:** Maximum fidelity, Windows-based testing

---

### Option 2E: libsmbclient (Samba Client Library)
**What it does:** Use Samba's C library via ctypes/cffi
```python
from ctypes import *
libsmb = CDLL("libsmbclient.so")
# Call Samba client functions
```

**Pros:**
- ✅ Mature (Samba project)
- ✅ Full SMB implementation
- ✅ Cross-platform

**Cons:**
- ❌ C library binding complexity
- ❌ Less Pythonic

**Best for:** Need mature library, okay with C bindings

---

### **EXECUTOR RECOMMENDATION:**
**For Bug Reproduction:** Option 2D (Windows native) or 2C (OS mount)  
**For Load Testing:** Option 2A (smbprotocol) or 2B (Impacket)  
**For Maximum Simplicity:** Option 2C (OS mount)

---

## Layer 3: Multi-Client Coordination (SCHEDULER)

### Option 3A: asyncio + ThreadPoolExecutor (Hybrid)
**What it does:** Event loop for timing, threads for I/O
```python
import asyncio
from concurrent.futures import ThreadPoolExecutor

async def schedule_operations():
    executor = ThreadPoolExecutor(max_workers=100)
    while ops:
        await asyncio.sleep(next_op_delay)
        loop.run_in_executor(executor, execute_smb_op, op)
```

**Pros:**
- ✅ Precise timing control
- ✅ Handles blocking I/O
- ✅ Single process

**Cons:**
- ⚠️ Complex (two concurrency models)
- ⚠️ GIL contention at high scale

**Best for:** 100-1000 concurrent users

---

### Option 3B: Multiprocessing (Simple Parallel)
**What it does:** One process per user/client
```python
from multiprocessing import Process

processes = []
for user in users:
    p = Process(target=replay_user, args=(user, operations))
    p.start()
    processes.append(p)
```

**Pros:**
- ✅ Simplest model
- ✅ True parallelism (no GIL)
- ✅ Process isolation

**Cons:**
- ⚠️ Higher memory (process per user)
- ⚠️ Harder cross-client coordination
- ⚠️ IPC complexity for synchronization

**Best for:** Moderate scale (10-100 users), simple coordination

---

### Option 3C: Pure Threading
**What it does:** One thread per user
```python
import threading

threads = []
for user in users:
    t = threading.Thread(target=replay_user, args=(user, ops))
    t.start()
    threads.append(t)
```

**Pros:**
- ✅ Simple
- ✅ Shared memory (easy coordination)

**Cons:**
- ❌ GIL bottleneck at scale
- ❌ High memory for 5000 threads

**Best for:** Small scale (<100 users)

---

### Option 3D: Event-Driven (heapq-based)
**What it does:** Single-threaded event loop
```python
import heapq

while heap:
    next_time, user, op = heapq.heappop(heap)
    sleep_until(next_time)
    execute(user, op)
    schedule_next(user, next_op)
```

**Pros:**
- ✅ Minimal memory per user
- ✅ Precise timing control
- ✅ Scales to 5000+ users

**Cons:**
- ⚠️ Complex with blocking I/O
- ⚠️ Need async SMB client (doesn't exist)

**Best for:** Pure async, non-blocking I/O

---

### Option 3E: Go Goroutines (Different Language)
**What it does:** Go's native concurrency
```go
for _, user := range users {
    go replayUser(user, operations)
}
```

**Pros:**
- ✅ Excellent concurrency model
- ✅ Low memory per goroutine
- ✅ Great performance

**Cons:**
- ❌ Not Python
- ❌ Less mature SMB libraries

**Best for:** Performance-critical, willing to use Go

---

### **SCHEDULER RECOMMENDATION:**
**For Bug Reproduction:** Option 3B (Multiprocessing) - simple, isolated  
**For Load Testing:** Option 3A (asyncio + threads) - scales better  
**For Simplicity:** Option 3C (Threading) - if <100 users

---

## Complete Architecture Options

### **Option Matrix A: Simplicity First** 🥇

| Layer | Choice | Rationale |
|-------|--------|-----------|
| **Compiler** | Pyshark | Wireshark protocol knowledge |
| **Executor** | **OS Mount + Python file I/O** | Kernel handles SMB complexity |
| **Scheduler** | Multiprocessing | Simple, scales to 100 users |

**Complexity:** LOW  
**Fidelity:** VERY HIGH (OS SMB client)  
**Scale:** 10-100 users  
**Time to MVP:** 2-3 weeks

---

### **Option Matrix B: Protocol Control** 🔧

| Layer | Choice | Rationale |
|-------|--------|-----------|
| **Compiler** | Scapy | Full control, Python native |
| **Executor** | **Impacket** | Low-level protocol access |
| **Scheduler** | asyncio + ThreadPoolExecutor | Precise timing |

**Complexity:** HIGH  
**Fidelity:** HIGH (manual protocol handling)  
**Scale:** 100-1000 users  
**Time to MVP:** 8-12 weeks

---

### **Option Matrix C: Modern Stack** ⚡

| Layer | Choice | Rationale |
|-------|--------|-----------|
| **Compiler** | Pyshark | Protocol coverage |
| **Executor** | **smbprotocol** | Modern API, connection pooling |
| **Scheduler** | asyncio + ThreadPoolExecutor | Balance simplicity/scale |

**Complexity:** MEDIUM  
**Fidelity:** HIGH (assuming oplock support)  
**Scale:** 100-5000 users  
**Time to MVP:** 6-8 weeks

---

### **Option Matrix D: Windows Native** 🪟

| Layer | Choice | Rationale |
|-------|--------|-----------|
| **Compiler** | Pyshark or tshark | Reuse Wireshark |
| **Executor** | **Windows Win32 API (pywin32)** | Perfect fidelity |
| **Scheduler** | Multiprocessing | Simple |

**Complexity:** LOW-MEDIUM  
**Fidelity:** **PERFECT** (Windows SMB client)  
**Scale:** 100-1000 users  
**Time to MVP:** 3-4 weeks  
**Constraint:** Windows only

---

### **Option Matrix E: Hybrid Simplicity** 🎯

| Layer | Choice | Rationale |
|-------|--------|-----------|
| **Compiler** | **tshark JSON export** | Simplest, no library |
| **Executor** | **OS mount + file I/O** | Kernel SMB client |
| **Scheduler** | **Threading** | Simplest coordination |

**Complexity:** **VERY LOW**  
**Fidelity:** VERY HIGH (OS client)  
**Scale:** 10-100 users  
**Time to MVP:** **1-2 weeks**

---

## The Missing Option: Don't Parse PCAP At All?

### Option F: Instrumentation-Based Capture
**Instead of parsing PCAP, what if you:**

1. **Use Windows ETW (Event Tracing for Windows)**
   - Capture SMB client operations directly from Windows
   - Get semantic operations without PCAP parsing
   ```powershell
   # Capture SMB operations natively
   logman start SMBTrace -p Microsoft-Windows-SMBClient -o trace.etl
   ```

2. **Use Linux eBPF/ftrace**
   - Trace kernel VFS operations
   - Get file operations without SMB parsing
   ```bash
   bpftrace -e 'tracepoint:syscalls:sys_enter_open { ... }'
   ```

3. **Use Samba audit logging**
   - If server is Samba, enable full audit
   - Get operations from server logs
   ```ini
   [global]
   full_audit:success = open write close
   ```

**Pros:**
- ✅ No PCAP parsing needed
- ✅ Already semantic operations
- ✅ High fidelity

**Cons:**
- ❌ Requires access to client/server OS
- ❌ Platform-specific

---

## Decision Framework

### Question 1: What's Your Primary Constraint?

**If TIME is critical (need MVP in 2-4 weeks):**
→ **Option E (Hybrid Simplicity)** or **Option A (Simplicity First)**

**If FIDELITY is critical (must reproduce 100% of bugs):**
→ **Option D (Windows Native)** - perfect Windows SMB client

**If SCALE is critical (5000 users):**
→ **Option C (Modern Stack)** - smbprotocol + asyncio

**If PROTOCOL CONTROL is critical:**
→ **Option B (Protocol Control)** - Impacket

---

### Question 2: What's Your Platform?

**Running on Windows:**
→ **Option D wins** - use native Win32 API

**Running on Linux only:**
→ **Option A or C** - Python libraries

**Cross-platform needed:**
→ **Option C** - smbprotocol

---

### Question 3: What's Your Expertise?

**Strong Python, want simplicity:**
→ **Option E** - tshark + OS mount + threading

**Strong systems programming:**
→ **Option B** - Impacket + custom everything

**Willing to learn as you go:**
→ **Option C** - smbprotocol (balanced)

---

### Question 4: What's Your Real Goal?

**Reproduce 1 specific bug:**
→ **Option E or A** - simplest path

**Build production testing framework:**
→ **Option C** - scales best

**Research project / thesis:**
→ **Option B** - full control

---

## My Current Assessment of What You've Been Designing

**Your architecture document suggests:** Option C (Modern Stack)
- Scapy for parsing
- smbprotocol for execution  
- Event-driven scheduler

**But I suspect you might want:** Option A or E (Simplicity First)
- Based on your uncertainty
- Based on "just reproduce the bug" use case
- Based on wanting to start simple

---

## Rapid Prototyping Approach

**Instead of deciding now, prototype 3 options:**

### Week 1: Quick Validation
```bash
# Test 1: Can OS mount work?
python test_os_mount_approach.py

# Test 2: Can smbprotocol handle your PCAPs?
python test_smbprotocol_approach.py

# Test 3: Can Impacket handle your PCAPs?
python test_impacket_approach.py
```

### Week 2: Pick Winner
- Compare complexity
- Compare fidelity
- Compare performance

**Then commit to architecture.**

---

## Critical Questions for YOU

Before I can recommend the "right" approach, tell me:

1. **MVP timeline:** Need working demo in 2 weeks or 12 weeks?
2. **Platform:** Must run on Linux, or Windows is okay?
3. **Scale priority:** Is 10 users enough initially or need 1000 day one?
4. **Complexity tolerance:** Comfortable with asyncio/threading complexity?
5. **Protocol visibility:** Need to debug SMB protocol internals or just file operations?

**Let's pick 2-3 of these questions and answer them. That will narrow down to the right approach.**

Which questions should we tackle first?
