# SMBench Documentation Index

**Project:** SMBench - SMB3 Workload Replay System  
**Date:** February 1, 2026  
**Status:** Architecture Complete, Ready for Implementation

---

## 📚 Documentation Overview

This directory contains the complete architecture and design documentation for SMBench.

### Core Documents (IMPLEMENTATION)

| Document | Purpose | Status |
|----------|---------|--------|
| **[architecture-v1.2.2-locked.md](./architecture-v1.2.2-locked.md)** | **PRIMARY** - Locked architecture, ready to code | 🔒 **USE THIS** |
| **[architecture-review-summary.md](./architecture-review-summary.md)** | Review journey and all issues resolved | ✅ Read first |
| **[problem-definition.md](./problem-definition.md)** | Requirements and use cases | ✅ Complete |
| **[platform-decision-rust-vs-python.md](./platform-decision-rust-vs-python.md)** | Why Rust was chosen | ✅ Complete |

### Supporting Documents (REFERENCE)

| Document | Purpose | Status |
|----------|---------|--------|
| **[github-technology-survey.md](./github-technology-survey.md)** | Available libraries (Context7 research) | 📚 Reference |
| **[adjacent-domains-analysis.md](./adjacent-domains-analysis.md)** | Learnings from similar systems | 📚 Reference |
| **[technology-options-matrix.md](./technology-options-matrix.md)** | All technology alternatives | 📚 Reference |
| **[architecture-review.md](./architecture-review.md)** | Original review (historical) | 📝 Historical |
| **[architecture.md](./architecture.md)** | v1.0 (superseded) | ❌ Outdated |
| **[architecture-v1.1-revised.md](./architecture-v1.1-revised.md)** | v1.1 (superseded) | ❌ Outdated |
| **[architecture-final.md](./architecture-final.md)** | v1.2 (superseded) | ❌ Outdated |

---

## 🎯 Quick Start: What You Need to Know

### The Problem
Customer reports SMB file server issues. You capture PCAP traces but manual reproduction is slow, error-prone, and can't handle multi-client scenarios.

### The Solution
SMBench: Capture PCAP → Compile to portable IR → Replay in lab with high fidelity.

### The Architecture
```
Python (PCAP Parser) → Workload IR (JSON) → Rust Engine (smb-rs + tokio) → SMB Server
```

### Why Rust?
- ✅ Native async (5000+ concurrent users)
- ✅ SMB credit system support (protocol-correct)
- ✅ Memory efficient (~500 KB per user)
- ✅ Single binary deployment
- ✅ Linux platform (elegant, simple)

---

## 🗺️ Reading Guide

### For Developers (Implementation)
**Read in this order:**
1. **[architecture-review-summary.md](./architecture-review-summary.md)** - Review journey (5 min read)
2. **[architecture-v1.2.2-locked.md](./architecture-v1.2.2-locked.md)** - **LOCKED ARCHITECTURE** 🔒
3. **[problem-definition.md](./problem-definition.md)** - Requirements context
4. **[platform-decision-rust-vs-python.md](./platform-decision-rust-vs-python.md)** - Technology rationale

### For Stakeholders (Overview)
**Read in this order:**
1. **[problem-definition.md](./problem-definition.md)** - What we're building and why
2. **[architecture-review-summary.md](./architecture-review-summary.md)** - Review process and decisions
3. **[architecture-v1.2.1-implementation-ready.md](./architecture-v1.2.1-implementation-ready.md)** (Executive Summary)

### For Researchers (Deep Dive)
**Read all documents:**
1. **[architecture-review-summary.md](./architecture-review-summary.md)** - Overview of all iterations
2. **[problem-definition.md](./problem-definition.md)** - Requirements
3. **[adjacent-domains-analysis.md](./adjacent-domains-analysis.md)** - Related work
4. **[github-technology-survey.md](./github-technology-survey.md)** - Available tech
5. **[technology-options-matrix.md](./technology-options-matrix.md)** - All options
6. **[platform-decision-rust-vs-python.md](./platform-decision-rust-vs-python.md)** - Tech decision
7. **[architecture-v1.2.2-locked.md](./architecture-v1.2.2-locked.md)** - Locked final architecture

---

## 🏗️ Architecture Summary

### High-Level Design

**Three-Phase System:**
1. **Capture** - Python PCAP parser extracts SMB operations
2. **Compile** - Convert to portable Workload IR (JSON + blobs)
3. **Replay** - Rust engine executes with high fidelity

### Key Innovations

**1. Hybrid Replay Model**
- Scheduled operations (from PCAP timeline)
- Reactive protocol handling (oplock breaks, server events)
- Preserves timing while maintaining protocol correctness

**2. Logical Clocks (Jepsen-Inspired)**
- Time-scalable (compress/expand without breaking causality)
- Preserves happens-before relationships
- Enables multi-client coordination

**3. SMB Credit System (smb-rs)**
- Parallel operations per connection (like real Windows clients)
- Higher throughput than sequential
- Protocol-correct behavior

**4. Tokio Async Runtime**
- 5000+ concurrent clients trivially
- Microsecond-precision timing
- Work-stealing scheduler
- No GIL bottlenecks

---

## 📊 Key Decisions

### Decision 1: Rust over Python ✅
**Rationale:**
- Native async (no GIL)
- smb-rs has SMB credit system support
- Memory efficient (2-4x better)
- Single binary deployment
- Better architecture for 5000-user scale

**Trade-off:** Learning curve, but better long-term

---

### Decision 2: Linux over Windows ✅
**Rationale:**
- Simpler deployment (no Windows licensing)
- Better container ecosystem
- Smaller images (50 MB vs. 4 GB)
- Rust works best on Linux
- SMB protocol is platform-independent

**Trade-off:** Can't use native Windows SMB client, but smb-rs is sufficient

---

### Decision 3: Semantic Replay over Packet Replay ✅
**Rationale:**
- Portable (not tied to network topology)
- Scalable (5000 users from 1 trace)
- Debuggable (human-readable IR)
- Flexible (time scaling, path mapping)

**Trade-off:** Must implement SMB protocol understanding

---

### Decision 4: Hybrid Model over Pure Replay ✅
**Rationale:**
- Real-world PCAPs have oplocks/leases (your correction!)
- Server responses happen at runtime (can't be predicted)
- Must preserve PCAP timing AND react to server

**Trade-off:** More complex than simple playback, but necessary

---

## 🚀 Implementation Timeline

| Phase | Duration | Deliverable | Risk |
|-------|----------|-------------|------|
| **Phase 0** | 2 weeks | Technology validation | High |
| **Phase 1** | 4 weeks | Single-client replay | Medium |
| **Phase 2** | 4 weeks | Multi-client + oplocks | Medium |
| **Phase 3** | 4 weeks | Scale to 5000 users | Low |
| **Phase 4** | 4 weeks | Production hardening | Low |
| **Total** | **18 weeks** | Production-ready system | - |

---

## 🎯 Success Criteria

### Technical
- ✅ Replay 95% of customer PCAPs
- ✅ Support 5000 concurrent users
- ✅ Memory < 1 MB per user
- ✅ <1% error rate at scale
- ✅ Reproduce known bugs >90% success rate

### Business
- ✅ Reduce bug reproduction time: hours → minutes
- ✅ Enable multi-client scenarios (previously impossible)
- ✅ Support load testing at customer scale
- ✅ Actionable debugging data

---

## 🔧 Technology Stack Summary

### Core
- **Language:** Rust 1.75+
- **SMB Client:** smb-rs (`/afiffon/smb-rs`)
- **Async Runtime:** tokio 1.48+
- **Platform:** Linux (Ubuntu 22.04+, Debian, RHEL 9+)

### Compiler
- **Language:** Python 3.9+
- **PCAP Parser:** Scapy or Pyshark
- **TCP Reassembly:** dpkt

### Deployment
- **Container:** Docker (optional)
- **Orchestration:** Kubernetes (optional)
- **Monitoring:** Prometheus + Grafana

---

## 📖 Key Concepts

### Workload IR (Intermediate Representation)
- JSON format with operation sequence
- Logical clocks for time-scalable replay
- Dependency graph for happens-before
- Content-addressed blobs for write data
- Platform-independent (maps to test environment)

### Hybrid Replay Model
- **Scheduled:** Operations execute at PCAP timestamps
- **Reactive:** Oplock breaks handled when server sends them
- **Coordinated:** Multiple clients synchronized via logical clocks

### SMB Credit System
- Multiple requests in-flight per connection
- Flow control via credit mechanism
- smb-rs natively supports this
- Matches real Windows client behavior

---

## 🎓 Learning Resources

### Rust Async
- [Tokio Tutorial](https://tokio.rs/tokio/tutorial)
- [Async Book](https://rust-lang.github.io/async-book/)

### SMB Protocol
- [MS-SMB2 Specification](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/)
- smb-rs documentation

### Related Patterns
- **Database Replay:** PostgreSQL WAL, Oracle AWR
- **Distributed Systems:** Jepsen linearizability checking
- **PCAP Tools:** tcpreplay, Scapy, Wireshark

---

## ⚠️ Critical Notes

### Oplock Handling is Critical
Customer PCAPs contain oplocks, leases, durable handles. These are NOT optional.  
Phase 0 MUST validate smb-rs supports these features.

### Hybrid Model is Complex
The combination of scheduled operations + reactive protocol handling requires careful design.  
Multi-client coordination with oplocks is the hardest part.

### Fidelity Matters
For bug reproduction, you need exact operation ordering, timing, and protocol features.  
This is NOT a simple load generator - it's a high-fidelity replay system.

---

## 🔄 Next Steps

### Immediate (This Week)
1. ✅ Architecture complete (this document)
2. 🔲 Set up Rust project structure
3. 🔲 Initialize cargo workspace
4. 🔲 Add dependencies (smb, tokio, serde, clap)
5. 🔲 Create IR schema (Rust structs)

### Week 1
1. 🔲 Implement minimal SMB connection test
2. 🔲 Test oplock request with smb-rs
3. 🔲 Test 100 concurrent connections
4. 🔲 Measure memory per connection
5. 🔲 **Decision point:** Validate smb-rs or pivot

### Week 2
1. 🔲 Build Python PCAP compiler (basic)
2. 🔲 Generate first IR from real PCAP
3. 🔲 Load IR in Rust
4. 🔲 Execute 10 operations end-to-end
5. 🔲 **Go/No-Go decision for Phase 1**

---

## 📞 Questions & Contact

For questions about this architecture:
- Technical questions: See detailed sections in [architecture.md](./architecture.md)
- Requirements questions: See [problem-definition.md](./problem-definition.md)
- Technology alternatives: See [technology-options-matrix.md](./technology-options-matrix.md)

---

## ✅ Document Status

**All foundational documents complete:**
- ✅ Problem defined
- ✅ Technology evaluated
- ✅ Architecture designed
- ✅ Implementation plan created

**Ready to start Phase 0 implementation.**

---

*Documentation created February 1, 2026, using Context7 MCP research, SMB protocol analysis, and distributed systems best practices.*
