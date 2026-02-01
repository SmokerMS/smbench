# smbench

**A semantic workload compiler and runner for SMB3 protocol load testing**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

## What is smbench?

smbench converts unencrypted SMB3 PCAP captures into replayable, scalable filesystem workloads. It enables you to:

- **Replay real-world SMB traffic** at scale (up to 5,000 concurrent users)
- **Generate filesystem load** against SMB3 shares (tested with Nutanix Files)
- **Test performance** with semantically accurate workloads, not packet replays

## Architecture

smbench uses a three-plane architecture:

```
┌────────────┐
│    PCAP    │
└──────┬─────┘
       │
   [Compiler]
       │
       ▼
┌────────────┐         ┌──────────────┐
│Workload IR │────────▶│ Runner Engine│
└────────────┘         │ (SMB3 Client)│
                       └──────┬───────┘
       ▲                      │
       │                      ▼
┌──────┴────────┐      ┌────────────┐
│ Control Plane │      │   Target   │
│ (LDAP/AD)     │      │ SMB3 Share │
└───────────────┘      └────────────┘
```

### Core Principles

1. **Semantic replay, not packet replay** - Reconstructs filesystem intent, not raw packets
2. **Strict plane separation** - Control ≠ Data ≠ Observability
3. **Immutable IR** - Single source of truth for workload definition
4. **Event-driven scheduler** - Scales to thousands of concurrent users without threads
5. **AD-backed authentication** - Real Kerberos/NTLM against Active Directory

## Key Features

- 🔄 **PCAP to IR Compiler** - Extracts filesystem operations from SMB3 captures
- 📊 **Scalable Execution** - Event-driven scheduler handles 5,000+ concurrent users
- 🔐 **AD Integration** - Provisions users via LDAP, authenticates via Kerberos
- 📈 **Rich Observability** - Prometheus metrics, structured logs, latency percentiles
- 🎯 **Namespace Isolation** - Per-user top-level directories prevent collisions

## Status

🚧 **Project Status: Design Phase**

This project is currently in the design phase. The architecture has been validated, and we're building the initial implementation.

See [docs/architecture-review.md](docs/architecture-review.md) for the comprehensive design review.

## Roadmap

### Phase 1: Proof of Concept (In Progress)
- [x] Architecture design
- [ ] Define Workload IR v1 schema
- [ ] Build minimal PCAP compiler
- [ ] Implement SMBExecutor wrapper (Impacket-based)
- [ ] Test with 10 users, 100 operations

### Phase 2: Scaling Infrastructure
- [ ] Event-driven scheduler implementation
- [ ] SMB connection pooling
- [ ] Control plane (LDAP provisioning)
- [ ] Test with 100 users, 10K operations

### Phase 3: Production Hardening
- [ ] Error handling & retry logic
- [ ] Observability (Prometheus + Grafana)
- [ ] Checkpoint/resume functionality
- [ ] Test with 5,000 users, 1M operations

## Technology Stack

- **Language:** Python 3.9+
- **SMB Client:** Impacket (with custom connection pooling)
- **LDAP:** python-ldap / ldap3
- **PCAP Parsing:** Scapy / pyshark
- **Metrics:** Prometheus client
- **Scheduler:** Custom event-driven (min-heap priority queue)

## Quick Start

*Coming soon - project in active development*

## Project Structure

```
smbench/
├── compiler/          # PCAP → Workload IR
├── runner/            # IR execution engine
├── control/           # AD/LDAP provisioning
├── executor/          # SMB client wrapper
├── scheduler/         # Event-driven scheduler
├── observability/     # Metrics & logging
├── ir/                # IR schema definitions
├── tests/             # Test suite
└── docs/              # Documentation
```

## Documentation

- [Architecture Review](docs/architecture-review.md) - Comprehensive design analysis
- [IR Schema v1](docs/ir-schema.md) - *Coming soon*
- [Deployment Guide](docs/deployment.md) - *Coming soon*

## Contributing

This project is currently in early development. Contribution guidelines will be published once the core implementation stabilizes.

## Use Cases

- **Storage performance testing** - Generate realistic filesystem load
- **Capacity planning** - Model user behavior at scale
- **Protocol validation** - Verify SMB3 server implementations
- **Regression testing** - Replay production traffic for QA

## Why "smbench"?

**smb** (Server Message Block) + **bench** (benchmark) = A tool for generating and measuring SMB workloads

## License

MIT License - see [LICENSE](LICENSE) for details

## Related Projects

- [Impacket](https://github.com/fortra/impacket) - SMB/MSRPC protocol implementation
- [Scapy](https://scapy.net/) - Packet manipulation library
- [pyshark](https://github.com/KimiNewt/pyshark) - Python wrapper for TShark

---

**Built for realistic SMB3 load generation at enterprise scale**
