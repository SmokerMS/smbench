# smbench

**A high-fidelity SMB workload replay system for bug reproduction and load testing**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust 1.70+](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org/)

## What is smbench?

smbench is a Rust-based SMB workload replay system that enables:

- **Bug Reproduction:** Capture customer workloads → Replay in lab → Reproduce issues with protocol fidelity
- **Load Testing:** Scale to thousands of concurrent users with realistic timing and operation mix
- **Protocol Validation:** Test SMB2/3 feature compliance against real servers (Windows Server, Synology NAS)

## Architecture

```
┌────────────┐
│    PCAP    │ (Future)
└──────┬─────┘
       │
   [Compiler] (Planned)
       │
       ▼
┌────────────┐         ┌──────────────┐
│Workload IR │────────▶│   Scheduler  │
│   (JSON)   │         │ (Event-driven)│
└────────────┘         └──────┬───────┘
                              │
                              ▼
                       ┌─────────────┐
                       │ SMB Backend │
                       │  (smb-rs)   │
                       └──────┬──────┘
                              │
                              ▼
                       ┌─────────────┐
                       │  SMB Server │
                       │ (Win/NAS)   │
                       └─────────────┘
```

### Core Principles

1. **Semantic replay, not packet replay** - Reconstructs filesystem operations with timing fidelity
2. **Event-driven scheduler** - Scales to thousands of concurrent users
3. **Immutable IR** - Single source of truth for workload definition
4. **Per-client ordering** - Operations from same client execute in order, cross-client parallelism
5. **Protocol fidelity** - Full SMB2/3 support via smb-rs (oplocks, leases, multichannel, encryption)

## Key Features

- ✅ **Rust Implementation** - High-performance, memory-safe execution
- ✅ **smb-rs Backend** - Native SMB2/3 protocol support with advanced features
- ✅ **Event-driven Scheduler** - Microsecond timing precision, scales to 5000+ users
- ✅ **Comprehensive Testing** - 45+ validation tests covering SMB3 features
- ✅ **Invariant Checking** - Detects handle leaks, ordering violations
- 🚧 **PCAP Compiler** - Extract operations from PCAP files (planned Phase 6)
- 🚧 **Provisioning Tools** - AD/LDAP integration (planned Phase 7)

## Status

**Project Status: v1.2.1 - Core Implementation Complete**

✅ **Completed:**
- Rust-based IR schema
- Event-driven scheduler with timing fidelity
- smb-rs backend with full SMB3 protocol support
- Comprehensive test suite (45+ tests)
- CLI tool (`smbench replay`)
- Use case validation tests

🚧 **In Progress:**
- PCAP compiler (Rust-based)
- Provisioning tools
- Analysis tools

See [docs/architecture-current.md](docs/architecture-current.md) for the complete architecture.

## Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/smbench.git
cd smbench

# Build
cargo build --release
```

### Usage

```bash
# Replay a workload
smbench replay workload.json \
  --server 10.10.10.79 \
  --share testshare \
  --user testuser \
  --pass testpass

# Validate IR without executing
smbench replay workload.json --validate-only

# Run with time scaling (10x faster)
smbench replay workload.json \
  --server 10.10.10.79 \
  --share testshare \
  --time-scale 0.1
```

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

# Use case tests (bug reproduction, load testing)
cargo test --features smb-rs-backend -- --ignored
```

## Workload IR Format

The Workload IR is a JSON-based format that describes SMB operations:

```json
{
  "version": 1,
  "metadata": {
    "source": "manual",
    "duration_seconds": 10.0,
    "client_count": 2
  },
  "clients": [
    {
      "client_id": "user001",
      "operation_count": 3
    }
  ],
  "operations": [
    {
      "op_id": "op_001",
      "client_id": "user001",
      "timestamp_us": 0,
      "operation": "Open",
      "path": "/testfile.txt",
      "mode": "Write",
      "handle_ref": "h_1",
      "extensions": {
        "oplock_level": "Batch",
        "create_disposition": "OpenIf"
      }
    },
    {
      "op_id": "op_002",
      "client_id": "user001",
      "timestamp_us": 100000,
      "operation": "Write",
      "handle_ref": "h_1",
      "offset": 0,
      "length": 1024,
      "blob_path": "/tmp/data.bin"
    },
    {
      "op_id": "op_003",
      "client_id": "user001",
      "timestamp_us": 200000,
      "operation": "Close",
      "handle_ref": "h_1"
    }
  ]
}
```

## Supported Operations

- **File Operations:** Open, Close, Read, Write, Delete, Rename
- **Directory Operations:** Mkdir, Rmdir, Query Directory
- **Control Operations:** Fsctl, Ioctl
- **Advanced Features:** Oplocks, Leases, Durable Handles, Multichannel

## Project Structure

```
smbench/
├── src/
│   ├── backend/         # Backend abstraction + smb-rs implementation
│   ├── scheduler/       # Event-driven scheduler
│   ├── ir/              # IR schema definitions
│   ├── observability/   # Logging and metrics
│   └── bin/             # CLI tool
├── tests/               # Integration tests
│   ├── smb_rs_validation.rs    # 45+ SMB feature tests
│   ├── use_case_bug_reproduction.rs  # Bug reproduction scenarios
│   ├── use_case_load_testing.rs      # Load testing scenarios
│   └── protocol_fidelity.rs          # Protocol compliance tests
├── vendor/smb-rs/       # SMB2/3 protocol implementation
└── docs/                # Documentation
    ├── architecture-current.md  # Primary architecture doc
    ├── problem-definition.md    # Requirements and use cases
    └── archive/                 # Historical documents
```

## Documentation

- [Architecture (Current)](docs/architecture-current.md) - Complete system architecture
- [Problem Definition](docs/problem-definition.md) - Requirements and use cases
- [Architecture v1.2.2](docs/architecture-v1.2.2-locked.md) - Previous architecture version

## Roadmap

### ✅ Phase 1-5: Core Implementation (Complete)
- [x] IR schema and serialization
- [x] Event-driven scheduler
- [x] smb-rs backend integration
- [x] Comprehensive test suite
- [x] Use case validation
- [x] Documentation consolidation

### 🚧 Phase 6: PCAP Compiler (In Progress)
- [ ] PCAP file parsing
- [ ] TCP stream reassembly
- [ ] SMB2/3 message parsing
- [ ] Protocol state machine
- [ ] IR generation
- [ ] `smbench compile` command

### 🔮 Phase 7: Provisioning Tools (Planned)
- [ ] AD/LDAP user creation
- [ ] Directory structure provisioning
- [ ] Path mapping (customer → lab)
- [ ] Permission assignment

### 🔮 Phase 8: Analysis Tools (Planned)
- [ ] Timing analysis
- [ ] Operation comparison
- [ ] Protocol compliance validation
- [ ] Performance regression detection

## Technology Stack

- **Language:** Rust 1.70+
- **SMB Protocol:** smb-rs (SMB 2.0, 2.1, 3.0, 3.1.1)
- **Async Runtime:** Tokio
- **Serialization:** Serde (JSON)
- **CLI:** Clap
- **Logging:** Tracing

## Use Cases

### Bug Reproduction
Customer reports issue → Capture PCAP → Replay in lab → Bug reproduces

**Example:** Oplock break race condition between two clients

### Load Testing
Scale single-user workload to thousands of concurrent users

**Example:** 100 users, 10,000 operations, measure p50/p95/p99 latency

### Protocol Validation
Test SMB3 feature compliance against real servers

**Example:** Validate lease state transitions per MS-SMB2 specification

## Contributing

Contributions are welcome! Please:

1. Read [docs/architecture-current.md](docs/architecture-current.md)
2. Check existing issues/PRs
3. Follow Rust conventions (rustfmt, clippy)
4. Add tests for new features
5. Reference MS-SMB2 specifications where applicable

## Testing Against Real Servers

SMBench has been tested against:

- **Windows Server 2022** (SMB 3.1.1)
- **Synology DSM 7.x** (SMB 3.0)

Set environment variables to run tests:

```bash
export SMBENCH_SMB_SERVER=your-server
export SMBENCH_SMB_SHARE=testshare
export SMBENCH_SMB_USER=testuser
export SMBENCH_SMB_PASS=testpass

cargo test --features smb-rs-backend -- --ignored
```

## License

MIT License - see [LICENSE](LICENSE) for details

## Related Projects

- [smb-rs](https://github.com/avivnaaman/smb-rs) - Rust SMB2/3 protocol implementation
- [Impacket](https://github.com/fortra/impacket) - Python SMB/MSRPC library
- [Wireshark](https://www.wireshark.org/) - Network protocol analyzer

## References

- [MS-SMB2] Server Message Block (SMB) Protocol Versions 2 and 3
- [MS-FSCC] File System Control Codes
- [MS-PCCRC] Peer Content Caching and Retrieval

---

**Built for high-fidelity SMB workload replay at enterprise scale**
