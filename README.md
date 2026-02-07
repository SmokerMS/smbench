# smbench

**A high-fidelity SMB workload replay system for bug reproduction and load testing**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust 1.70+](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org/)

## What is smbench?

smbench is a Rust-based SMB workload replay system that enables:

- **Bug Reproduction:** Capture customer workloads → Compile PCAP → Replay in lab → Reproduce issues with protocol fidelity
- **Load Testing:** Scale to thousands of concurrent users with realistic timing and operation mix
- **Protocol Validation:** Test SMB2/3 feature compliance against real servers (Windows Server, Synology NAS)

## Architecture

```
┌────────────┐
│    PCAP    │
└──────┬─────┘
       │
   [Compiler]  smbench compile
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

- **Rust Implementation** - High-performance, memory-safe execution
- **PCAP Compiler** - Extract SMB operations from PCAP files (`smbench compile`)
- **smb-rs Backend** - Native SMB2/3 protocol support with advanced features
- **Event-driven Scheduler** - Microsecond timing precision, scales to 5000+ users
- **Comprehensive Testing** - 80+ tests covering SMB3 features, compiler pipeline, and E2E
- **Invariant Checking** - Detects handle leaks, ordering violations
- **Content-addressed Blob Storage** - BLAKE3-hashed write data with automatic deduplication

## Status

**Project Status: v1.3.0 - PCAP Compiler Complete**

**Completed:**
- Rust-based IR schema
- Event-driven scheduler with timing fidelity
- smb-rs backend with full SMB3 protocol support
- PCAP compiler (Rust-based, `smbench compile`)
- Comprehensive test suite (80+ tests)
- CLI tool (`smbench compile`, `smbench run`, `smbench validate`)
- Use case validation tests

**Planned:**
- Provisioning tools (AD/LDAP integration)
- Analysis tools (replay vs PCAP comparison)

See [docs/architecture-current.md](docs/architecture-current.md) for the complete architecture.

## Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/smbench.git
cd smbench

# Build (core only)
cargo build --release

# Build with PCAP compiler
cargo build --release --features pcap-compiler
```

### Compile a PCAP

```bash
# Compile PCAP to WorkloadIr
smbench compile customer.pcap -o output/

# Filter by client IP
smbench compile customer.pcap -o output/ --filter-client 192.168.1.50

# Verbose output
smbench compile customer.pcap -o output/ -v
```

### Replay a Workload

```bash
# Replay a workload
smbench run workload.json

# Or use legacy flat-args mode
smbench --ir workload.json \
  --backend smb-rs \
  --time-scale 0.1

# Validate IR without executing
smbench validate workload.json
```

### Running Tests

```bash
# All tests (non-SMB)
cargo test

# PCAP compiler tests
cargo test --features pcap-compiler

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
    "source": "pcap_compiler",
    "duration_seconds": 10.0,
    "client_count": 2
  },
  "clients": [
    {
      "client_id": "10.0.0.1",
      "operation_count": 3
    }
  ],
  "operations": [
    {
      "type": "Open",
      "op_id": "op_1",
      "client_id": "10.0.0.1",
      "timestamp_us": 0,
      "path": "testfile.txt",
      "mode": "ReadWrite",
      "handle_ref": "h_1",
      "extensions": {
        "create_disposition": 2
      }
    },
    {
      "type": "Write",
      "op_id": "op_2",
      "client_id": "10.0.0.1",
      "timestamp_us": 100000,
      "handle_ref": "h_1",
      "offset": 0,
      "length": 1024,
      "blob_path": "blobs/a1b2c3d4.bin"
    },
    {
      "type": "Close",
      "op_id": "op_3",
      "client_id": "10.0.0.1",
      "timestamp_us": 200000,
      "handle_ref": "h_1"
    }
  ]
}
```

## Supported Operations

- **File Operations:** Open, Close, Read, Write, Delete, Rename
- **Advanced Features:** Oplocks, Leases, Durable Handles, Multichannel

## Project Structure

```
smbench/
├── src/
│   ├── backend/         # Backend abstraction + smb-rs implementation
│   ├── compiler/        # PCAP compiler pipeline
│   │   ├── pcap_reader.rs        # PCAP file streaming (pcap-parser)
│   │   ├── tcp_reassembly.rs     # TCP stream reconstruction
│   │   ├── smb_parser.rs         # SMB2/3 message parsing (nom)
│   │   ├── state_machine.rs      # Protocol state tracking
│   │   ├── operation_extractor.rs # IR operation conversion
│   │   └── ir_generator.rs       # WorkloadIr JSON + blob storage (blake3)
│   ├── scheduler/       # Event-driven scheduler
│   ├── ir/              # IR schema definitions
│   ├── observability/   # Logging and metrics
│   └── bin/             # CLI tool (compile, run, validate)
├── tests/               # Integration tests
│   ├── smb_rs_validation.rs         # 45+ SMB feature tests
│   ├── compiler_tests.rs            # Compiler pipeline integration tests
│   ├── e2e_pcap_to_replay.rs        # End-to-end PCAP to IR tests
│   ├── pcap_helpers.rs              # Synthetic PCAP generation utilities
│   ├── use_case_bug_reproduction.rs # Bug reproduction scenarios
│   ├── use_case_load_testing.rs     # Load testing scenarios
│   └── protocol_fidelity.rs         # Protocol compliance tests
├── vendor/smb-rs/       # SMB2/3 protocol implementation
└── docs/                # Documentation
    ├── architecture-current.md  # Primary architecture doc
    ├── problem-definition.md    # Requirements and use cases
    └── archive/                 # Historical documents
```

## Documentation

- [Architecture (Current)](docs/architecture-current.md) - Complete system architecture
- [Problem Definition](docs/problem-definition.md) - Requirements and use cases
- [Implementation Summary](docs/IMPLEMENTATION_SUMMARY.md) - Detailed implementation log

## Roadmap

### Phase 1-5: Core Implementation (Complete)
- [x] IR schema and serialization
- [x] Event-driven scheduler
- [x] smb-rs backend integration
- [x] Comprehensive test suite
- [x] Use case validation
- [x] Documentation consolidation

### Phase 6-7: PCAP Compiler (Complete)
- [x] PCAP file parsing (pcap-parser)
- [x] TCP stream reassembly (IPv4/IPv6, out-of-order, retransmission)
- [x] SMB2/3 message parsing (nom, per MS-SMB2 2.2)
- [x] Protocol state machine (sessions, trees, files)
- [x] Operation extraction with access mask inference
- [x] Content-addressed blob storage (BLAKE3)
- [x] `smbench compile` CLI command
- [x] Multi-client support
- [x] Integration and E2E tests

### Provisioning Tools (Planned)
- [ ] AD/LDAP user creation
- [ ] Directory structure provisioning
- [ ] Path mapping (customer to lab)
- [ ] Permission assignment

### Analysis Tools (Planned)
- [ ] Timing analysis
- [ ] Operation comparison
- [ ] Protocol compliance validation
- [ ] Performance regression detection

## Technology Stack

- **Language:** Rust 1.70+
- **SMB Protocol:** smb-rs (SMB 2.0, 2.1, 3.0, 3.1.1)
- **PCAP Parsing:** pcap-parser, nom
- **Blob Hashing:** BLAKE3
- **Async Runtime:** Tokio
- **Serialization:** Serde (JSON)
- **CLI:** Clap
- **Logging:** Tracing

## Use Cases

### Bug Reproduction
Customer reports issue -> Capture PCAP -> `smbench compile` -> `smbench run` -> Bug reproduces

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
- [RFC 793] Transmission Control Protocol

---

**Built for high-fidelity SMB workload replay at enterprise scale**
