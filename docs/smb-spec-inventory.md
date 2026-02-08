# SMB Specification Inventory & Implementation Roadmap

**Date:** February 8, 2026
**Status:** Reference Document
**Purpose:** Consolidated inventory of all Microsoft Open Specifications relevant to a full SMB client implementation, audited against smbench's current state, with a phased roadmap filtered through trace replay goals.

---

## Table of Contents

1. [Full Compatibility Spec List](#full-compatibility-spec-list)
2. [Implementation Recommendations for Rust](#implementation-recommendations-for-rust)
3. [Audit Against Current Implementation](#audit-against-current-implementation)
4. [Implementation Roadmap](#implementation-roadmap)
5. [Priority Mapping to Replay Goals](#priority-mapping-to-replay-goals)

---

## Full Compatibility Spec List

### Tier 1: Core Wire Protocol (The Engine)

| Spec | Title | Relevance |
|------|-------|-----------|
| **[MS-SMB2]** | SMB2/3 Protocol | Covers everything from 2.0.2 to 3.1.1 (Encryption, Signing, Multichannel). The primary specification for smbench's parser, state machine, and replay engine. |
| **[MS-SMB]** | SMB Protocol | Legacy SMB. Required for "negotiation context" even if only modern dialects are supported. |
| **[MS-CIFS]** | Common Internet File System | Legacy reference. Required alongside [MS-SMB] for understanding SMB1-to-SMB2 dialect upgrade sequences that appear in some PCAPs. |

**Links:**
- [MS-SMB2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/)
- [MS-SMB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb/)
- [MS-CIFS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/)

### Tier 2: File System & Data (The Cargo)

| Spec | Title | Relevance |
|------|-------|-----------|
| **[MS-FSCC]** | File System Control Codes | Essential for defining how files behave (info classes, FSCTLs). Required for parsing SET_INFO/QUERY_INFO payloads and IOCTL control codes. |
| **[MS-FSA]** | File System Algorithms | Defines the "logical" rules for locking and state that a client must mimic. Reference for correct replay of concurrent file access patterns. |
| **[MS-ERREF]** | NTSTATUS Codes | Error-handling mapping table. Every SMB response carries an NTSTATUS code; structured handling requires this spec. |

**Links:**
- [MS-FSCC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/)
- [MS-FSA](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/)
- [MS-ERREF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/)

### Tier 3: Security & Auth (The Gatekeeper)

| Spec | Title | Relevance |
|------|-------|-----------|
| **[MS-SPNG]** | SPNEGO | The wrapper used to negotiate authentication. All SMB sessions begin with SPNEGO. |
| **[MS-NLMP]** | NTLM | For local/workgroup authentication. Common in lab environments and fallback scenarios. |
| **[MS-KILE]** | Kerberos | Mandatory for Active Directory / domain environments. Required for replaying traces captured against domain-joined servers. |

**Links:**
- [MS-SPNG](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/)
- [MS-NLMP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/)
- [MS-KILE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/)

### Tier 4: Enterprise Infrastructure (The Roadmap)

| Spec | Title | Relevance |
|------|-------|-----------|
| **[MS-DFSC]** | DFS | Required for path resolution in corporate networks. Customer PCAPs often contain DFS namespace paths. |
| **[MS-SWN]** | Service Witness | For "Transparent Failover" (High Availability). Only needed for HA failover testing scenarios. |
| **[MS-RPCE]** | Remote Procedure Call | Many DFS and Witness features are actually RPC calls tunneled through SMB named pipes. |

**Links:**
- [MS-DFSC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsc/)
- [MS-SWN](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-swn/)
- [MS-RPCE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/)

### Tier 5: VHDX/FSLogix Specialization (The Block Layer)

| Spec | Title | Relevance |
|------|-------|-----------|
| **[MS-RSVD]** | Remote Shared Virtual Disk | The core of network-based VHDX management. Only for Hyper-V/FSLogix workloads. |
| **[MS-SQOS]** | Storage QoS | Ensures VHDX performance stability. Companion to [MS-RSVD]. |
| **[MS-SMBD]** | SMB Direct (RDMA) | Mandatory to match the performance of native Windows FSLogix drivers. smb-rs has optional RDMA transport support. |

**Links:**
- [MS-RSVD](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rsvd/)
- [MS-SQOS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sqos/)
- [MS-SMBD](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smbd/)

---

## Implementation Recommendations for Rust

These are strategic recommendations for building a production-grade SMB client in Rust.

### 1. Bit-Level Precision

Use the `deku` crate. SMB headers have specific bit-fields (like the Flags field in SMB2) and strict padding/alignment requirements. `deku` allows defining these declaratively on structs, which is safer than manual bit-shifting.

### 2. Async/Non-blocking

Use `tokio`. SMB3 is highly concurrent (especially with Multichannel). Managing multiple TCP streams and asynchronous "credits" (the SMB flow control mechanism) requires a mature async runtime.

### 3. State Machine

SMB is extremely stateful (Session Setup -> Tree Connect -> Create -> Read/Write). Implement this as a Finite State Machine (FSM) using Rust enums to prevent "illegal" transitions (e.g., trying to read before a Tree Connect is valid).

### 4. Zero-Copy Strategy

For high-performance VHDX workloads, use pinned memory and try to implement zero-copy reading of packet payloads. This significantly reduces CPU overhead during heavy I/O.

### 5. Security First

Use `ring` for AES-GCM encryption. Do not roll custom crypto. SMB 3.1.1 encryption is tricky because the nonces are derived from the session keys and sequence numbers.

### 6. Credit Management

**Critical Detail:** Do not skip [MS-SMB2] Section 3.2.4.2 (Algorithm for Credit Management). If the Rust client does not manage credits properly, a Windows Server will abruptly drop the connection once the granted limit is exceeded.

---

## Audit Against Current Implementation

This section maps each recommendation to what smbench already has in place, identifying gaps and confirming what is already done.

### Recommendation 1: deku for Bit-Level Parsing

**Current state:** smbench uses `nom` in `src/compiler/smb_parser.rs` with manual byte slicing at known offsets. The parser has 42 unit tests covering all SMB2 command types, enriched fields, compound messages, and header metadata.

**Verdict: Keep nom.** `deku` is declarative and excellent for new struct definitions, but rewriting the existing battle-tested `nom` parser provides no functional gain. For new work (e.g., FSCTL payload structures, QUERY_INFO response bodies), `deku` could be adopted selectively for those specific structs without replacing `nom` for the top-level parser.

### Recommendation 2: tokio for Async

**Current state:** smbench uses `tokio` throughout. The scheduler uses `select!` with `sleep_until` for deadline racing, `mpsc` channels for completion events, and `Semaphore` for concurrency control. This is locked in the v1.2.2 architecture.

**Verdict: Already done.** No action needed. The architecture explicitly mandates `tokio::time::Instant` (not `std::time::Instant`) throughout.

### Recommendation 3: FSM with Rust Enums

**Current state:** The state machine in `src/compiler/state_machine.rs` tracks sessions, trees, and open files using `HashMap`-based state (`SmbConnection` -> `SessionState` -> `TreeState` -> `FileState`). The scheduler enforces per-client ordering via `in_flight_op: Option<String>`. The parser uses `SmbCommand` enum variants with structured fields for each command type.

**Verdict: Already done.** Could be enhanced with a typestate pattern for the connection lifecycle (Negotiate -> SessionSetup -> TreeConnect -> Ready), but the current approach is correct and not blocking any functionality.

### Recommendation 4: Zero-Copy for VHDX

**Current state:** Not implemented. Blob data is read via `tokio::fs::read()` which allocates a `Vec<u8>`. Write data captured from PCAPs is stored in content-addressed blob files (BLAKE3 hashed).

**Verdict: Defer to Tier 5 (Phase D).** Zero-copy is only relevant for VHDX/FSLogix workloads where I/O throughput is the bottleneck. For trace replay and load testing of typical file server workloads, the current approach is sufficient. When targeting RDMA/VHDX scenarios, pinned memory buffers and `bytes::Bytes` with `Arc` sharing should be evaluated.

### Recommendation 5: ring for AES-GCM

**Current state:** The `smb-rs` vendor crate handles SMB3 encryption internally. smbench does not perform its own cryptographic operations.

**Verdict: No action needed at smbench level.** The crypto layer is owned by smb-rs. If extending smb-rs to support additional encryption features (e.g., AES-256-GCM for SMB 3.1.1), `ring` should be used there. smbench should never implement its own SMB encryption.

### Recommendation 6: Credit Management (Section 3.2.4.2)

**Current state:** The parser extracts `credit_charge` from the SMB2 header (offset 6..8) and tracks it through `TrackedOperation.credit_charge`. During replay, the smb-rs backend relies on smb-rs's built-in credit management algorithm.

**Verdict: Partially done.** The parser captures credit information from PCAPs, and smb-rs handles credits during replay. For higher fidelity, smbench could replay exact credit sequences from the original trace (e.g., requesting the same number of credits the original client did). This is a Phase A enhancement, not a blocker.

### Summary Table

| Recommendation | Status | Action |
|---|---|---|
| deku for parsing | nom in use, 42 tests | Keep nom; consider deku for new structs |
| tokio async | Fully adopted, locked | None |
| FSM with enums | Implemented | Optional typestate enhancement |
| Zero-copy | Not implemented | Defer to Phase D (Tier 5) |
| ring for crypto | smb-rs handles it | None at smbench level |
| Credit management | Parser captures; smb-rs replays | Enhance fidelity in Phase A |

---

## Implementation Roadmap

The roadmap maps each spec tier to concrete work items, filtered through smbench's trace replay lens. Each phase builds on the last.

### Phase A: Core Protocol Depth (Tier 1 + Tier 2 Essentials)

**Specs:** [MS-SMB2] (deepen), [MS-FSCC] (add), [MS-ERREF] (add)

**Goal:** Make the parser, state machine, and replay engine understand all SMB2 commands with full fidelity, handle every NTSTATUS code gracefully, and support the FSCTL/info class values that appear in real customer PCAPs.

**Concrete work:**

1. **NTSTATUS structured handling** -- Map all [MS-ERREF] NTSTATUS codes to a Rust enum for structured error reporting during replay. Currently stored as raw `u32` in `TrackedOperation.nt_status`. Create `src/protocol/ntstatus.rs` with named constants and a `Display` implementation for human-readable error messages.

2. **FSCC info class parsing** -- Parse [MS-FSCC] info classes in SET_INFO/QUERY_INFO payloads so the state machine can track metadata changes (timestamps, attributes, ACLs). The parser currently captures `info_type` and `info_class` as raw bytes but does not decode the payload body.

3. **FSCTL payload parsing** -- Add FSCTL-specific payload parsing for the most common control codes: `FSCTL_GET_REPARSE_POINT`, `FSCTL_SET_REPARSE_POINT`, `FSCTL_QUERY_ALLOCATED_RANGES`, `FSCTL_SET_ZERO_DATA`, `FSCTL_CREATE_OR_GET_OBJECT_ID`. These appear frequently in customer PCAPs.

4. **Negotiation context replay** -- Capture NEGOTIATE request/response details (dialect, capabilities, pre-auth integrity hash ID, encryption/signing algorithms) so smbench can configure the smb-rs connection to match the exact dialect the captured client used.

5. **Credit fidelity enhancement** -- Use captured `credit_charge` values during replay to match the original client's credit consumption pattern, improving protocol fidelity.

**Files affected:** `smb_parser.rs`, `state_machine.rs`, `operation_extractor.rs`, `ir/mod.rs`, new `src/protocol/ntstatus.rs`

### Phase B: Authentication and Security (Tier 3)

**Specs:** [MS-SPNG], [MS-NLMP], [MS-KILE]

**Goal:** Enable smbench to connect to production-like environments using real credentials (Kerberos or NTLM), which is required for any serious replay against a domain-joined server.

**Concrete work:**

1. **Auth method validation** -- smb-rs already supports NTLM and Kerberos via its `connection` module. Validate and document which auth methods work end-to-end against Windows Server 2022, Samba, and Synology.

2. **Kerberos CLI configuration** -- Add Kerberos credential configuration to `smbench run` CLI: keytab path, principal name, KDC address. Currently only username/password via environment variables.

3. **AD domain testing** -- Test against Active Directory domain controllers. Validate session establishment, tree connect, and basic file operations using domain credentials.

4. **Session re-authentication** -- Handle session re-authentication when sessions expire during long-running replays. The state machine should detect `STATUS_USER_SESSION_DELETED` and trigger re-auth.

**Files affected:** `src/bin/smbench.rs` (CLI), `src/backend/smbrs.rs`, config schema

### Phase C: Enterprise Infrastructure (Tier 4)

**Specs:** [MS-DFSC], [MS-SWN], [MS-RPCE]

**Goal:** Handle DFS path resolution and transparent failover so traces captured in enterprise environments can be replayed in the lab.

**Concrete work:**

1. **DFS referral resolution** -- Implement DFS referral resolution (either in smbench or by extending smb-rs). Customer PCAPs often contain DFS namespace paths (`\\domain.com\DFSRoot\share`) that need to be resolved to actual server paths before replay.

2. **DFS path mapping** -- Add a DFS mapping mode to the path mapping configuration: allow users to specify DFS-to-direct-path translations for lab replay without needing a DFS infrastructure.

3. **Service Witness (defer)** -- [MS-SWN] is low-priority unless specifically targeting HA failover testing. Defer unless a customer PCAP requires it.

4. **RPC tunneling (defer)** -- [MS-RPCE] is only needed if DFS or SWN requires it. smb-rs already supports named pipe I/O which is the transport for RPC-over-SMB.

**Files affected:** New `src/protocol/dfs.rs`, `src/backend/smbrs.rs`

### Phase D: Specialized Workloads (Tier 5)

**Specs:** [MS-RSVD], [MS-SQOS], [MS-SMBD]

**Goal:** Support VHDX-over-SMB and RDMA workloads. Only relevant for FSLogix/Hyper-V trace replay.

**Concrete work:**

1. **RDMA transport validation** -- smb-rs already has RDMA transport support (optional). Validate it works for replay scenarios.

2. **RSVD/SQOS (defer)** -- [MS-RSVD] and [MS-SQOS] are very specialized. Defer until there is a customer PCAP requiring VHDX-over-SMB replay.

3. **Zero-copy I/O** -- When targeting RDMA workloads, implement pinned memory buffers and zero-copy read paths using `bytes::Bytes` to minimize CPU overhead.

**Files affected:** Vendor `smb-rs` crates, potentially new `src/protocol/rsvd.rs`

### Phase E: Legacy Compatibility (Tier 1 Subset)

**Specs:** [MS-SMB], [MS-CIFS]

**Goal:** Handle PCAPs that contain SMB1 negotiation context (e.g., an SMB1 NEGOTIATE followed by SMB2 dialect upgrade). Not implementing full SMB1 replay.

**Concrete work:**

1. **SMB1 magic detection** -- Detect SMB1 magic (`\xFF\x53\x4D\x42`) in the parser and skip/log those messages instead of failing.

2. **Dialect upgrade handling** -- Handle the common case of SMB1-to-SMB2 dialect negotiation upgrade that appears in some older PCAPs.

**Files affected:** `smb_parser.rs`

---

## Priority Mapping to Replay Goals

### For Bug Reproduction (Primary Use Case)

| Priority | Phase | Rationale |
|----------|-------|-----------|
| **Critical** | Phase A -- Core Protocol Depth | Full protocol fidelity is the foundation. Without understanding all commands, info classes, and error codes, replays will silently diverge from the original trace. |
| **Important** | Phase B -- Authentication | Connecting to real domain-joined servers is required for any production-like replay. |
| **Nice-to-have** | Phase C -- DFS | Only needed when customer PCAPs contain DFS namespace paths. Can be worked around with manual path mapping. |
| **Defer** | Phase D -- VHDX/RDMA | Specialized workloads not commonly encountered in bug reproduction. |
| **Defer** | Phase E -- Legacy SMB1 | Rare in modern environments. |

### For Load Testing (Secondary Use Case)

| Priority | Phase | Rationale |
|----------|-------|-----------|
| **Critical** | Phase A -- Core Protocol Depth | Accurate protocol behavior under load requires full command coverage and correct credit management. |
| **Critical** | Phase B -- Authentication | Load testing at scale (5000 users) requires Kerberos authentication against AD. |
| **Important** | Credit management fidelity (Phase A) | Incorrect credit handling causes connection drops under load, producing misleading results. |
| **Nice-to-have** | Phase D -- RDMA | High-throughput testing benefits from RDMA, but is not required for correctness. |
| **Defer** | Phase E -- Legacy SMB1 | Irrelevant for load testing. |

### Visual Priority Map

```
                Bug Reproduction          Load Testing
               ────────────────         ──────────────
Critical:      Phase A (Protocol)       Phase A + B
Important:     Phase B (Auth)           Credit Mgmt
Nice-to-have:  Phase C (DFS)            Phase D (RDMA)
Defer:         Phase D, E               Phase E
```

---

## References

### Microsoft Open Specifications Portal
https://learn.microsoft.com/en-us/openspecs/windows_protocols/

### Key Sections Within [MS-SMB2]
- **Section 2.2.1** -- SMB2 Packet Header (parsed in `smb_parser.rs`)
- **Section 2.2.13** -- CREATE Request (share_access, file_attributes, create contexts)
- **Section 2.2.14** -- CREATE Response (create_action, file_id, oplock level)
- **Section 2.2.24** -- Oplock Break Notification/Acknowledgment
- **Section 2.2.26** -- LOCK Request (lock elements, lock sequence)
- **Section 2.2.31/32** -- IOCTL Request/Response (FSCTL codes)
- **Section 2.2.37/38** -- QUERY_INFO Request/Response
- **Section 2.2.39** -- SET_INFO Request
- **Section 3.2.4.2** -- Algorithm for Credit Management (critical for connection stability)
- **Section 3.3.5.9** -- Oplock Break handling

### smbench Current Implementation
- Parser: `src/compiler/smb_parser.rs` (42 unit tests, all SMB2 commands)
- State machine: `src/compiler/state_machine.rs` (25 unit tests)
- Operation extractor: `src/compiler/operation_extractor.rs` (44 unit tests)
- IR schema: `src/ir/mod.rs`
- smb-rs backend: `src/backend/smbrs.rs`
- Impacket backend: `src/backend/impacket.rs`

---

*Document created February 8, 2026. This is a living reference that should be updated as phases are completed.*
