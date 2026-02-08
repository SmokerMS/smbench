//! RSVD (Remote Shared Virtual Disk) and SQOS (Storage Quality of Service)
//! protocol stubs.
//!
//! These stubs represent operations from [MS-RSVD] and [MS-SQOS] that would
//! be used for Hyper-V virtual disk and storage QoS scenarios. They are not
//! yet fully implemented but provide the type scaffolding for future work.
//!
//! ## When to use
//!
//! - **RSVD**: When benchmarking Hyper-V shared VHDX workloads. RSVD tunnels
//!   SCSI commands over SMB2 WRITE/READ to a shared virtual disk file.
//!
//! - **SQOS**: When testing storage QoS policy enforcement. SQOS allows
//!   setting IOPS and bandwidth limits for virtual disk I/O.

/// RSVD operations for shared virtual disk access.
///
/// [MS-RSVD] defines these operations, which are tunneled through
/// SMB2 IOCTL (FSCTL_SVHDX_SYNC_TUNNEL_REQUEST).
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RsvdOperation {
    /// Open a shared virtual disk (VHDX).
    OpenVirtualDisk {
        /// Path to the virtual disk file.
        path: String,
        /// Whether to open in read-only mode.
        read_only: bool,
    },
    /// Read from a shared virtual disk.
    ReadVirtualDisk {
        /// Offset within the virtual disk.
        offset: u64,
        /// Number of bytes to read.
        length: u32,
    },
    /// Write to a shared virtual disk.
    WriteVirtualDisk {
        /// Offset within the virtual disk.
        offset: u64,
        /// Number of bytes to write.
        length: u32,
    },
    /// Query virtual disk information.
    QueryVirtualDiskInfo,
    /// Query shared virtual disk support.
    QuerySharedVirtualDiskSupport,
}

/// SQOS policy definition for storage QoS management.
///
/// [MS-SQOS] allows configuring performance limits and reservations
/// for virtual disk I/O through SMB.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub struct SqosPolicy {
    /// Maximum IOPS allowed (0 = unlimited).
    pub iops_limit: u64,
    /// Maximum bandwidth in bytes/sec (0 = unlimited).
    pub bandwidth_limit: u64,
    /// Minimum IOPS reserved for this flow.
    pub iops_reservation: u64,
    /// Policy name for identification.
    pub policy_name: String,
}

impl Default for SqosPolicy {
    fn default() -> Self {
        Self {
            iops_limit: 0,
            bandwidth_limit: 0,
            iops_reservation: 0,
            policy_name: String::new(),
        }
    }
}

/// FSCTL code for RSVD tunnel requests.
#[allow(dead_code)]
pub const FSCTL_SVHDX_SYNC_TUNNEL_REQUEST: u32 = 0x0009_0304;

/// FSCTL code for SQOS operations.
#[allow(dead_code)]
pub const FSCTL_STORAGE_QOS_CONTROL: u32 = 0x0009_0350;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsvd_operation_construction() {
        let op = RsvdOperation::OpenVirtualDisk {
            path: "disk.vhdx".to_string(),
            read_only: false,
        };
        assert!(matches!(op, RsvdOperation::OpenVirtualDisk { .. }));

        let read = RsvdOperation::ReadVirtualDisk { offset: 4096, length: 512 };
        match read {
            RsvdOperation::ReadVirtualDisk { offset, length } => {
                assert_eq!(offset, 4096);
                assert_eq!(length, 512);
            }
            _ => panic!("expected ReadVirtualDisk"),
        }

        let write = RsvdOperation::WriteVirtualDisk { offset: 0, length: 1024 };
        assert!(matches!(write, RsvdOperation::WriteVirtualDisk { .. }));
    }

    #[test]
    fn test_sqos_policy_default() {
        let policy = SqosPolicy::default();
        assert_eq!(policy.iops_limit, 0);
        assert_eq!(policy.bandwidth_limit, 0);
        assert_eq!(policy.iops_reservation, 0);
        assert!(policy.policy_name.is_empty());
    }

    #[test]
    fn test_sqos_policy_custom() {
        let policy = SqosPolicy {
            iops_limit: 10000,
            bandwidth_limit: 100 * 1024 * 1024, // 100 MB/s
            iops_reservation: 5000,
            policy_name: "gold-tier".to_string(),
        };
        assert_eq!(policy.iops_limit, 10000);
        assert_eq!(policy.bandwidth_limit, 104_857_600);
        assert_eq!(policy.policy_name, "gold-tier");
    }

    #[test]
    fn test_fsctl_constants() {
        // Verify the FSCTL codes are correctly defined
        assert_ne!(FSCTL_SVHDX_SYNC_TUNNEL_REQUEST, 0);
        assert_ne!(FSCTL_STORAGE_QOS_CONTROL, 0);
        assert_ne!(FSCTL_SVHDX_SYNC_TUNNEL_REQUEST, FSCTL_STORAGE_QOS_CONTROL);
    }

    #[test]
    fn test_rsvd_operation_equality() {
        let op1 = RsvdOperation::ReadVirtualDisk { offset: 0, length: 512 };
        let op2 = RsvdOperation::ReadVirtualDisk { offset: 0, length: 512 };
        let op3 = RsvdOperation::ReadVirtualDisk { offset: 1024, length: 512 };
        assert_eq!(op1, op2);
        assert_ne!(op1, op3);
    }

    #[test]
    fn test_rsvd_operation_clone() {
        let op = RsvdOperation::WriteVirtualDisk { offset: 4096, length: 1024 };
        let cloned = op.clone();
        assert_eq!(op, cloned);
    }

    #[test]
    fn test_rsvd_query_variants() {
        let q1 = RsvdOperation::QueryVirtualDiskInfo;
        let q2 = RsvdOperation::QuerySharedVirtualDiskSupport;
        assert_ne!(q1, q2);
    }

    #[test]
    fn test_sqos_policy_clone_and_eq() {
        let p1 = SqosPolicy {
            iops_limit: 5000,
            bandwidth_limit: 50_000_000,
            iops_reservation: 1000,
            policy_name: "test".to_string(),
        };
        let p2 = p1.clone();
        assert_eq!(p1, p2);
    }
}
