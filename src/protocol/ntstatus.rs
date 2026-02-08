//! NTSTATUS codes from [MS-ERREF] for structured error handling.
//!
//! The top 2 bits of an NTSTATUS code encode severity:
//! - 00 = Success
//! - 01 = Informational
//! - 10 = Warning
//! - 11 = Error
//!
//! This module provides a `NtStatus` wrapper with named constants for the
//! ~80 most common codes encountered in SMB traffic, plus `Display` and
//! severity helpers.

use std::fmt;

/// A wrapper around a raw `u32` NTSTATUS code with named constants
/// and helper methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NtStatus(pub u32);

impl NtStatus {
    // ── Severity constants ──────────────────────────────────────────

    const SEVERITY_MASK: u32 = 0xC000_0000;

    /// Returns `true` if the code indicates success (severity bits = 00).
    pub fn is_success(self) -> bool {
        (self.0 & Self::SEVERITY_MASK) == 0x0000_0000
    }

    /// Returns `true` if the code indicates an informational status (severity bits = 01).
    pub fn is_informational(self) -> bool {
        (self.0 & Self::SEVERITY_MASK) == 0x4000_0000
    }

    /// Returns `true` if the code indicates a warning (severity bits = 10).
    pub fn is_warning(self) -> bool {
        (self.0 & Self::SEVERITY_MASK) == 0x8000_0000
    }

    /// Returns `true` if the code indicates an error (severity bits = 11).
    pub fn is_error(self) -> bool {
        (self.0 & Self::SEVERITY_MASK) == 0xC000_0000
    }

    /// Returns the raw `u32` code.
    pub fn code(self) -> u32 {
        self.0
    }

    /// Returns a short human-readable name for known status codes,
    /// or `None` for unknown codes.
    pub fn name(self) -> Option<&'static str> {
        match self.0 {
            0x0000_0000 => Some("STATUS_SUCCESS"),
            0x0000_0103 => Some("STATUS_PENDING"),
            0x0000_0104 => Some("STATUS_REPARSE"),
            0x0000_0105 => Some("STATUS_MORE_ENTRIES"),
            0x0000_010B => Some("STATUS_NOTIFY_CLEANUP"),
            0x0000_010C => Some("STATUS_NOTIFY_ENUM_DIR"),
            0x0000_0107 => Some("STATUS_SOME_NOT_MAPPED"),
            0x0000_0106 => Some("STATUS_NO_MORE_ENTRIES"),

            // Informational (0x4xxx_xxxx)
            // (none common in SMB)

            // Warning (0x8000_xxxx)
            0x8000_0005 => Some("STATUS_BUFFER_OVERFLOW"),
            0x8000_0006 => Some("STATUS_NO_MORE_FILES"),
            0x8000_002D => Some("STATUS_STOPPED_ON_SYMLINK"),

            // Error — General (0xC000_xxxx)
            0xC000_0001 => Some("STATUS_UNSUCCESSFUL"),
            0xC000_0002 => Some("STATUS_NOT_IMPLEMENTED"),
            0xC000_0003 => Some("STATUS_INVALID_INFO_CLASS"),
            0xC000_0004 => Some("STATUS_INFO_LENGTH_MISMATCH"),
            0xC000_0005 => Some("STATUS_ACCESS_VIOLATION"),
            0xC000_0008 => Some("STATUS_INVALID_HANDLE"),
            0xC000_000D => Some("STATUS_INVALID_PARAMETER"),
            0xC000_000E => Some("STATUS_NO_SUCH_DEVICE"),
            0xC000_000F => Some("STATUS_NO_SUCH_FILE"),
            0xC000_0010 => Some("STATUS_INVALID_DEVICE_REQUEST"),
            0xC000_0011 => Some("STATUS_END_OF_FILE"),
            0xC000_0013 => Some("STATUS_NO_MEDIA_IN_DEVICE"),
            0xC000_0015 => Some("STATUS_NONEXISTENT_SECTOR"),
            0xC000_0016 => Some("STATUS_MORE_PROCESSING_REQUIRED"),
            0xC000_001A => Some("STATUS_NO_MEMORY"),
            0xC000_001C => Some("STATUS_CONFLICTING_ADDRESSES"),
            0xC000_0022 => Some("STATUS_ACCESS_DENIED"),
            0xC000_0023 => Some("STATUS_BUFFER_TOO_SMALL"),
            0xC000_0024 => Some("STATUS_OBJECT_TYPE_MISMATCH"),
            0xC000_0030 => Some("STATUS_INVALID_PARAMETER_MIX"),
            0xC000_0033 => Some("STATUS_OBJECT_NAME_INVALID"),
            0xC000_0034 => Some("STATUS_OBJECT_NAME_NOT_FOUND"),
            0xC000_0035 => Some("STATUS_OBJECT_NAME_COLLISION"),
            0xC000_003A => Some("STATUS_OBJECT_PATH_NOT_FOUND"),
            0xC000_003B => Some("STATUS_OBJECT_PATH_SYNTAX_BAD"),
            0xC000_003C => Some("STATUS_DATA_OVERRUN"),
            0xC000_0041 => Some("STATUS_NETWORK_ACCESS_DENIED"),
            0xC000_0043 => Some("STATUS_SHARING_VIOLATION"),
            0xC000_0044 => Some("STATUS_QUOTA_EXCEEDED"),
            0xC000_004F => Some("STATUS_EAS_NOT_SUPPORTED"),
            0xC000_0054 => Some("STATUS_FILE_LOCK_CONFLICT"),
            0xC000_0055 => Some("STATUS_LOCK_NOT_GRANTED"),
            0xC000_0056 => Some("STATUS_DELETE_PENDING"),
            0xC000_006D => Some("STATUS_LOGON_FAILURE"),
            0xC000_006E => Some("STATUS_ACCOUNT_RESTRICTION"),
            0xC000_006F => Some("STATUS_INVALID_LOGON_HOURS"),
            0xC000_0070 => Some("STATUS_INVALID_WORKSTATION"),
            0xC000_0071 => Some("STATUS_PASSWORD_EXPIRED"),
            0xC000_0072 => Some("STATUS_ACCOUNT_DISABLED"),
            0xC000_0073 => Some("STATUS_NONE_MAPPED"),
            0xC000_007C => Some("STATUS_NO_TRUST_LSA_SECRET"),
            0xC000_007E => Some("STATUS_RANGE_NOT_LOCKED"),
            0xC000_0097 => Some("STATUS_DISK_FULL"),
            0xC000_009A => Some("STATUS_INSUFFICIENT_RESOURCES"),
            0xC000_009C => Some("STATUS_MEDIA_WRITE_PROTECTED"),
            0xC000_00BA => Some("STATUS_FILE_IS_A_DIRECTORY"),
            0xC000_00BB => Some("STATUS_NOT_SUPPORTED"),
            0xC000_00CC => Some("STATUS_BAD_NETWORK_NAME"),
            0xC000_00CE => Some("STATUS_NOT_SAME_DEVICE"),
            0xC000_00D4 => Some("STATUS_NETWORK_NAME_DELETED"),
            0xC000_00D5 => Some("STATUS_NETWORK_ACCESS_DENIED_2"),
            0xC000_00FB => Some("STATUS_REDIRECTOR_NOT_STARTED"),
            0xC000_0101 => Some("STATUS_DIRECTORY_NOT_EMPTY"),
            0xC000_010A => Some("STATUS_PROCESS_IS_TERMINATING"),
            0xC000_011F => Some("STATUS_TOO_MANY_OPENED_FILES"),
            0xC000_0120 => Some("STATUS_CANCELLED"),
            0xC000_0121 => Some("STATUS_CANNOT_DELETE"),
            0xC000_0123 => Some("STATUS_FILE_DELETED"),
            0xC000_0128 => Some("STATUS_FILE_CLOSED"),
            0xC000_015B => Some("STATUS_LOGON_TYPE_NOT_GRANTED"),
            0xC000_0184 => Some("STATUS_INVALID_DEVICE_STATE"),
            0xC000_0190 => Some("STATUS_IO_TIMEOUT"),
            0xC000_0193 => Some("STATUS_ACCOUNT_EXPIRED"),
            0xC000_0203 => Some("STATUS_USER_SESSION_DELETED"),
            0xC000_0205 => Some("STATUS_CONNECTION_DISCONNECTED"),
            0xC000_0206 => Some("STATUS_CONNECTION_RESET"),
            0xC000_0224 => Some("STATUS_PASSWORD_MUST_CHANGE"),
            0xC000_0233 => Some("STATUS_DOMAIN_CONTROLLER_NOT_FOUND"),
            0xC000_0234 => Some("STATUS_ACCOUNT_LOCKED_OUT"),
            0xC000_0257 => Some("STATUS_PATH_NOT_COVERED"),

            // Error — SMB-specific
            0xC000_0046 => Some("STATUS_NETWORK_CREDENTIAL_CONFLICT"),
            0xC009_0006 => Some("STATUS_LOG_FULL"),

            // DFS
            0xC002_0001 => Some("STATUS_DFS_UNAVAILABLE"),

            _ => None,
        }
    }

    /// Constructs from a raw `u32`.
    pub fn from_u32(code: u32) -> Self {
        Self(code)
    }

    // ── Named constants ─────────────────────────────────────────────

    // Success
    pub const SUCCESS: Self = Self(0x0000_0000);
    pub const PENDING: Self = Self(0x0000_0103);
    pub const REPARSE: Self = Self(0x0000_0104);
    pub const MORE_ENTRIES: Self = Self(0x0000_0105);
    pub const NOTIFY_CLEANUP: Self = Self(0x0000_010B);
    pub const NOTIFY_ENUM_DIR: Self = Self(0x0000_010C);

    // Warning
    pub const BUFFER_OVERFLOW: Self = Self(0x8000_0005);
    pub const NO_MORE_FILES: Self = Self(0x8000_0006);

    // Error — authentication
    pub const LOGON_FAILURE: Self = Self(0xC000_006D);
    pub const ACCOUNT_RESTRICTION: Self = Self(0xC000_006E);
    pub const PASSWORD_EXPIRED: Self = Self(0xC000_0071);
    pub const ACCOUNT_DISABLED: Self = Self(0xC000_0072);
    pub const ACCOUNT_LOCKED_OUT: Self = Self(0xC000_0234);
    pub const ACCOUNT_EXPIRED: Self = Self(0xC000_0193);
    pub const PASSWORD_MUST_CHANGE: Self = Self(0xC000_0224);

    // Error — access
    pub const ACCESS_DENIED: Self = Self(0xC000_0022);
    pub const NETWORK_ACCESS_DENIED: Self = Self(0xC000_0041);
    pub const SHARING_VIOLATION: Self = Self(0xC000_0043);
    pub const FILE_LOCK_CONFLICT: Self = Self(0xC000_0054);
    pub const LOCK_NOT_GRANTED: Self = Self(0xC000_0055);

    // Error — path/name
    pub const OBJECT_NAME_NOT_FOUND: Self = Self(0xC000_0034);
    pub const OBJECT_NAME_COLLISION: Self = Self(0xC000_0035);
    pub const OBJECT_NAME_INVALID: Self = Self(0xC000_0033);
    pub const OBJECT_PATH_NOT_FOUND: Self = Self(0xC000_003A);
    pub const NO_SUCH_FILE: Self = Self(0xC000_000F);
    pub const BAD_NETWORK_NAME: Self = Self(0xC000_00CC);

    // Error — file state
    pub const DELETE_PENDING: Self = Self(0xC000_0056);
    pub const FILE_IS_A_DIRECTORY: Self = Self(0xC000_00BA);
    pub const DIRECTORY_NOT_EMPTY: Self = Self(0xC000_0101);
    pub const END_OF_FILE: Self = Self(0xC000_0011);
    pub const DISK_FULL: Self = Self(0xC000_0097);
    pub const FILE_CLOSED: Self = Self(0xC000_0128);
    pub const FILE_DELETED: Self = Self(0xC000_0123);
    pub const CANCELLED: Self = Self(0xC000_0120);

    // Error — connection
    pub const USER_SESSION_DELETED: Self = Self(0xC000_0203);
    pub const CONNECTION_DISCONNECTED: Self = Self(0xC000_0205);
    pub const CONNECTION_RESET: Self = Self(0xC000_0206);
    pub const NETWORK_NAME_DELETED: Self = Self(0xC000_00D4);

    // Error — general
    pub const NOT_IMPLEMENTED: Self = Self(0xC000_0002);
    pub const INVALID_PARAMETER: Self = Self(0xC000_000D);
    pub const INVALID_HANDLE: Self = Self(0xC000_0008);
    pub const NOT_SUPPORTED: Self = Self(0xC000_00BB);
    pub const BUFFER_TOO_SMALL: Self = Self(0xC000_0023);
    pub const INSUFFICIENT_RESOURCES: Self = Self(0xC000_009A);
    pub const IO_TIMEOUT: Self = Self(0xC000_0190);
    pub const MORE_PROCESSING_REQUIRED: Self = Self(0xC000_0016);

    // DFS
    pub const PATH_NOT_COVERED: Self = Self(0xC000_0257);
    pub const DFS_UNAVAILABLE: Self = Self(0xC002_0001);
}

impl fmt::Display for NtStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(name) = self.name() {
            write!(f, "{} (0x{:08X})", name, self.0)
        } else {
            let severity = match self.0 & Self::SEVERITY_MASK {
                0x0000_0000 => "Success",
                0x4000_0000 => "Info",
                0x8000_0000 => "Warning",
                _ => "Error",
            };
            write!(f, "NTSTATUS_{}(0x{:08X})", severity, self.0)
        }
    }
}

impl From<u32> for NtStatus {
    fn from(code: u32) -> Self {
        Self(code)
    }
}

impl From<NtStatus> for u32 {
    fn from(status: NtStatus) -> u32 {
        status.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_u32() {
        let s = NtStatus::from_u32(0xC000_0022);
        assert_eq!(s, NtStatus::ACCESS_DENIED);
        assert_eq!(s.code(), 0xC000_0022);
    }

    #[test]
    fn test_severity_success() {
        assert!(NtStatus::SUCCESS.is_success());
        assert!(!NtStatus::SUCCESS.is_error());
        assert!(!NtStatus::SUCCESS.is_warning());
        assert!(!NtStatus::SUCCESS.is_informational());
    }

    #[test]
    fn test_severity_pending() {
        assert!(NtStatus::PENDING.is_success());
    }

    #[test]
    fn test_severity_warning() {
        assert!(NtStatus::BUFFER_OVERFLOW.is_warning());
        assert!(!NtStatus::BUFFER_OVERFLOW.is_error());
        assert!(!NtStatus::BUFFER_OVERFLOW.is_success());
    }

    #[test]
    fn test_severity_error() {
        assert!(NtStatus::ACCESS_DENIED.is_error());
        assert!(!NtStatus::ACCESS_DENIED.is_success());
        assert!(!NtStatus::ACCESS_DENIED.is_warning());
    }

    #[test]
    fn test_display_known() {
        let s = NtStatus::ACCESS_DENIED;
        let display = format!("{}", s);
        assert_eq!(display, "STATUS_ACCESS_DENIED (0xC0000022)");
    }

    #[test]
    fn test_display_unknown() {
        let s = NtStatus::from_u32(0xC000_FFFF);
        let display = format!("{}", s);
        assert!(display.contains("0xC000FFFF"));
        assert!(display.contains("Error"));
    }

    #[test]
    fn test_display_unknown_success() {
        let s = NtStatus::from_u32(0x0000_9999);
        let display = format!("{}", s);
        assert!(display.contains("Success"));
    }

    #[test]
    fn test_name_known() {
        assert_eq!(NtStatus::SUCCESS.name(), Some("STATUS_SUCCESS"));
        assert_eq!(NtStatus::LOGON_FAILURE.name(), Some("STATUS_LOGON_FAILURE"));
        assert_eq!(NtStatus::USER_SESSION_DELETED.name(), Some("STATUS_USER_SESSION_DELETED"));
    }

    #[test]
    fn test_name_unknown() {
        assert_eq!(NtStatus::from_u32(0xDEAD_BEEF).name(), None);
    }

    #[test]
    fn test_from_into_u32() {
        let code: u32 = NtStatus::PENDING.into();
        assert_eq!(code, 0x0000_0103);
        let status: NtStatus = 0xC000_0034u32.into();
        assert_eq!(status, NtStatus::OBJECT_NAME_NOT_FOUND);
    }

    #[test]
    fn test_common_smb_codes() {
        // Verify all commonly-seen SMB codes have names
        let codes = [
            NtStatus::SUCCESS,
            NtStatus::PENDING,
            NtStatus::BUFFER_OVERFLOW,
            NtStatus::NO_MORE_FILES,
            NtStatus::ACCESS_DENIED,
            NtStatus::OBJECT_NAME_NOT_FOUND,
            NtStatus::SHARING_VIOLATION,
            NtStatus::LOGON_FAILURE,
            NtStatus::USER_SESSION_DELETED,
            NtStatus::FILE_LOCK_CONFLICT,
            NtStatus::END_OF_FILE,
            NtStatus::CANCELLED,
            NtStatus::NOT_SUPPORTED,
        ];
        for code in codes {
            assert!(code.name().is_some(), "code 0x{:08X} should have a name", code.0);
        }
    }

    #[test]
    fn test_severity_classification() {
        // Success: high bits = 00 (STATUS_SUCCESS and STATUS_PENDING both have severity 00)
        assert!(NtStatus::SUCCESS.is_success());
        assert!(!NtStatus::SUCCESS.is_error());
        assert!(!NtStatus::SUCCESS.is_warning());
        assert!(!NtStatus::SUCCESS.is_informational());

        // STATUS_PENDING has severity 00 (same as success) per [MS-ERREF]
        assert!(NtStatus::PENDING.is_success());
        assert!(!NtStatus::PENDING.is_error());

        // Informational: high bits = 01 — use a manually constructed value
        let informational = NtStatus::from_u32(0x4000_0001);
        assert!(informational.is_informational());
        assert!(!informational.is_success());
        assert!(!informational.is_error());

        // Warning: high bits = 10
        assert!(NtStatus::BUFFER_OVERFLOW.is_warning());
        assert!(!NtStatus::BUFFER_OVERFLOW.is_success());
        assert!(!NtStatus::BUFFER_OVERFLOW.is_error());

        // Error: high bits = 11
        assert!(NtStatus::ACCESS_DENIED.is_error());
        assert!(!NtStatus::ACCESS_DENIED.is_success());
        assert!(!NtStatus::ACCESS_DENIED.is_warning());
    }

    #[test]
    fn test_from_u32_roundtrip() {
        let raw: u32 = 0xC000_0022;
        let status = NtStatus::from_u32(raw);
        assert_eq!(status.code(), raw);
        assert_eq!(status.name(), Some("STATUS_ACCESS_DENIED"));

        let back: u32 = status.into();
        assert_eq!(back, raw);
    }

    #[test]
    fn test_display_contains_name_and_hex() {
        let s = format!("{}", NtStatus::ACCESS_DENIED);
        assert!(s.contains("ACCESS_DENIED"), "Display should contain name: {}", s);
        assert!(s.contains("C0000022"), "Display should contain hex code: {}", s);
    }

    #[test]
    fn test_display_unknown_hex_only() {
        let s = format!("{}", NtStatus::from_u32(0xDEAD_BEEF));
        assert!(s.contains("DEADBEEF"), "Display should contain hex code: {}", s);
    }

    #[test]
    fn test_unknown_code_name_is_none() {
        assert!(NtStatus::from_u32(0xFFFF_FFFF).name().is_none());
        assert!(NtStatus::from_u32(0x1234_5678).name().is_none());
    }
}
