//! DFS (Distributed File System) referral parsing and path mapping.
//!
//! Implements resolution of DFS namespace paths to direct UNC paths,
//! following [MS-DFSC] (Distributed File System: Referral Protocol).
//!
//! ## Overview
//!
//! DFS allows a logical namespace (`\\domain\DFSRoot\share`) that maps
//! to physical servers (`\\server\share`). When the SMB client encounters
//! `STATUS_PATH_NOT_COVERED`, it sends `FSCTL_DFS_GET_REFERRALS` to discover
//! the correct target server.
//!
//! This module provides:
//! - `DfsReferral` struct for individual referral entries
//! - `DfsReferralResponse` for parsed referral responses
//! - `DfsPathMapper` for caching referrals and resolving paths

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// A single DFS referral entry from a `RESP_GET_DFS_REFERRAL` response.
#[derive(Debug, Clone)]
pub struct DfsReferral {
    /// DFS path being resolved (e.g., `\\domain\DFSRoot\share`).
    pub dfs_path: String,
    /// Target server to redirect to (e.g., `server.domain.com`).
    pub target_server: String,
    /// Target share on the server (e.g., `share$`).
    pub target_share: String,
    /// Time-to-live in seconds for this referral.
    pub ttl_seconds: u32,
}

/// Parsed response from `FSCTL_DFS_GET_REFERRALS`.
#[derive(Debug, Clone)]
pub struct DfsReferralResponse {
    /// Version of the referral (1, 2, 3, or 4).
    pub version: u16,
    /// List of referral entries.
    pub referrals: Vec<DfsReferral>,
}

/// Caches DFS referrals and resolves namespace paths to direct UNC paths.
pub struct DfsPathMapper {
    /// Cached referrals keyed by DFS path prefix.
    cache: HashMap<String, CachedReferral>,
    /// Manual DFS mappings from config (never expire).
    manual_mappings: HashMap<String, String>,
}

struct CachedReferral {
    referral: DfsReferral,
    cached_at: Instant,
}

impl DfsPathMapper {
    /// Create a new `DfsPathMapper` with optional manual mappings.
    pub fn new(manual_mappings: HashMap<String, String>) -> Self {
        Self {
            cache: HashMap::new(),
            manual_mappings,
        }
    }

    /// Add a referral to the cache.
    pub fn add_referral(&mut self, referral: DfsReferral) {
        let key = referral.dfs_path.to_lowercase();
        self.cache.insert(
            key,
            CachedReferral {
                referral,
                cached_at: Instant::now(),
            },
        );
    }

    /// Resolve a DFS path to a direct UNC path.
    ///
    /// Returns `Some(resolved_path)` if a matching referral is found,
    /// or `None` if no referral covers this path.
    pub fn resolve(&self, dfs_path: &str) -> Option<String> {
        let lower = dfs_path.to_lowercase();

        // Check manual mappings first
        for (prefix, target) in &self.manual_mappings {
            let prefix_lower = prefix.to_lowercase();
            if lower.starts_with(&prefix_lower) {
                let suffix = &dfs_path[prefix.len()..];
                return Some(format!("{}{}", target, suffix));
            }
        }

        // Check cached referrals
        for (prefix, cached) in &self.cache {
            if lower.starts_with(prefix) {
                // Check TTL
                let elapsed = cached.cached_at.elapsed();
                if elapsed < Duration::from_secs(cached.referral.ttl_seconds as u64) {
                    let suffix = &dfs_path[prefix.len()..];
                    let target = format!(
                        "\\\\{}\\{}{}",
                        cached.referral.target_server,
                        cached.referral.target_share,
                        suffix,
                    );
                    return Some(target);
                }
            }
        }

        None
    }

    /// Remove expired entries from the cache.
    pub fn evict_expired(&mut self) {
        self.cache.retain(|_, cached| {
            cached.cached_at.elapsed() < Duration::from_secs(cached.referral.ttl_seconds as u64)
        });
    }

    /// Check if a path is a DFS path (has a referral or manual mapping).
    pub fn is_dfs_path(&self, path: &str) -> bool {
        self.resolve(path).is_some()
    }
}

/// Parse a DFS referral response payload from `FSCTL_DFS_GET_REFERRALS`.
///
/// [MS-DFSC 2.2.4] `RESP_GET_DFS_REFERRAL`:
///   PathConsumed (2) + NumberOfReferrals (2) + ReferralHeaderFlags (4) + Referrals (variable)
pub fn parse_dfs_referral_response(data: &[u8]) -> Option<DfsReferralResponse> {
    if data.len() < 8 {
        return None;
    }
    let _path_consumed = u16::from_le_bytes([data[0], data[1]]);
    let num_referrals = u16::from_le_bytes([data[2], data[3]]);
    let _flags = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

    let mut referrals = Vec::new();
    let mut offset = 8usize;

    for _ in 0..num_referrals {
        if offset + 18 > data.len() {
            break;
        }

        let version = u16::from_le_bytes([data[offset], data[offset + 1]]);
        let entry_size = u16::from_le_bytes([data[offset + 2], data[offset + 3]]) as usize;

        if entry_size == 0 || offset + entry_size > data.len() {
            break;
        }

        // For version 3/4 referrals, we parse the structure differently.
        // Simplified: just extract what we can.
        let ttl_seconds = if offset + 8 <= data.len() {
            u32::from_le_bytes([data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]])
        } else {
            300 // default TTL
        };

        // For a proper implementation, we'd parse the DFS_REFERRAL_V3/V4 structure
        // with offsets to DFS path and target strings.
        // For now, create a placeholder referral.
        referrals.push(DfsReferral {
            dfs_path: String::new(),
            target_server: String::new(),
            target_share: String::new(),
            ttl_seconds,
        });

        offset += entry_size;
        let _ = version; // suppress warning; used for future version-specific parsing
    }

    Some(DfsReferralResponse {
        version: if referrals.is_empty() { 0 } else {
            u16::from_le_bytes([data[8], data[9]])
        },
        referrals,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dfs_path_mapper_manual() {
        let mut mappings = HashMap::new();
        mappings.insert(
            "\\\\domain\\DFSRoot\\share".to_string(),
            "\\\\server\\actualshare".to_string(),
        );
        let mapper = DfsPathMapper::new(mappings);

        let resolved = mapper.resolve("\\\\domain\\DFSRoot\\share\\subdir\\file.txt");
        assert_eq!(resolved.as_deref(), Some("\\\\server\\actualshare\\subdir\\file.txt"));
    }

    #[test]
    fn test_dfs_path_mapper_no_match() {
        let mapper = DfsPathMapper::new(HashMap::new());
        assert!(mapper.resolve("\\\\server\\share\\file.txt").is_none());
    }

    #[test]
    fn test_dfs_path_mapper_cache() {
        let mut mapper = DfsPathMapper::new(HashMap::new());
        mapper.add_referral(DfsReferral {
            dfs_path: "\\\\domain\\root".to_string(),
            target_server: "fileserver".to_string(),
            target_share: "data".to_string(),
            ttl_seconds: 300,
        });

        let resolved = mapper.resolve("\\\\domain\\root\\file.txt");
        assert_eq!(resolved.as_deref(), Some("\\\\fileserver\\data\\file.txt"));
    }

    #[test]
    fn test_dfs_is_dfs_path() {
        let mut mappings = HashMap::new();
        mappings.insert("\\\\dfs\\ns".to_string(), "\\\\srv\\sh".to_string());
        let mapper = DfsPathMapper::new(mappings);

        assert!(mapper.is_dfs_path("\\\\dfs\\ns\\something"));
        assert!(!mapper.is_dfs_path("\\\\other\\path"));
    }

    #[test]
    fn test_parse_dfs_referral_response_empty() {
        // Minimal 8-byte header with 0 referrals
        let data = [0u8; 8];
        let resp = parse_dfs_referral_response(&data).unwrap();
        assert!(resp.referrals.is_empty());
    }

    #[test]
    fn test_parse_dfs_referral_response_too_short() {
        assert!(parse_dfs_referral_response(&[0u8; 4]).is_none());
    }

    #[test]
    fn test_dfs_evict_expired() {
        let mut mapper = DfsPathMapper::new(HashMap::new());
        mapper.add_referral(DfsReferral {
            dfs_path: "\\\\test\\root".to_string(),
            target_server: "srv".to_string(),
            target_share: "sh".to_string(),
            ttl_seconds: 0, // expired immediately
        });
        // Allow the entry to expire
        std::thread::sleep(std::time::Duration::from_millis(10));
        mapper.evict_expired();
        assert!(mapper.resolve("\\\\test\\root\\file").is_none());
    }

    #[test]
    fn test_dfs_case_insensitive_manual() {
        let mut mappings = HashMap::new();
        mappings.insert(
            "\\\\DOMAIN\\DFSROOT".to_string(),
            "\\\\server\\share".to_string(),
        );
        let mapper = DfsPathMapper::new(mappings);

        // Lowercase input should match uppercase mapping
        let resolved = mapper.resolve("\\\\domain\\dfsroot\\sub\\file.txt");
        assert_eq!(resolved.as_deref(), Some("\\\\server\\share\\sub\\file.txt"));
    }

    #[test]
    fn test_dfs_case_insensitive_cache() {
        let mut mapper = DfsPathMapper::new(HashMap::new());
        mapper.add_referral(DfsReferral {
            dfs_path: "\\\\Domain\\Root".to_string(),
            target_server: "srv".to_string(),
            target_share: "sh".to_string(),
            ttl_seconds: 3600,
        });

        // Different case should still match
        let resolved = mapper.resolve("\\\\domain\\root\\test");
        assert_eq!(resolved.as_deref(), Some("\\\\srv\\sh\\test"));
    }

    #[test]
    fn test_dfs_manual_mapping_takes_priority_over_cache() {
        let mut mappings = HashMap::new();
        mappings.insert(
            "\\\\domain\\root".to_string(),
            "\\\\manual-srv\\manual-sh".to_string(),
        );
        let mut mapper = DfsPathMapper::new(mappings);

        // Add a cache entry for the same path
        mapper.add_referral(DfsReferral {
            dfs_path: "\\\\domain\\root".to_string(),
            target_server: "cached-srv".to_string(),
            target_share: "cached-sh".to_string(),
            ttl_seconds: 3600,
        });

        // Manual mapping should win
        let resolved = mapper.resolve("\\\\domain\\root\\file");
        assert_eq!(resolved.as_deref(), Some("\\\\manual-srv\\manual-sh\\file"));
    }

    #[test]
    fn test_dfs_multiple_referrals() {
        let mut mapper = DfsPathMapper::new(HashMap::new());
        mapper.add_referral(DfsReferral {
            dfs_path: "\\\\ns\\share1".to_string(),
            target_server: "srv1".to_string(),
            target_share: "data1".to_string(),
            ttl_seconds: 3600,
        });
        mapper.add_referral(DfsReferral {
            dfs_path: "\\\\ns\\share2".to_string(),
            target_server: "srv2".to_string(),
            target_share: "data2".to_string(),
            ttl_seconds: 3600,
        });

        assert!(mapper.is_dfs_path("\\\\ns\\share1\\file"));
        assert!(mapper.is_dfs_path("\\\\ns\\share2\\file"));
        assert!(!mapper.is_dfs_path("\\\\ns\\share3\\file"));
    }

    #[test]
    fn test_parse_dfs_referral_response_with_entries() {
        // Build a minimal referral response with 1 entry
        let mut data = vec![0u8; 8 + 18]; // header + 1 referral entry
        data[2..4].copy_from_slice(&1u16.to_le_bytes()); // NumberOfReferrals = 1
        // Referral entry at offset 8
        data[8..10].copy_from_slice(&3u16.to_le_bytes()); // Version = 3
        data[10..12].copy_from_slice(&18u16.to_le_bytes()); // EntrySize = 18
        data[12..16].copy_from_slice(&600u32.to_le_bytes()); // TTL = 600

        let resp = parse_dfs_referral_response(&data).unwrap();
        assert_eq!(resp.referrals.len(), 1);
        assert_eq!(resp.referrals[0].ttl_seconds, 600);
    }
}
