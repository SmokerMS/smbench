//! WorkloadIr generation with content-addressed blob storage.
//!
//! Write data captured from PCAP is hashed with BLAKE3 and stored
//! in `<output_dir>/blobs/<hash>.bin`. Identical writes are
//! automatically deduplicated.

use crate::ir::{ClientSpec, Metadata, Operation, WorkloadIr};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Generates the final `WorkloadIr` JSON and blob files on disk.
pub struct IrGenerator {
    output_dir: PathBuf,
    blobs_dir: PathBuf,
}

impl IrGenerator {
    /// Create a new generator. Creates the output and blobs directories.
    pub fn new(output_dir: impl AsRef<Path>) -> Result<Self> {
        let output_dir = output_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&output_dir)
            .with_context(|| format!("Failed to create output directory: {:?}", output_dir))?;
        let blobs_dir = output_dir.join("blobs");
        std::fs::create_dir_all(&blobs_dir)
            .with_context(|| format!("Failed to create blobs directory: {:?}", blobs_dir))?;
        Ok(Self { output_dir, blobs_dir })
    }

    /// Generate the IR JSON and blob files. Returns the path to `workload.json`.
    ///
    /// `write_data` maps `(op_id)` → raw bytes that were captured from the
    /// PCAP. The generator hashes each blob, writes it to disk if not already
    /// present, and patches the `blob_path` field on the corresponding
    /// `Operation::Write`.
    pub fn generate(
        &self,
        mut operations: Vec<Operation>,
        write_data: HashMap<String, Vec<u8>>,
    ) -> Result<String> {
        // ── 1. Write blobs and update blob_path on Write operations ──
        let mut blob_cache: HashMap<String, String> = HashMap::new(); // hash → relative path

        for op in operations.iter_mut() {
            if let Operation::Write { op_id, blob_path, .. } = op {
                if let Some(data) = write_data.get(op_id.as_str()) {
                    if !data.is_empty() {
                        let hash = blake3::hash(data).to_hex().to_string();
                        let rel_path = blob_cache.entry(hash.clone()).or_insert_with(|| {
                            let file_name = format!("{}.bin", &hash[..32]);
                            let abs_path = self.blobs_dir.join(&file_name);
                            // Write only if not already on disk (deduplication).
                            if !abs_path.exists() {
                                if let Err(e) = std::fs::write(&abs_path, data) {
                                    tracing::warn!("Failed to write blob {}: {}", file_name, e);
                                }
                            }
                            format!("blobs/{}", file_name)
                        });
                        *blob_path = rel_path.clone();
                    }
                }
            }
        }

        // ── 2. Build client specs ──
        let mut client_ops: HashMap<String, u32> = HashMap::new();
        for op in &operations {
            *client_ops.entry(op.client_id().to_string()).or_insert(0) += 1;
        }
        let mut clients: Vec<ClientSpec> = client_ops
            .into_iter()
            .map(|(client_id, operation_count)| ClientSpec { client_id, operation_count })
            .collect();
        clients.sort_by(|a, b| a.client_id.cmp(&b.client_id));

        // ── 3. Compute duration ──
        let first_ts = operations.first().map(|o| o.timestamp_us()).unwrap_or(0);
        let last_ts = operations.last().map(|o| o.timestamp_us()).unwrap_or(0);
        let duration_seconds = if first_ts < last_ts {
            (last_ts - first_ts) as f64 / 1_000_000.0
        } else {
            0.0
        };

        // ── 4. Write workload.json ──
        let ir = WorkloadIr {
            version: 1,
            metadata: Metadata {
                source: "pcap_compiler".to_string(),
                duration_seconds,
                client_count: clients.len() as u32,
            },
            clients,
            operations,
        };

        let ir_path = self.output_dir.join("workload.json");
        let json = serde_json::to_string_pretty(&ir).context("Failed to serialize WorkloadIr")?;
        std::fs::write(&ir_path, json)
            .with_context(|| format!("Failed to write {:?}", ir_path))?;

        Ok(ir_path.to_string_lossy().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{OpenMode, Operation};

    #[test]
    fn test_generate_empty() {
        let dir = std::env::temp_dir().join("smbench_irgen_test_empty");
        let _ = std::fs::remove_dir_all(&dir);
        let gen = IrGenerator::new(&dir).unwrap();
        let path = gen.generate(Vec::new(), HashMap::new()).unwrap();
        assert!(std::path::Path::new(&path).exists());

        let contents = std::fs::read_to_string(&path).unwrap();
        let ir: WorkloadIr = serde_json::from_str(&contents).unwrap();
        assert_eq!(ir.operations.len(), 0);
        assert_eq!(ir.clients.len(), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_blob_deduplication() {
        let dir = std::env::temp_dir().join("smbench_irgen_test_dedup");
        let _ = std::fs::remove_dir_all(&dir);
        let gen = IrGenerator::new(&dir).unwrap();

        let ops = vec![
            Operation::Open {
                op_id: "op_1".to_string(),
                client_id: "c1".to_string(),
                timestamp_us: 100,
                path: "file.txt".to_string(),
                mode: OpenMode::ReadWrite,
                handle_ref: "h_1".to_string(),
                extensions: None,
            },
            Operation::Write {
                op_id: "op_2".to_string(),
                client_id: "c1".to_string(),
                timestamp_us: 200,
                handle_ref: "h_1".to_string(),
                offset: 0,
                length: 5,
                blob_path: String::new(),
            },
            Operation::Write {
                op_id: "op_3".to_string(),
                client_id: "c1".to_string(),
                timestamp_us: 300,
                handle_ref: "h_1".to_string(),
                offset: 5,
                length: 5,
                blob_path: String::new(),
            },
            Operation::Close {
                op_id: "op_4".to_string(),
                client_id: "c1".to_string(),
                timestamp_us: 400,
                handle_ref: "h_1".to_string(),
            },
        ];

        let mut write_data = HashMap::new();
        // Same data → same blob
        write_data.insert("op_2".to_string(), b"hello".to_vec());
        write_data.insert("op_3".to_string(), b"hello".to_vec());

        let path = gen.generate(ops, write_data).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        let ir: WorkloadIr = serde_json::from_str(&contents).unwrap();

        // Both writes should reference the same blob path.
        let write_ops: Vec<_> = ir.operations.iter().filter(|o| matches!(o, Operation::Write { .. })).collect();
        assert_eq!(write_ops.len(), 2);
        let bp1 = match &write_ops[0] { Operation::Write { blob_path, .. } => blob_path.clone(), _ => unreachable!() };
        let bp2 = match &write_ops[1] { Operation::Write { blob_path, .. } => blob_path.clone(), _ => unreachable!() };
        assert_eq!(bp1, bp2);
        assert!(bp1.starts_with("blobs/"));

        // Only one blob file should exist.
        let blob_files: Vec<_> = std::fs::read_dir(dir.join("blobs"))
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(blob_files.len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
