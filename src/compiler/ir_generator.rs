//! WorkloadIr generation and blob file writing

use crate::ir::{ClientSpec, Metadata, Operation, WorkloadIr};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// IR generator
pub struct IrGenerator {
    output_dir: PathBuf,
}

impl IrGenerator {
    /// Create a new IR generator
    pub fn new(output_dir: impl AsRef<Path>) -> Result<Self> {
        let output_dir = output_dir.as_ref().to_path_buf();

        // Create output directory
        std::fs::create_dir_all(&output_dir)
            .with_context(|| format!("Failed to create output directory: {:?}", output_dir))?;

        // Create blobs subdirectory
        let blobs_dir = output_dir.join("blobs");
        std::fs::create_dir_all(&blobs_dir)
            .with_context(|| format!("Failed to create blobs directory: {:?}", blobs_dir))?;

        Ok(Self { output_dir })
    }

    /// Generate WorkloadIr JSON and blob files
    pub fn generate(&self, operations: Vec<Operation>) -> Result<String> {
        // Count operations per client
        let mut client_ops: HashMap<String, u32> = HashMap::new();
        for op in &operations {
            let client_id = match op {
                Operation::Open { client_id, .. } => client_id,
                Operation::Close { client_id, .. } => client_id,
                Operation::Read { client_id, .. } => client_id,
                Operation::Write { client_id, .. } => client_id,
                Operation::Delete { client_id, .. } => client_id,
                Operation::Rename { client_id, .. } => client_id,
                Operation::Mkdir { client_id, .. } => client_id,
                Operation::Rmdir { client_id, .. } => client_id,
                Operation::Fsctl { client_id, .. } => client_id,
                Operation::Ioctl { client_id, .. } => client_id,
            };
            *client_ops.entry(client_id.clone()).or_insert(0) += 1;
        }

        // Create client specs
        let mut clients: Vec<ClientSpec> = client_ops
            .into_iter()
            .map(|(client_id, operation_count)| ClientSpec {
                client_id,
                operation_count,
            })
            .collect();
        clients.sort_by(|a, b| a.client_id.cmp(&b.client_id));

        // Calculate duration
        let duration_seconds = if let Some(last_op) = operations.last() {
            let last_ts = match last_op {
                Operation::Open { timestamp_us, .. } => *timestamp_us,
                Operation::Close { timestamp_us, .. } => *timestamp_us,
                Operation::Read { timestamp_us, .. } => *timestamp_us,
                Operation::Write { timestamp_us, .. } => *timestamp_us,
                Operation::Delete { timestamp_us, .. } => *timestamp_us,
                Operation::Rename { timestamp_us, .. } => *timestamp_us,
                Operation::Mkdir { timestamp_us, .. } => *timestamp_us,
                Operation::Rmdir { timestamp_us, .. } => *timestamp_us,
                Operation::Fsctl { timestamp_us, .. } => *timestamp_us,
                Operation::Ioctl { timestamp_us, .. } => *timestamp_us,
            };
            (last_ts as f64) / 1_000_000.0
        } else {
            0.0
        };

        // Create WorkloadIr
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

        // Write WorkloadIr JSON
        let ir_path = self.output_dir.join("workload.json");
        let ir_json = serde_json::to_string_pretty(&ir)
            .context("Failed to serialize WorkloadIr")?;
        std::fs::write(&ir_path, ir_json)
            .with_context(|| format!("Failed to write WorkloadIr: {:?}", ir_path))?;

        Ok(ir_path.to_string_lossy().to_string())
    }
}
