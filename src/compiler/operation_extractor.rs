//! Operation extraction from SMB state machine
//!
//! Converts tracked SMB operations to IR operations

use super::state_machine::{SmbConnection, TrackedOperation};
use crate::ir::Operation;
use anyhow::Result;

/// Operation extractor
pub struct OperationExtractor;

impl OperationExtractor {
    /// Create a new operation extractor
    pub fn new() -> Self {
        Self
    }

    /// Extract IR operations from SMB connections
    pub fn extract(&self, connections: &[SmbConnection]) -> Result<Vec<Operation>> {
        let mut operations = Vec::new();

        for conn in connections {
            for tracked_op in &conn.operations {
                if let Some(ir_op) = self.convert_operation(&conn.client_id, tracked_op)? {
                    operations.push(ir_op);
                }
            }
        }

        // Sort by timestamp
        operations.sort_by_key(|op| match op {
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
        });

        Ok(operations)
    }

    fn convert_operation(
        &self,
        _client_id: &str,
        _tracked_op: &TrackedOperation,
    ) -> Result<Option<Operation>> {
        // TODO: Implement operation conversion
        // 1. Map SMB operations to IR operations
        // 2. Generate unique op_id
        // 3. Generate handle_ref for file operations
        // 4. Extract blob data for Write operations
        Ok(None)
    }
}

impl Default for OperationExtractor {
    fn default() -> Self {
        Self::new()
    }
}
