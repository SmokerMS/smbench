use anyhow::Result;
use async_trait::async_trait;

use smbench::backend::{
    ensure_backend_allowed, BackendCapabilities, BackendMode, ConnectionState, SMBBackend,
};

struct DevOnlyBackend;

#[async_trait]
impl SMBBackend for DevOnlyBackend {
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            name: "dev-only".to_string(),
            supports_oplocks: false,
            is_dev_only: true,
        }
    }

    async fn connect(&self, _client_id: &str) -> Result<ConnectionState> {
        Err(anyhow::anyhow!("not implemented"))
    }
}

#[test]
fn test_dev_only_backend_blocked_in_production() {
    let backend = DevOnlyBackend;
    let result = ensure_backend_allowed(&backend, BackendMode::Production);
    assert!(result.is_err());
}
