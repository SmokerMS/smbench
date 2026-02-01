# Decisions
- Rust edition: 2026
- Error handling: anyhow for app, thiserror for libraries (optional)
- Logging: tracing + tracing-subscriber
- CLI: clap derive
- Runtime: tokio full
- Default backend for dev: osmount (dev-only) OR mock backend
- Production mode must reject osmount backend
- Test environment: local linux VM
