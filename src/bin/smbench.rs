use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::{Parser, ValueEnum};
use smbench::backend::{BackendMode, SMBBackend};
use smbench::ir::WorkloadIr;
use smbench::scheduler::{InvariantMode, Scheduler, SchedulerConfig};

#[derive(Parser, Debug)]
#[command(name = "smbench", version, about = "SMBench CLI runner")]
struct Cli {
    /// Path to workload IR JSON
    #[arg(long)]
    ir: PathBuf,

    /// Backend implementation to use
    #[arg(long, value_enum, default_value = "smb-rs")]
    backend: BackendChoice,

    /// Backend mode (development or production)
    #[arg(long, value_enum, default_value = "development")]
    backend_mode: BackendModeArg,

    /// Scheduler invariant handling
    #[arg(long, value_enum, default_value = "panic")]
    invariant_mode: InvariantModeArg,

    /// Max concurrent operations across clients
    #[arg(long, default_value_t = 64)]
    max_concurrent: usize,

    /// Scheduler worker count
    #[arg(long, default_value_t = 4)]
    worker_count: usize,

    /// Time scale factor (1.0 = real time)
    #[arg(long, default_value_t = 1.0)]
    time_scale: f64,

    /// Watchdog interval in milliseconds
    #[arg(long, default_value_t = 500)]
    watchdog_interval_ms: u64,

    /// In-flight timeout in milliseconds
    #[arg(long, default_value_t = 10_000)]
    inflight_timeout_ms: u64,

    /// Emit scheduler state dumps on invariant errors/timeouts
    #[arg(long, default_value_t = false)]
    debug_dump_on_error: bool,

    /// Use JSON logs (default true)
    #[arg(long, default_value_t = true)]
    log_json: bool,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum BackendChoice {
    SmbRs,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum BackendModeArg {
    Development,
    Production,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum InvariantModeArg {
    Panic,
    Log,
}

impl From<BackendModeArg> for BackendMode {
    fn from(value: BackendModeArg) -> Self {
        match value {
            BackendModeArg::Development => BackendMode::Development,
            BackendModeArg::Production => BackendMode::Production,
        }
    }
}

impl From<InvariantModeArg> for InvariantMode {
    fn from(value: InvariantModeArg) -> Self {
        match value {
            InvariantModeArg::Panic => InvariantMode::Panic,
            InvariantModeArg::Log => InvariantMode::LogAndContinue,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.log_json)?;

    let ir_contents = fs::read_to_string(&cli.ir)?;
    let ir: WorkloadIr = serde_json::from_str(&ir_contents)?;

    let backend: Arc<dyn SMBBackend> = match cli.backend {
        BackendChoice::SmbRs => build_smb_rs_backend()?,
    };

    let config = SchedulerConfig {
        max_concurrent: cli.max_concurrent,
        time_scale: cli.time_scale,
        worker_count: cli.worker_count,
        backend_mode: cli.backend_mode.into(),
        invariant_mode: cli.invariant_mode.into(),
        debug_dump_on_error: cli.debug_dump_on_error,
        watchdog_interval: std::time::Duration::from_millis(cli.watchdog_interval_ms),
        inflight_timeout: std::time::Duration::from_millis(cli.inflight_timeout_ms),
    };

    let scheduler = Scheduler::from_ir(ir, config)?;
    scheduler.run(backend).await?;
    Ok(())
}

fn init_tracing(json: bool) -> Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "info".into());
    if json {
        tracing_subscriber::fmt().with_env_filter(filter).json().init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
    Ok(())
}

fn build_smb_rs_backend() -> Result<Arc<dyn SMBBackend>> {
    #[cfg(feature = "smb-rs-backend")]
    {
        let config = smbench::backend::smbrs::SmbRsConfig::from_env()?;
        Ok(Arc::new(smbench::backend::smbrs::SmbRsBackend::new(
            config,
        )))
    }
    #[cfg(not(feature = "smb-rs-backend"))]
    {
        Err(anyhow!("smb-rs backend feature not enabled"))
    }
}
