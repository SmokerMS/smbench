use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand, ValueEnum};
use smbench::backend::{BackendMode, SMBBackend};
use smbench::ir::WorkloadIr;
use smbench::scheduler::{InvariantMode, Scheduler, SchedulerConfig};

#[derive(Parser, Debug)]
#[command(name = "smbench", version, about = "SMBench – SMB workload replay & analysis")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    // ── Legacy flat-args mode (kept for backwards compatibility) ──

    /// Path to workload IR JSON (for legacy run mode)
    #[arg(long, global = false)]
    ir: Option<PathBuf>,

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

    /// Validate IR and exit without running
    #[arg(long, default_value_t = false)]
    validate_only: bool,

    /// Validate IR and print summary without executing
    #[arg(long, default_value_t = false)]
    dry_run: bool,

    /// Use JSON logs (default true)
    #[arg(long, default_value_t = true)]
    log_json: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Compile a PCAP file into a WorkloadIr JSON (+ blob files)
    #[cfg(feature = "pcap-compiler")]
    Compile {
        /// Path to the PCAP or PCAPNG file
        pcap_file: PathBuf,

        /// Output directory for workload.json and blobs/
        #[arg(short, long, default_value = "output")]
        output: PathBuf,

        /// Only include traffic from/to this client IP
        #[arg(long)]
        filter_client: Option<String>,

        /// Only include traffic for this share name
        #[arg(long)]
        filter_share: Option<String>,

        /// Anonymize IPs and file paths in the output
        #[arg(long, default_value_t = false)]
        anonymize: bool,

        /// Verbose logging
        #[arg(short, long, default_value_t = false)]
        verbose: bool,
    },

    /// Replay a WorkloadIr against an SMB server
    Run {
        /// Path to workload IR JSON
        ir: PathBuf,
    },

    /// Validate a WorkloadIr JSON and print a summary
    Validate {
        /// Path to workload IR JSON
        ir: PathBuf,
    },
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

    match cli.command {
        #[cfg(feature = "pcap-compiler")]
        Some(Commands::Compile {
            pcap_file,
            output,
            filter_client,
            filter_share,
            anonymize,
            verbose,
        }) => {
            let options = smbench::compiler::CompilerOptions {
                filter_client,
                filter_share,
                anonymize,
                verbose,
            };
            let compiler = smbench::compiler::PcapCompiler::with_options(
                pcap_file.to_string_lossy().to_string(),
                options,
            )?;
            let ir_path = compiler.compile(&output).await?;
            println!("Compiled PCAP → {}", ir_path);
        }

        Some(Commands::Run { ref ir }) => {
            run_workload(&cli, ir).await?;
        }

        Some(Commands::Validate { ref ir }) => {
            let ir_contents = fs::read_to_string(&ir)?;
            let workload: WorkloadIr = serde_json::from_str(&ir_contents)?;
            workload.validate().map_err(|e| anyhow!(e))?;
            let summary = workload.summary();
            println!("IR validation OK");
            println!(
                "Clients: {} | Ops: {} (open {}, read {}, write {}, close {}, rename {}, delete {})",
                summary.client_count,
                summary.operation_count,
                summary.open_ops,
                summary.read_ops,
                summary.write_ops,
                summary.close_ops,
                summary.rename_ops,
                summary.delete_ops
            );
        }

        None => {
            // Legacy flat-args mode: require --ir
            if let Some(ref ir_path) = cli.ir {
                let ir_contents = fs::read_to_string(ir_path)?;
                let ir: WorkloadIr = serde_json::from_str(&ir_contents)?;
                ir.validate().map_err(|err| anyhow!(err))?;
                let summary = ir.summary();

                if cli.validate_only {
                    println!("IR validation OK");
                    return Ok(());
                }
                if cli.dry_run {
                    println!("IR validation OK");
                    println!(
                        "Clients: {} | Ops: {} (open {}, read {}, write {}, close {}, rename {}, delete {})",
                        summary.client_count,
                        summary.operation_count,
                        summary.open_ops,
                        summary.read_ops,
                        summary.write_ops,
                        summary.close_ops,
                        summary.rename_ops,
                        summary.delete_ops
                    );
                    return Ok(());
                }

                run_workload(&cli, ir_path).await?;
            } else {
                eprintln!("Usage: smbench <COMMAND> or smbench --ir <path>");
                eprintln!("  compile   Compile a PCAP file into WorkloadIr");
                eprintln!("  run       Replay a WorkloadIr against an SMB server");
                eprintln!("  validate  Validate a WorkloadIr JSON");
                std::process::exit(1);
            }
        }
    }

    Ok(())
}

async fn run_workload(cli: &Cli, ir_path: &std::path::Path) -> Result<()> {
    let ir_contents = fs::read_to_string(ir_path)?;
    let ir: WorkloadIr = serde_json::from_str(&ir_contents)?;
    ir.validate().map_err(|err| anyhow!(err))?;

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
    let summary = scheduler.run(backend).await?;
    println!(
        "Run complete: dispatched={}, succeeded={}, failed={}, violations={}, wall_clock={:.2}s",
        summary.dispatched,
        summary.succeeded,
        summary.failed,
        summary.invariant_violations,
        summary.wall_clock.as_secs_f64()
    );
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
