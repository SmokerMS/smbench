use tracing_subscriber::fmt::format::FmtSpan;

pub fn init_tracing() {
    let subscriber = tracing_subscriber::fmt()
        .with_span_events(FmtSpan::CLOSE)
        .with_target(false)
        .json()
        .finish();

    let _ = tracing::subscriber::set_global_default(subscriber);
}
