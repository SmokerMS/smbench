use tokio::sync::mpsc;
use tokio::time::{sleep_until, Duration, Instant};

#[tokio::test]
async fn test_timing_precision_realistic() {
    let start = Instant::now();
    let (tx, mut rx) = mpsc::channel(1000);

    for i in 0..1000u64 {
        let tx = tx.clone();
        tokio::spawn(async move {
            let target_us = 100_000 + (i * 1_000);
            let target = start + Duration::from_micros(target_us);
            sleep_until(target).await;
            let drift_us = Instant::now().duration_since(target).as_micros() as i64;
            let _ = tx.send(drift_us).await;
        });
    }

    drop(tx);

    let mut drifts = Vec::new();
    while let Some(drift) = rx.recv().await {
        drifts.push(drift);
    }

    drifts.sort_unstable();

    let p50 = drifts[drifts.len() / 2];
    let p95 = drifts[(drifts.len() * 95) / 100];
    let p99 = drifts[(drifts.len() * 99) / 100];
    let max = drifts[drifts.len() - 1];

    println!("Timing drift (1000 timers):");
    println!("  p50: {} µs", p50);
    println!("  p95: {} µs", p95);
    println!("  p99: {} µs", p99);
    println!("  max: {} µs", max);

    assert!(p50 < 5_000, "p50 drift must be <5ms, got {}µs", p50);
    assert!(p95 < 20_000, "p95 drift must be <20ms, got {}µs", p95);
    assert!(p99 < 50_000, "p99 drift must be <50ms, got {}µs", p99);
}
