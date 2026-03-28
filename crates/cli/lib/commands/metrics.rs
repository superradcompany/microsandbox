//! `msb metrics` command — show live sandbox metrics.

use clap::Args;
use microsandbox::sandbox::{Sandbox, SandboxMetrics, all_sandbox_metrics};

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Show live metrics for a running sandbox.
#[derive(Debug, Args)]
pub struct MetricsArgs {
    /// Sandbox to inspect. Omit to show all running sandboxes.
    pub name: Option<String>,

    /// Output format (json).
    #[arg(long, value_name = "FORMAT", value_parser = ["json"])]
    pub format: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb metrics` command.
pub async fn run(args: MetricsArgs) -> anyhow::Result<()> {
    if let Some(name) = args.name.as_deref() {
        let handle = Sandbox::get(name).await?;
        let metrics = handle.metrics().await?;

        if args.format.as_deref() == Some("json") {
            println!(
                "{}",
                serde_json::to_string_pretty(&metrics_json(handle.name(), &metrics))?
            );
            return Ok(());
        }

        print_table(&[(handle.name().to_string(), metrics)]);
        return Ok(());
    }

    let mut metrics = all_sandbox_metrics()
        .await?
        .into_iter()
        .collect::<Vec<(String, SandboxMetrics)>>();
    metrics.sort_by(|left, right| left.0.cmp(&right.0));

    if args.format.as_deref() == Some("json") {
        let json = serde_json::Value::Array(
            metrics
                .iter()
                .map(|(name, metrics)| metrics_json(name, metrics))
                .collect(),
        );
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }

    if metrics.is_empty() {
        eprintln!("No running sandboxes.");
        return Ok(());
    }

    print_table(&metrics);

    Ok(())
}

fn print_table(metrics: &[(String, SandboxMetrics)]) {
    let mut table = ui::Table::new(&[
        "NAME",
        "CPU",
        "MEMORY",
        "DISK READ",
        "DISK WRITE",
        "NET RX",
        "NET TX",
        "UPTIME",
        "TIMESTAMP",
    ]);

    for (name, metric) in metrics {
        table.add_row(vec![
            name.clone(),
            format!("{:.1}%", metric.cpu_percent),
            format!(
                "{} / {}",
                ui::format_bytes(metric.memory_bytes),
                ui::format_bytes(metric.memory_limit_bytes)
            ),
            ui::format_bytes(metric.disk_read_bytes),
            ui::format_bytes(metric.disk_write_bytes),
            ui::format_bytes(metric.net_rx_bytes),
            ui::format_bytes(metric.net_tx_bytes),
            ui::format_duration(metric.uptime),
            metric.timestamp.to_rfc3339(),
        ]);
    }

    table.print();
}

fn metrics_json(name: &str, metrics: &SandboxMetrics) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "timestamp": metrics.timestamp.to_rfc3339(),
        "cpu_percent": metrics.cpu_percent,
        "memory_bytes": metrics.memory_bytes,
        "memory_limit_bytes": metrics.memory_limit_bytes,
        "disk_read_bytes": metrics.disk_read_bytes,
        "disk_write_bytes": metrics.disk_write_bytes,
        "net_rx_bytes": metrics.net_rx_bytes,
        "net_tx_bytes": metrics.net_tx_bytes,
        "uptime_secs": metrics.uptime.as_secs_f64(),
    })
}
