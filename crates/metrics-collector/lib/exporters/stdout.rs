//! Stdout exporter — writes each batch as one summary line per snapshot.
//!
//! Useful for "is shm even populated?" during development, for a quick
//! demo without standing up an OTLP receiver, and for piping through
//! `jq` / `awk` in shell loops. Not for production: the format is
//! human-readable and not committed as stable.
//!
//! Output format is one line per snapshot:
//!
//! ```text
//! 2026-05-30T00:48:22.713Z sandbox=devbox id=33 cpu=0.000086 \
//!     mem=14.0 MiB / 512.0 MiB disk_r=88.7 MiB disk_w=614.2 MiB \
//!     net_rx=48.00MiB net_tx=274.85KiB uptime=2345m3s
//! ```
//!
//! Empty collections (zero active sandboxes) print a single line:
//! `<timestamp> (no active sandboxes)`.

use std::io::{self, BufWriter, Write};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use microsandbox_utils::format::{format_bytes, format_duration};

use crate::core::{MetricsExportBatch, MetricsExporter, SandboxMetricSnapshot};
use crate::error::{MetricsCollectorError, MetricsCollectorResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Per-batch output sink. Stdout in the binary; the tests use an
/// in-memory buffer.
type Sink = Arc<Mutex<Box<dyn Write + Send + Sync>>>;

/// Stdout-pretty-prints each export batch. Intended for local debugging
/// of `msb-metrics`, not for production telemetry shipping.
pub struct StdoutExporter {
    sink: Sink,
}

impl Default for StdoutExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl StdoutExporter {
    /// New exporter writing to process stdout.
    pub fn new() -> Self {
        Self {
            sink: Arc::new(Mutex::new(Box::new(BufWriter::new(io::stdout())))),
        }
    }

    /// New exporter writing to the supplied `Write`. Used by tests.
    #[doc(hidden)]
    pub fn with_writer<W: Write + Send + Sync + 'static>(writer: W) -> Self {
        Self {
            sink: Arc::new(Mutex::new(Box::new(writer))),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

#[async_trait]
impl MetricsExporter for StdoutExporter {
    async fn export(&self, batch: Arc<MetricsExportBatch>) -> MetricsCollectorResult<()> {
        let mut buf = String::new();
        for collection in &batch.collections {
            if collection.sandboxes.is_empty() {
                buf.push_str(&format!(
                    "{} (no active sandboxes)\n",
                    collection.collected_at.to_rfc3339()
                ));
                continue;
            }
            let ts = collection.collected_at.to_rfc3339();
            for snapshot in &collection.sandboxes {
                let labels = collection.labels.get(&snapshot.sandbox_id);
                buf.push_str(&format_snapshot(
                    &ts,
                    snapshot,
                    labels.map(|l| l.as_slice()),
                ));
                buf.push('\n');
            }
        }
        if batch.dropped_collection_count > 0 {
            buf.push_str(&format!(
                "  (dropped {} stale collections from buffer)\n",
                batch.dropped_collection_count
            ));
        }
        let mut guard = self
            .sink
            .lock()
            .map_err(|e| MetricsCollectorError::Custom(format!("stdout sink poisoned: {e}")))?;
        guard
            .write_all(buf.as_bytes())
            .map_err(|e| MetricsCollectorError::Custom(format!("stdout write failed: {e}")))?;
        guard
            .flush()
            .map_err(|e| MetricsCollectorError::Custom(format!("stdout flush failed: {e}")))?;
        Ok(())
    }

    async fn shutdown(&self) -> MetricsCollectorResult<()> {
        if let Ok(mut guard) = self.sink.lock() {
            let _ = guard.flush();
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn format_snapshot(
    ts: &str,
    s: &SandboxMetricSnapshot,
    labels: Option<&[(String, String)]>,
) -> String {
    let m = &s.metrics;
    let mut line = format!(
        "{ts} sandbox={name} id={id} cpu={cpu:.6} mem={mem} / {mem_lim} \
         disk_r={dr} disk_w={dw} net_rx={nrx} net_tx={ntx} uptime={uptime}",
        ts = ts,
        name = s.name,
        id = s.sandbox_id,
        cpu = f64::from(m.cpu_percent) / 100.0,
        mem = format_bytes(m.memory_bytes),
        mem_lim = format_bytes(m.memory_limit_bytes),
        dr = format_bytes(m.disk_read_bytes),
        dw = format_bytes(m.disk_write_bytes),
        nrx = format_bytes(m.net_rx_bytes),
        ntx = format_bytes(m.net_tx_bytes),
        uptime = format_duration(m.uptime),
    );
    if let Some(labels) = labels.filter(|l| !l.is_empty()) {
        let rendered = labels
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(",");
        line.push_str(&format!(" labels={{{rendered}}}"));
    }
    line
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use chrono::TimeZone;

    use crate::SandboxMetrics;
    use crate::core::MetricsCollection;
    use std::time::Duration;

    fn snapshot(name: &str, id: i32) -> SandboxMetricSnapshot {
        SandboxMetricSnapshot {
            name: name.into(),
            sandbox_id: id,
            run_id: 1,
            pid: 100,
            metrics: SandboxMetrics {
                cpu_percent: 12.5,
                vcpu_time_ns: 1,
                memory_bytes: 14 * 1024 * 1024,
                memory_available_bytes: Some(13 * 1024 * 1024),
                memory_host_resident_bytes: Some(12 * 1024 * 1024),
                memory_limit_bytes: 512 * 1024 * 1024,
                disk_read_bytes: 1024,
                disk_write_bytes: 2048,
                net_rx_bytes: 0,
                net_tx_bytes: 4096,
                uptime: Duration::from_secs(60),
                timestamp: chrono::Utc.with_ymd_and_hms(2026, 5, 30, 0, 0, 0).unwrap(),
            },
        }
    }

    /// Captures stdout writes into an in-memory buffer for assertion.
    #[derive(Clone, Default)]
    struct CapturedSink(Arc<Mutex<Vec<u8>>>);
    impl Write for CapturedSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn writes_one_line_per_snapshot() {
        let sink = CapturedSink::default();
        let exporter = StdoutExporter::with_writer(sink.clone());
        let batch = Arc::new(MetricsExportBatch {
            collections: vec![MetricsCollection {
                collected_at: chrono::Utc.with_ymd_and_hms(2026, 5, 30, 1, 2, 3).unwrap(),
                sandboxes: vec![snapshot("devbox", 33), snapshot("devenv", 38)],
                labels: std::collections::HashMap::new(),
            }],
            dropped_collection_count: 0,
        });
        exporter.export(batch).await.expect("export");

        let buf = sink.0.lock().unwrap().clone();
        let out = String::from_utf8(buf).expect("utf8");
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2, "two snapshots → two lines, got: {out}");
        assert!(lines[0].contains("sandbox=devbox"));
        assert!(lines[0].contains("id=33"));
        assert!(lines[0].contains("cpu=0.125000"));
        assert!(lines[0].contains("mem=14.0 MiB / 512.0 MiB"));
        assert!(lines[1].contains("sandbox=devenv"));
    }

    #[tokio::test]
    async fn appends_labels_when_present() {
        let sink = CapturedSink::default();
        let exporter = StdoutExporter::with_writer(sink.clone());
        let batch = Arc::new(MetricsExportBatch {
            collections: vec![MetricsCollection {
                collected_at: chrono::Utc.with_ymd_and_hms(2026, 5, 30, 1, 2, 3).unwrap(),
                sandboxes: vec![snapshot("devbox", 33)],
                labels: std::collections::HashMap::from([(
                    33,
                    Arc::new(vec![("user.id".to_string(), "alice".to_string())]),
                )]),
            }],
            dropped_collection_count: 0,
        });
        exporter.export(batch).await.expect("export");

        let out = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
        assert!(
            out.contains("labels={user.id=alice}"),
            "label should be rendered, got: {out}"
        );
    }

    #[tokio::test]
    async fn writes_marker_line_for_empty_collection() {
        let sink = CapturedSink::default();
        let exporter = StdoutExporter::with_writer(sink.clone());
        let batch = Arc::new(MetricsExportBatch {
            collections: vec![MetricsCollection {
                collected_at: chrono::Utc.with_ymd_and_hms(2026, 5, 30, 1, 2, 3).unwrap(),
                sandboxes: vec![],
                labels: std::collections::HashMap::new(),
            }],
            dropped_collection_count: 0,
        });
        exporter.export(batch).await.expect("export");

        let out = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
        assert!(
            out.contains("(no active sandboxes)"),
            "empty collection should print the marker, got: {out}"
        );
    }

    #[tokio::test]
    async fn surfaces_dropped_count() {
        let sink = CapturedSink::default();
        let exporter = StdoutExporter::with_writer(sink.clone());
        let batch = Arc::new(MetricsExportBatch {
            collections: vec![],
            dropped_collection_count: 7,
        });
        exporter.export(batch).await.expect("export");

        let out = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
        assert!(out.contains("dropped 7"), "dropped count missing in: {out}");
    }
}
