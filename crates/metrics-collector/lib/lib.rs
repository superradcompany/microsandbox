//! Metrics collector orchestrator. Polls the microsandbox shared-memory
//! metrics registry, buffers per-exporter, and fans batches out to
//! registered exporters.
//!
//! See `docs/msb-metrics-binary-plan.md` for the architecture and the
//! `msb-metrics` binary that ships in this crate's `bin/main.rs`.
//!
//! This file is intentionally a stub during the orchestrator migration.
//! Modules land in follow-on commits: `driver`, `builder`, `worker`,
//! `types`, `exporter`, `exporters/otel`.
