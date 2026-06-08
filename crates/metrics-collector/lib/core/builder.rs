//! Builder and per-exporter configuration for [`MetricsCollector`].

use std::{sync::Arc, time::Duration};

use crate::error::{MetricsCollectorError, MetricsCollectorResult};

use super::driver::{CollectorConfig, MetricsCollector, MetricsErrorPolicy};
use super::label_source::LabelSource;
use super::reader::{CollectFn, enrich_with_labels, filter_stale_samples, registry_collect_fn};
use super::types::MetricsExporter;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Default interval between shared-memory metrics reads.
pub const DEFAULT_COLLECT_INTERVAL: Duration = Duration::from_secs(1);

/// Default per-exporter interval between scheduled exports.
pub const DEFAULT_FLUSH_INTERVAL: Duration = Duration::from_secs(10);

/// Default per-exporter collection buffer limit.
pub const DEFAULT_MAX_BUFFERED_COLLECTIONS: usize = 60;

/// Default max age of a sandbox's most recent sample before the collector stops
/// emitting it. A running sandbox samples ~1/s; a quiet slot is a stopped
/// sandbox whose shm slot was never released, which would otherwise be
/// re-exported with a frozen value forever (microsandbox#941). Generous enough
/// that a brief sampler stall on a live sandbox does not drop it.
pub const DEFAULT_MAX_SAMPLE_AGE: Duration = Duration::from_secs(30);

/// Default per-exporter timeout for a single export call.
pub const DEFAULT_EXPORT_TIMEOUT: Duration = Duration::from_secs(30);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Per-exporter configuration.
///
/// Each registered exporter runs in its own worker task with its own buffer
/// cap, flush cadence, export timeout, and error policy. Use
/// [`MetricsCollectorBuilder::register_with`] to attach a custom config;
/// [`MetricsCollectorBuilder::register`] applies the builder's current
/// defaults.
#[derive(Clone, Debug)]
pub struct MetricsExporterConfig {
    /// Interval between scheduled exports for this collector.
    pub flush_interval: Duration,

    /// Maximum collections held in this exporter's local buffer. When the
    /// buffer is full, the oldest collection is dropped and
    /// `dropped_collection_count` on the next export batch is incremented.
    pub max_buffered_collections: usize,

    /// Timeout for a single export call.
    pub export_timeout: Duration,

    /// Behavior when a scheduled export fails.
    pub error_policy: MetricsErrorPolicy,
}

/// Builder for [`MetricsCollector`].
pub struct MetricsCollectorBuilder {
    collect_interval: Duration,
    max_sample_age: Option<Duration>,
    default_collector_config: MetricsExporterConfig,
    collectors: Vec<Registered>,
    collect_fn: CollectFn,
}

#[derive(Clone)]
enum Registered {
    /// Use the builder's default config (resolved at `build()` time).
    Default(Arc<dyn MetricsExporter>),

    /// Use this explicit config, ignoring builder-level defaults.
    Custom(Arc<dyn MetricsExporter>, MetricsExporterConfig),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl MetricsExporterConfig {
    /// Construct a config with all defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the scheduled flush interval for this collector.
    pub fn flush_interval(mut self, interval: Duration) -> Self {
        self.flush_interval = interval;
        self
    }

    /// Set the buffer limit for this collector.
    pub fn max_buffered_collections(mut self, limit: usize) -> Self {
        self.max_buffered_collections = limit;
        self
    }

    /// Set the export timeout for this collector.
    pub fn export_timeout(mut self, timeout: Duration) -> Self {
        self.export_timeout = timeout;
        self
    }

    /// Set the scheduled-export error policy for this collector.
    pub fn error_policy(mut self, policy: MetricsErrorPolicy) -> Self {
        self.error_policy = policy;
        self
    }
}

impl Default for MetricsExporterConfig {
    fn default() -> Self {
        Self {
            flush_interval: DEFAULT_FLUSH_INTERVAL,
            max_buffered_collections: DEFAULT_MAX_BUFFERED_COLLECTIONS,
            export_timeout: DEFAULT_EXPORT_TIMEOUT,
            error_policy: MetricsErrorPolicy::LogAndContinue,
        }
    }
}

impl MetricsCollectorBuilder {
    /// Construct a builder that reads from the named shm registry.
    pub(crate) fn new(registry_name: String) -> Self {
        Self {
            collect_interval: DEFAULT_COLLECT_INTERVAL,
            max_sample_age: Some(DEFAULT_MAX_SAMPLE_AGE),
            default_collector_config: MetricsExporterConfig::default(),
            collectors: Vec::new(),
            collect_fn: registry_collect_fn(registry_name),
        }
    }

    /// Set the collector-wide interval between shared-memory metrics reads.
    pub fn collect_interval(mut self, interval: Duration) -> Self {
        self.collect_interval = interval;
        self
    }

    /// Stop emitting a sandbox once its most recent sample is older than
    /// `max_age`. Guards against a stopped sandbox whose shm slot was never
    /// released being re-exported forever with a frozen value
    /// (microsandbox#941). `None` (or a zero duration) disables the filter.
    /// Defaults to 30s (`DEFAULT_MAX_SAMPLE_AGE`).
    pub fn max_sample_age(mut self, max_age: Option<Duration>) -> Self {
        self.max_sample_age = max_age;
        self
    }

    /// Enrich each collection with per-sandbox labels from a [`LabelSource`]
    /// (e.g. [`CatalogLabelSource`](super::CatalogLabelSource)). Labels are
    /// attached as attributes by label-aware exporters (e.g. OTel). Without
    /// this, collections carry no labels.
    pub fn enrich_labels(mut self, source: Arc<dyn LabelSource>) -> Self {
        self.collect_fn = enrich_with_labels(self.collect_fn, source);
        self
    }

    /// Set the default scheduled flush interval applied to exporters
    /// registered without an explicit [`MetricsExporterConfig`].
    pub fn flush_interval(mut self, interval: Duration) -> Self {
        self.default_collector_config.flush_interval = interval;
        self
    }

    /// Set the default buffer limit applied to exporters registered without
    /// an explicit [`MetricsExporterConfig`].
    pub fn max_buffered_collections(mut self, limit: usize) -> Self {
        self.default_collector_config.max_buffered_collections = limit;
        self
    }

    /// Set the default export timeout applied to exporters registered without
    /// an explicit [`MetricsExporterConfig`].
    pub fn export_timeout(mut self, timeout: Duration) -> Self {
        self.default_collector_config.export_timeout = timeout;
        self
    }

    /// Set the default error policy applied to exporters registered without
    /// an explicit [`MetricsExporterConfig`].
    pub fn error_policy(mut self, policy: MetricsErrorPolicy) -> Self {
        self.default_collector_config.error_policy = policy;
        self
    }

    /// Register an exporter using the builder's current defaults.
    pub fn register<C>(mut self, collector: C) -> Self
    where
        C: MetricsExporter,
    {
        self.collectors
            .push(Registered::Default(Arc::new(collector)));
        self
    }

    /// Register an exporter with an explicit per-exporter configuration.
    pub fn register_with<C>(mut self, collector: C, config: MetricsExporterConfig) -> Self
    where
        C: MetricsExporter,
    {
        self.collectors
            .push(Registered::Custom(Arc::new(collector), config));
        self
    }

    /// Register an already shared exporter using the builder's defaults.
    pub fn register_arc(mut self, collector: Arc<dyn MetricsExporter>) -> Self {
        self.collectors.push(Registered::Default(collector));
        self
    }

    /// Register an already shared exporter with an explicit configuration.
    pub fn register_arc_with(
        mut self,
        collector: Arc<dyn MetricsExporter>,
        config: MetricsExporterConfig,
    ) -> Self {
        self.collectors.push(Registered::Custom(collector, config));
        self
    }

    /// Build the metrics collector.
    pub fn build(self) -> MetricsCollectorResult<MetricsCollector> {
        if self.collect_interval.is_zero() {
            return Err(MetricsCollectorError::InvalidConfig(
                "metrics collect_interval must be greater than zero".into(),
            ));
        }

        let default_config = self.default_collector_config;
        let collectors: Vec<(Arc<dyn MetricsExporter>, MetricsExporterConfig)> = self
            .collectors
            .into_iter()
            .map(|reg| match reg {
                Registered::Default(c) => (c, default_config.clone()),
                Registered::Custom(c, cfg) => (c, cfg),
            })
            .collect();

        for (_, cfg) in &collectors {
            if cfg.flush_interval.is_zero() {
                return Err(MetricsCollectorError::InvalidConfig(
                    "metrics flush_interval must be greater than zero".into(),
                ));
            }
            if cfg.export_timeout.is_zero() {
                return Err(MetricsCollectorError::InvalidConfig(
                    "metrics export_timeout must be greater than zero".into(),
                ));
            }
            if cfg.max_buffered_collections == 0 {
                return Err(MetricsCollectorError::InvalidConfig(
                    "metrics max_buffered_collections must be greater than zero".into(),
                ));
            }
        }

        // Apply the staleness filter outermost so stopped-but-unreleased slots
        // are dropped before export (microsandbox#941). Zero/None disables it.
        let collect_fn = match self.max_sample_age {
            Some(max_age) if !max_age.is_zero() => filter_stale_samples(self.collect_fn, max_age),
            _ => self.collect_fn,
        };

        Ok(MetricsCollector::from_config(CollectorConfig {
            collect_interval: self.collect_interval,
            collect_fn,
            collectors,
        }))
    }

    /// Override the collection source with a custom closure. Test-only.
    #[cfg(test)]
    pub(crate) fn collect_with<F, Fut>(mut self, collect: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = MetricsCollectorResult<super::types::MetricsCollection>>
            + Send
            + 'static,
    {
        self.collect_fn = Arc::new(move || Box::pin(collect()));
        self
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::types::MetricsExportBatch;
    use super::*;

    #[test]
    fn builder_rejects_zero_collect_interval() {
        let result = MetricsCollector::builder("test")
            .collect_interval(Duration::ZERO)
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn builder_rejects_zero_flush_interval_via_default() {
        let result = MetricsCollector::builder("test")
            .flush_interval(Duration::ZERO)
            .register(NoopCollector)
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn builder_rejects_zero_export_timeout_via_default() {
        let result = MetricsCollector::builder("test")
            .export_timeout(Duration::ZERO)
            .register(NoopCollector)
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn builder_rejects_zero_flush_interval_via_register_with() {
        let cfg = MetricsExporterConfig::default().flush_interval(Duration::ZERO);
        let result = MetricsCollector::builder("test")
            .register_with(NoopCollector, cfg)
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn default_buffer_limit_is_sixty_collections() {
        let builder = MetricsCollector::builder("test");
        assert_eq!(
            builder.default_collector_config.max_buffered_collections,
            60
        );
    }

    #[test]
    fn builder_rejects_zero_max_buffered_collections() {
        let result = MetricsCollector::builder("test")
            .max_buffered_collections(0)
            .register(NoopCollector)
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn register_with_overrides_builder_defaults() {
        let custom_cap: usize = 5;
        let cfg = MetricsExporterConfig::default().max_buffered_collections(custom_cap);
        let builder = MetricsCollector::builder("test")
            .max_buffered_collections(99)
            .register_with(NoopCollector, cfg);

        // The Custom registration should carry its own config regardless of
        // the builder-level default.
        match &builder.collectors[0] {
            Registered::Custom(_, c) => assert_eq!(c.max_buffered_collections, custom_cap),
            Registered::Default(_) => panic!("expected Custom registration"),
        }
    }

    struct NoopCollector;
    #[async_trait::async_trait]
    impl MetricsExporter for NoopCollector {
        async fn export(&self, _batch: Arc<MetricsExportBatch>) -> MetricsCollectorResult<()> {
            Ok(())
        }
    }
}
