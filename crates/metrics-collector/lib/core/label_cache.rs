//! In-process cache of per-sandbox labels for the metrics read path.
//!
//! On each tick the collector reads the active sandboxes from shared memory and
//! resolves their labels from the catalog config that describes the running VM.
//! The cache avoids reparsing unchanged configs while still refreshing when a
//! sandbox restarts quickly enough to remain in consecutive snapshots.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
};

use crate::error::{MetricsCollectorError, MetricsCollectorResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One sandbox's labels as `(key, value)` pairs, ordered by key for stable
/// output.
pub(crate) type LabelSet = Vec<(String, String)>;

/// A parsed label set and the config JSON from which it was derived.
struct CacheEntry {
    config_json: String,
    labels: Arc<LabelSet>,
}

/// Caches each active sandbox's labels, keyed on `sandbox_id`.
///
/// An entry is reparsed when its effective config changes. Presence-based
/// eviction still bounds the cache to the active sandbox count.
#[derive(Default)]
pub(crate) struct LabelCache {
    by_sandbox_id: HashMap<i32, CacheEntry>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LabelCache {
    /// An empty cache.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Drop cached entries for sandboxes absent from the current snapshot.
    pub(crate) fn sync(&mut self, active: &HashSet<i32>) {
        self.by_sandbox_id.retain(|id, _| active.contains(id));
    }

    /// Labels parsed from `config_json`, reusing an unchanged cached entry.
    pub(crate) fn get_or_parse(
        &mut self,
        sandbox_id: i32,
        config_json: &str,
    ) -> MetricsCollectorResult<Arc<LabelSet>> {
        if let Some(entry) = self.by_sandbox_id.get(&sandbox_id)
            && entry.config_json == config_json
        {
            return Ok(entry.labels.clone());
        }

        let labels = Arc::new(extract_labels(config_json).map_err(|error| {
            MetricsCollectorError::Custom(format!(
                "parse active config labels for sandbox id {sandbox_id}: {error}"
            ))
        })?);
        self.by_sandbox_id.insert(
            sandbox_id,
            CacheEntry {
                config_json: config_json.to_owned(),
                labels: labels.clone(),
            },
        );
        Ok(labels)
    }

    /// Number of cached sandboxes. Test helper for asserting eviction.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.by_sandbox_id.len()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn extract_labels(config_json: &str) -> Result<LabelSet, String> {
    let config = serde_json::from_str::<serde_json::Value>(config_json)
        .map_err(|error| format!("invalid JSON: {error}"))?;
    let Some(labels) = config.get("labels") else {
        return Ok(LabelSet::new());
    };
    let labels = labels
        .as_object()
        .ok_or_else(|| "labels must be an object".to_string())?;

    let mut labels_by_key = BTreeMap::new();
    for (key, value) in labels {
        let value = value
            .as_str()
            .ok_or_else(|| format!("label {key:?} must have a string value"))?;
        labels_by_key.insert(key.clone(), value.to_owned());
    }
    Ok(labels_by_key.into_iter().collect())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_or_parse_sorts_then_caches_labels() {
        let mut cache = LabelCache::new();
        let config = r#"{"labels":{"user.id":"alice","tier":"web"}}"#;

        let first = cache.get_or_parse(1, config).unwrap();
        assert_eq!(
            *first,
            vec![
                ("tier".to_string(), "web".to_string()),
                ("user.id".to_string(), "alice".to_string()),
            ]
        );
        let cached = cache.get_or_parse(1, config).unwrap();

        assert!(Arc::ptr_eq(&first, &cached));
    }

    #[test]
    fn changed_config_refreshes_same_sandbox_id() {
        let mut cache = LabelCache::new();
        let first = cache
            .get_or_parse(1, r#"{"labels":{"user.id":"alice"}}"#)
            .unwrap();
        let refreshed = cache
            .get_or_parse(1, r#"{"labels":{"user.id":"bob"}}"#)
            .unwrap();

        assert!(!Arc::ptr_eq(&first, &refreshed));
        assert_eq!(*refreshed, vec![("user.id".to_string(), "bob".to_string())]);
    }

    #[test]
    fn missing_labels_caches_an_empty_set() {
        let mut cache = LabelCache::new();

        let labels = cache.get_or_parse(1, r#"{"name":"api"}"#).unwrap();

        assert!(labels.is_empty());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn sync_evicts_absent_sandboxes() {
        let mut cache = LabelCache::new();
        cache.get_or_parse(1, "{}").unwrap();
        cache.get_or_parse(2, "{}").unwrap();

        cache.sync(&HashSet::from([2]));

        assert_eq!(cache.len(), 1);
    }
}
