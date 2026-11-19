//! Context clones share captured configuration, catalog initialization and control state.

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn retained_context_shares_all_local_state() {
        let context = LocalContext::from_backend_config(
            BackendConfig::new(GlobalConfigPatch::default(), GlobalConfigPatch::default()),
            ContextSelectionSource::Programmatic,
            None,
        );
        let retained = context.clone_shared();
        let cloned = retained.as_local().unwrap();
        assert!(Arc::ptr_eq(&context.inner, &cloned.inner));
        assert!(context.inner.db.get().is_none());
        drop(context);
        assert!(cloned.inner.db.get().is_none());
    }
}
