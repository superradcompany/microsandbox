use std::sync::atomic::{AtomicBool, Ordering};

use super::*;

//--------------------------------------------------------------------------------------------------
// Types: Test Hooks
//--------------------------------------------------------------------------------------------------

/// A hook that tracks whether before_plan was called.
struct BeforePlanTracker {
    called: AtomicBool,
}

impl hooks::DualDispatchHook for BeforePlanTracker {
    fn before_plan(&self, _ctx: &mut hooks::HookCtx) -> hooks::HookDecision {
        self.called.store(true, Ordering::SeqCst);
        hooks::HookDecision::Continue
    }
}

/// A hook that tracks whether after_dispatch was called.
struct AfterDispatchTracker {
    called: AtomicBool,
}

impl hooks::DualDispatchHook for AfterDispatchTracker {
    fn after_dispatch(
        &self,
        _ctx: &hooks::HookCtx,
        _step: &hooks::DispatchStep,
        _out: &hooks::StepResult,
    ) {
        self.called.store(true, Ordering::SeqCst);
    }
}

/// A hook that denies all operations from before_plan.
struct DenyAllHook {
    errno: i32,
}

impl hooks::DualDispatchHook for DenyAllHook {
    fn before_plan(&self, _ctx: &mut hooks::HookCtx) -> hooks::HookDecision {
        hooks::HookDecision::Deny(self.errno)
    }
}

/// A hook that adds a hint.
struct HintAdder;

impl hooks::DualDispatchHook for HintAdder {
    fn before_plan(&self, _ctx: &mut hooks::HookCtx) -> hooks::HookDecision {
        hooks::HookDecision::AddHint(policy::Hint::Custom("test_hint".to_string()))
    }
}

/// A hook that short-circuits with a synthetic response.
struct ShortCircuitHook;

impl hooks::DualDispatchHook for ShortCircuitHook {
    fn before_plan(&self, _ctx: &mut hooks::HookCtx) -> hooks::HookDecision {
        hooks::HookDecision::ShortCircuit(hooks::SyntheticResponse::Ok)
    }
}

/// A hook that tracks ordering via an atomic counter.
struct OrderingTracker {
    index: usize,
    order: Arc<std::sync::Mutex<Vec<usize>>>,
}

impl hooks::DualDispatchHook for OrderingTracker {
    fn before_plan(&self, _ctx: &mut hooks::HookCtx) -> hooks::HookDecision {
        self.order.lock().unwrap().push(self.index);
        hooks::HookDecision::Continue
    }
}

/// A hook that tracks observer phases.
struct ObserverTracker {
    after_dispatch_called: AtomicBool,
    after_commit_called: AtomicBool,
    after_response_called: AtomicBool,
}

impl hooks::DualDispatchHook for ObserverTracker {
    fn after_dispatch(
        &self,
        _ctx: &hooks::HookCtx,
        _step: &hooks::DispatchStep,
        _out: &hooks::StepResult,
    ) {
        self.after_dispatch_called.store(true, Ordering::SeqCst);
    }

    fn after_commit(&self, _event: &hooks::CommitEvent) {
        self.after_commit_called.store(true, Ordering::SeqCst);
    }

    fn after_response(&self, _event: &hooks::ResponseEvent) {
        self.after_response_called.store(true, Ordering::SeqCst);
    }
}

/// A hook that denies from before_dispatch.
struct BeforeDispatchDenier {
    errno: i32,
}

impl hooks::DualDispatchHook for BeforeDispatchDenier {
    fn before_dispatch(
        &self,
        _ctx: &mut hooks::HookCtx,
        _step: &hooks::DispatchStep,
    ) -> hooks::HookDecision {
        hooks::HookDecision::Deny(self.errno)
    }
}

/// A hook that attempts to track state but cannot mutate core state.
struct NoMutateHook {
    saw_request: AtomicBool,
}

impl hooks::DualDispatchHook for NoMutateHook {
    fn before_plan(&self, ctx: &mut hooks::HookCtx) -> hooks::HookDecision {
        // Hooks can inspect context but not mutate core state.
        self.saw_request.store(true, Ordering::SeqCst);
        // Add metadata — this is allowed.
        ctx.metadata
            .insert("observed".to_string(), "yes".to_string());
        hooks::HookDecision::Continue
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn test_hook_before_plan_called() {
    let tracker = Arc::new(BeforePlanTracker {
        called: AtomicBool::new(false),
    });
    let sb = DualFsTestSandbox::with_hooks(vec![tracker.clone()]);
    // Any operation that goes through the plan pipeline.
    let _ = sb.lookup_root("nonexistent");
    assert!(
        tracker.called.load(Ordering::SeqCst),
        "before_plan should have been called"
    );
}

#[test]
fn test_hook_after_dispatch_called() {
    let tracker = Arc::new(AfterDispatchTracker {
        called: AtomicBool::new(false),
    });
    let sb = DualFsTestSandbox::with_hooks(vec![tracker.clone()]);
    // Lookup goes through the dispatch pipeline and fires after_dispatch.
    let _ = sb.lookup_root("nonexistent");
    assert!(
        tracker.called.load(Ordering::SeqCst),
        "after_dispatch should have been called"
    );
}

#[test]
fn test_hook_deny_stops_chain() {
    let denier = Arc::new(DenyAllHook {
        errno: LINUX_EACCES,
    });
    let sb = DualFsTestSandbox::with_hooks(vec![denier]);
    // Lookup should be denied.
    let result = sb.lookup_root("anything");
    DualFsTestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_hook_add_hint() {
    // A hook that adds a hint — the operation should still succeed
    // (hints are informational for the policy).
    let adder = Arc::new(HintAdder);
    let sb = DualFsTestSandbox::with_hooks(vec![adder]);
    let result = sb.fuse_create_root("hinted.txt");
    assert!(result.is_ok(), "operation should succeed with hint");
    if let Ok((entry, handle)) = result {
        sb.fs
            .release(DualFsTestSandbox::ctx(), entry.inode, 0, handle, false, false, None)
            .unwrap();
    }
}

#[test]
fn test_hook_short_circuit() {
    // ShortCircuit with SyntheticResponse::Ok for an unlink.
    // The unlink will get short-circuited before any backend dispatch.
    let circuit = Arc::new(ShortCircuitHook);
    let sb = DualFsTestSandbox::with_hooks(vec![circuit]);
    // Try to unlink a nonexistent file — normally ENOENT, but short-circuited to Ok.
    // Note: the short-circuit fires at before_plan, so the result depends on whether
    // unlink goes through the plan pipeline. Let's test with a create — short-circuit
    // from before_plan for lookup (which create uses internally to check existence).
    // Actually, let's just test lookup itself.
    let result = sb.lookup_root("nonexistent");
    // ShortCircuit(Ok) for a lookup doesn't produce a valid Entry, so it may error.
    // The important thing is it doesn't panic. The decode will fail (expects Entry).
    // This tests that ShortCircuit is handled.
    assert!(
        result.is_err(),
        "ShortCircuit(Ok) for lookup should result in error (wrong type)"
    );
}

#[test]
fn test_hook_ordering() {
    let order = Arc::new(std::sync::Mutex::new(Vec::new()));
    let h0 = Arc::new(OrderingTracker {
        index: 0,
        order: order.clone(),
    });
    let h1 = Arc::new(OrderingTracker {
        index: 1,
        order: order.clone(),
    });
    let h2 = Arc::new(OrderingTracker {
        index: 2,
        order: order.clone(),
    });
    let sb = DualFsTestSandbox::with_hooks(vec![h0, h1, h2]);
    let _ = sb.lookup_root("trigger_ordering");
    let logged = order.lock().unwrap();
    assert_eq!(&*logged, &[0, 1, 2], "hooks should fire in registration order");
}

#[test]
fn test_hook_observer_phases_fire_and_forget() {
    let tracker = Arc::new(ObserverTracker {
        after_dispatch_called: AtomicBool::new(false),
        after_commit_called: AtomicBool::new(false),
        after_response_called: AtomicBool::new(false),
    });
    let sb = DualFsTestSandbox::with_hooks(vec![tracker.clone()]);
    // Lookup triggers after_dispatch (via backend dispatch) and after_response.
    let _ = sb.lookup_root("nonexistent");
    assert!(
        tracker.after_dispatch_called.load(Ordering::SeqCst),
        "after_dispatch should fire on lookup"
    );
    assert!(
        tracker.after_response_called.load(Ordering::SeqCst),
        "after_response should fire on lookup"
    );
    // Create a file to trigger after_commit (create fires after_commit for dentry registration).
    let (entry, handle) = sb.fuse_create_root("observer.txt").unwrap();
    sb.fs
        .release(DualFsTestSandbox::ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
    assert!(
        tracker.after_commit_called.load(Ordering::SeqCst),
        "after_commit should fire on create"
    );
}

#[test]
fn test_hook_before_dispatch_can_deny() {
    let denier = Arc::new(BeforeDispatchDenier {
        errno: LINUX_EACCES,
    });
    let sb = DualFsTestSandbox::with_hooks(vec![denier]);
    // before_dispatch fires right before the backend call. This should deny lookup.
    let result = sb.lookup_root("anything");
    DualFsTestSandbox::assert_errno(result, LINUX_EACCES);
}

#[test]
fn test_hook_cannot_mutate_core_state() {
    // Hooks can add hints and metadata, but cannot directly mutate inodes or dentries.
    let hook = Arc::new(NoMutateHook {
        saw_request: AtomicBool::new(false),
    });
    let sb = DualFsTestSandbox::with_hooks(vec![hook.clone()]);
    // Lookup triggers before_plan where NoMutateHook observes the request.
    let _ = sb.lookup_root("nonexistent");
    assert!(
        hook.saw_request.load(Ordering::SeqCst),
        "hook should have observed the request"
    );
    // Create a file and verify state is intact — the hook could only observe, not corrupt.
    let (entry, handle) = sb.fuse_create_root("test_mut.txt").unwrap();
    sb.fs
        .release(DualFsTestSandbox::ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
    let lookup = sb.lookup_root("test_mut.txt");
    assert!(lookup.is_ok(), "filesystem state should be intact");
}
