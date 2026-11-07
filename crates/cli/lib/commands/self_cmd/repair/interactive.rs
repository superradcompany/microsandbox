//! Repair selected sandboxes independently, keeping consent and partial outcomes visible.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use microsandbox::sandbox::{Sandbox, StorageRecovery, StorageRecoveryOptions};
use microsandbox::setup::{
    self, StorageDiagnosticReason, StorageDiagnosticStatus, StorageRepairBlocker,
    StorageSandboxDiagnosis, StorageSelection,
};
use microsandbox::{MicrosandboxError, MicrosandboxResult};

use super::super::storage_doctor::{StorageDoctorExit, terminal_text};
use super::RepairArgs;
use super::report::{self, Actions, Failure, RuntimeVersion};
use super::terminal::{Screen, Target};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Pending,
    AlreadyReady,
    Repaired,
    Investigation(Failure),
    Skipped(&'static str),
    Cancelled,
}

struct Entry {
    name: String,
    diagnosis: Option<StorageSandboxDiagnosis>,
    outcome: Outcome,
    actions: Actions,
    stopped: Vec<String>,
    inspection_unavailable: bool,
}

/// Keep the decision sequence testable without launching VMs or fabricating private run tokens.
trait Operations {
    type Blocker;

    async fn inspect(&mut self, name: &str) -> MicrosandboxResult<StorageSandboxDiagnosis>;
    async fn blockers(&mut self, name: &str) -> MicrosandboxResult<Vec<Self::Blocker>>;
    fn blocker_name(blocker: &Self::Blocker) -> &str;
    async fn stop(&mut self, blocker: &Self::Blocker) -> MicrosandboxResult<()>;
    async fn repair(
        &mut self,
        name: &str,
        maintenance: bool,
    ) -> MicrosandboxResult<StorageRecovery>;
}

trait Interaction {
    fn confirm(
        &mut self,
        title: &str,
        context: &[String],
        question: &str,
    ) -> io::Result<Option<bool>>;
    fn clear(&mut self) -> io::Result<()>;
}

struct LocalOperations;

#[derive(Clone, Default)]
struct Cancellation(Arc<AtomicBool>);

/// Own only this CLI command's listener. No handler is installed by the SDK or repair engine.
struct Interrupts {
    cancellation: Cancellation,
    listener: tokio::task::JoinHandle<()>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Entry {
    fn inspected(item: StorageSandboxDiagnosis) -> Self {
        let outcome = classify(&item);
        Self {
            name: item.name.clone(),
            inspection_unavailable: item.status == StorageDiagnosticStatus::Unavailable,
            diagnosis: Some(item),
            outcome,
            actions: Actions::default(),
            stopped: Vec::new(),
        }
    }

    fn unavailable(name: String, error: &MicrosandboxError) -> Self {
        Self {
            name,
            diagnosis: None,
            outcome: Outcome::Investigation(Failure::from_error(error)),
            actions: Actions::default(),
            stopped: Vec::new(),
            inspection_unavailable: true,
        }
    }

    fn update(&mut self, item: StorageSandboxDiagnosis) {
        self.outcome = classify(&item);
        self.inspection_unavailable = item.status == StorageDiagnosticStatus::Unavailable;
        self.diagnosis = Some(item);
    }

    fn blocker_check_failed(&mut self, error: &MicrosandboxError) {
        // Discovery is supplementary: an unusable active-state record can also prevent
        // identifying related writers. Keep the specific storage diagnosis in that case,
        // rather than replacing it with the later probe's generic refusal. Neither permits
        // a stop or repair; pending or unclassified entries still report the probe failure.
        if matches!(self.outcome, Outcome::Investigation(failure) if failure != Failure::Unclassified)
        {
            return;
        }
        self.inspection_unavailable = true;
        self.outcome = Outcome::Investigation(Failure::from_error(error));
    }
}

impl Cancellation {
    fn request(&self) {
        self.0.store(true, Ordering::Release);
    }

    fn requested(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    async fn checkpoint(&self) -> bool {
        // A capture can synchronously block its polling thread. Let the independently
        // registered listener run before starting another operation or reading a prompt.
        tokio::task::yield_now().await;
        self.requested()
    }
}

impl Interrupts {
    fn install() -> io::Result<Self> {
        // Register synchronously, before the first SDK await. Polling ctrl_c() only in a
        // select beside migration would miss its initial synchronous block_in_place work.
        #[cfg(unix)]
        let mut signals =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
        #[cfg(windows)]
        let mut signals = tokio::signal::windows::ctrl_c()?;
        let cancellation = Cancellation::default();
        let requested = cancellation.clone();
        let listener = tokio::spawn(async move {
            while signals.recv().await.is_some() {
                // Repeated interrupts remain requests; never abort an admitted import.
                requested.request();
            }
        });
        Ok(Self {
            cancellation,
            listener,
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Operations for LocalOperations {
    type Blocker = StorageRepairBlocker;

    async fn inspect(&mut self, name: &str) -> MicrosandboxResult<StorageSandboxDiagnosis> {
        setup::diagnose_storage(
            Default::default(),
            StorageSelection::Named(vec![name.into()]),
        )
        .await?
        .sandboxes
        .into_iter()
        .next()
        .ok_or_else(|| MicrosandboxError::SandboxNotFound(name.into()))
    }

    async fn blockers(&mut self, name: &str) -> MicrosandboxResult<Vec<Self::Blocker>> {
        setup::storage_repair_blockers(Default::default(), name).await
    }

    fn blocker_name(blocker: &Self::Blocker) -> &str {
        &blocker.name
    }

    async fn stop(&mut self, blocker: &Self::Blocker) -> MicrosandboxResult<()> {
        Sandbox::stop_storage_repair_blocker(blocker).await
    }

    async fn repair(
        &mut self,
        name: &str,
        maintenance: bool,
    ) -> MicrosandboxResult<StorageRecovery> {
        // Empty selections preserve the existing validated state. The shared engine still
        // reacquires lifecycle ownership and excludes related writers for every target.
        Sandbox::recover_storage(
            name,
            StorageRecoveryOptions {
                legacy_writers_stopped: maintenance,
                ..Default::default()
            },
        )
        .await
    }
}

impl Interaction for Screen {
    fn confirm(
        &mut self,
        title: &str,
        context: &[String],
        question: &str,
    ) -> io::Result<Option<bool>> {
        self.confirm_choice(title, context, question)
    }

    fn clear(&mut self) -> io::Result<()> {
        Screen::clear(self)
    }
}

impl Drop for Interrupts {
    fn drop(&mut self) {
        self.listener.abort();
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) async fn run(args: RepairArgs) -> anyhow::Result<()> {
    let mut screen = Screen::new()?;
    let interrupts = Interrupts::install().map_err(|error| {
        anyhow::anyhow!(
            "could not register repair interrupt handling; no repairs were performed: {error}"
        )
    })?;
    let cancellation = &interrupts.cancellation;
    let names = if let Some(name) = args.name {
        vec![name]
    } else {
        // This inventory belongs to an explicitly requested picker, never ordinary startup.
        let inspected = setup::diagnose_storage(Default::default(), StorageSelection::All).await;
        if cancellation.checkpoint().await {
            return finish(&mut screen, &[], true);
        }
        let inventory = match inspected {
            Ok(report) => report.sandboxes,
            Err(error) => {
                let entries = vec![Entry::unavailable("selected home".into(), &error)];
                review_results(&mut screen, &entries)?;
                return finish(&mut screen, &entries, false);
            }
        };
        if inventory.is_empty() {
            screen.finish()?;
            println!("There are no local sandboxes to repair.");
            return Ok(());
        }
        let targets = inventory
            .iter()
            .map(|item| Target {
                name: item.name.clone(),
                status: inspection_label(item).into(),
                ready: item.status == StorageDiagnosticStatus::Ready,
            })
            .collect::<Vec<_>>();
        let Some(indices) = screen.choose_targets(&targets)? else {
            screen.finish()?;
            println!("Repair cancelled. No repairs were performed.");
            return Err(StorageDoctorExit { code: 2 }.into());
        };
        if indices.is_empty() {
            screen.finish()?;
            println!("No sandboxes selected. No repairs were performed.");
            return Ok(());
        }
        indices
            .into_iter()
            .map(|index| targets[index].name.clone())
            .collect()
    };

    // The picker is provisional. Inspect the exact accepted set again before offering repairs.
    let mut entries =
        match setup::diagnose_storage(Default::default(), StorageSelection::Named(names.clone()))
            .await
        {
            Ok(report) => report
                .sandboxes
                .into_iter()
                .map(Entry::inspected)
                .collect::<Vec<_>>(),
            Err(error) => names
                .into_iter()
                .map(|name| Entry::unavailable(name, &error))
                .collect(),
        };
    let mut operations = LocalOperations;
    if cancellation.checkpoint().await {
        cancel_pending(&mut entries);
        return finish(&mut screen, &entries, true);
    }
    discover_blockers(&mut entries, &mut operations, cancellation).await;
    if cancellation.checkpoint().await {
        cancel_pending(&mut entries);
        return finish(&mut screen, &entries, true);
    }
    if entries
        .iter()
        .any(|entry| entry.outcome == Outcome::Pending)
    {
        let mut context = summary(&entries);
        context.push(String::new());
        context.push("Repair supported storage using its existing saved state. Original disk files are retained.".into());
        context
            .push("Sandboxes stay stopped. Any required shutdown needs separate consent.".into());
        context.push(
            "Ctrl-C waits for an active operation to finish, then cancels remaining repairs."
                .into(),
        );
        if screen.confirm_choice(
            "Confirm storage repairs",
            &context,
            "Repair the supported sandboxes?",
        )? != Some(true)
        {
            cancel_pending(&mut entries);
            return finish(&mut screen, &entries, true);
        }
        let result = process_batch(
            &mut entries,
            &mut operations,
            &mut screen,
            cfg!(target_os = "macos"),
            cancellation,
        )
        .await;
        match result {
            Ok(true) => return finish(&mut screen, &entries, true),
            Ok(false) => {}
            Err(error) => {
                // A terminal failure cannot erase earlier successful shutdowns or imports.
                cancel_pending(&mut entries);
                let _ = screen.finish();
                print_summary(&entries, true);
                return Err(error.into());
            }
        }
    }
    if let Err(error) = review_results(&mut screen, &entries) {
        let _ = screen.finish();
        print_summary(&entries, false);
        return Err(error.into());
    }
    finish(&mut screen, &entries, false)
}

/// Stops are consented and completed before the maintenance attestation and any disk import.
async fn process_batch<B: Operations, U: Interaction>(
    entries: &mut [Entry],
    backend: &mut B,
    ui: &mut U,
    needs_maintenance: bool,
    cancellation: &Cancellation,
) -> io::Result<bool> {
    for index in 0..entries.len() {
        if cancellation.checkpoint().await {
            cancel_pending(entries);
            return Ok(true);
        }
        if entries[index].outcome == Outcome::Pending
            && prepare(&mut entries[index], backend, ui, cancellation).await?
        {
            cancel_pending(entries);
            return Ok(true);
        }
    }
    if cancellation.checkpoint().await {
        cancel_pending(entries);
        return Ok(true);
    }
    // Every batch obtains its own consent in this terminal; no argument can pre-authorize it.
    let mut maintenance_confirmed = false;
    if needs_maintenance
        && entries
            .iter()
            .any(|entry| entry.outcome == Outcome::Pending)
    {
        let context = vec![
            "Stop legacy VMs across all microsandbox homes and prevent old tools or other writers from changing these disks until repair finishes.".into(),
            "New and already migrated sandboxes may keep running. This command cannot establish safety across other homes.".into(),
        ];
        match ui.confirm(
            "macOS maintenance confirmation",
            &context,
            "Have you stopped legacy VMs and excluded new writers?",
        )? {
            Some(true) => maintenance_confirmed = true,
            Some(false) => {
                for entry in entries
                    .iter_mut()
                    .filter(|entry| entry.outcome == Outcome::Pending)
                {
                    entry.outcome = Outcome::Skipped("maintenance not confirmed");
                }
            }
            None => {
                cancel_pending(entries);
                return Ok(true);
            }
        }
    }
    for index in 0..entries.len() {
        if cancellation.checkpoint().await {
            cancel_pending(entries);
            return Ok(true);
        }
        let entry = &mut entries[index];
        if entry.outcome != Outcome::Pending {
            continue;
        }
        ui.clear()?;
        entry.actions.repair_attempted = true;
        match backend.repair(&entry.name, maintenance_confirmed).await {
            Ok(_) => {
                entry.actions.repaired = true;
                entry.outcome = Outcome::Repaired;
            }
            Err(error) => entry.outcome = Outcome::Investigation(Failure::from_error(&error)),
        }
        // A failure concerns this target. The next target must establish its own writer
        // exclusions and dependencies; a selected batch is never treated as one trust group.
    }
    // Keep a completed final action visible even if interruption arrived during that action.
    Ok(cancellation.checkpoint().await)
}

async fn prepare<B: Operations, U: Interaction>(
    entry: &mut Entry,
    backend: &mut B,
    ui: &mut U,
    cancellation: &Cancellation,
) -> io::Result<bool> {
    loop {
        if cancellation.checkpoint().await {
            return Ok(true);
        }
        ui.clear()?;
        match backend.inspect(&entry.name).await {
            Ok(item) => entry.update(item),
            Err(error) => {
                entry.inspection_unavailable = true;
                entry.outcome = Outcome::Investigation(Failure::from_error(&error));
                return Ok(false);
            }
        }
        if entry.outcome != Outcome::Pending
            && !entry.diagnosis.as_ref().is_some_and(may_check_blockers)
        {
            return Ok(false);
        }
        if cancellation.checkpoint().await {
            return Ok(true);
        }
        let blockers = match backend.blockers(&entry.name).await {
            Ok(blockers) => blockers,
            Err(error) => {
                entry.blocker_check_failed(&error);
                return Ok(false);
            }
        };
        if cancellation.checkpoint().await {
            return Ok(true);
        }
        let Some(blocker) = blockers.first() else {
            if entry.diagnosis.as_ref().is_some_and(|item| item.running) {
                entry.outcome = Outcome::Investigation(Failure::WriterProtection);
            }
            return Ok(false);
        };
        let name = B::blocker_name(blocker).to_owned();
        let context = vec![
            format!("Storage checks for '{}' require '{name}' to be stopped.", entry.name),
            "Stopping a VM can upgrade this home's catalog. Older tools may then refuse to open it.".into(),
            "Only a graceful shutdown will be requested.".into(),
        ];
        match ui.confirm(
            "Stop required for repair",
            &context,
            &format!("Stop '{name}' gracefully?"),
        )? {
            Some(true) => {}
            Some(false) => {
                entry.outcome = Outcome::Skipped("stop declined");
                return Ok(false);
            }
            None => return Ok(true),
        }
        if cancellation.checkpoint().await {
            return Ok(true);
        }
        ui.clear()?;
        entry.actions.stop_attempted = true;
        match backend.stop(blocker).await {
            Ok(()) => {
                entry.actions.stopped += 1;
                entry.stopped.push(name);
            }
            Err(error) => {
                entry.outcome = Outcome::Investigation(Failure::from_error(&error));
                return Ok(false);
            }
        }
        // A consent token describes one observed run only. Obtain new state and blockers
        // after each completed stop instead of applying the token to a later generation.
    }
}

/// A stopped target may share selected storage with a running peer. Its diagnosis then
/// reports recovery-required even though stopping that verified peer can make it eligible.
/// Discover this before presenting the batch, and reacquire the actual tokens before consent.
async fn discover_blockers<B: Operations>(
    entries: &mut [Entry],
    backend: &mut B,
    cancellation: &Cancellation,
) {
    for entry in entries.iter_mut().filter(|entry| {
        matches!(entry.outcome, Outcome::Investigation(_))
            && entry.diagnosis.as_ref().is_some_and(may_check_blockers)
    }) {
        if cancellation.checkpoint().await {
            return;
        }
        match backend.blockers(&entry.name).await {
            Ok(blockers) if !blockers.is_empty() => entry.outcome = Outcome::Pending,
            Ok(_) => {}
            Err(error) => entry.blocker_check_failed(&error),
        }
    }
}

fn may_check_blockers(item: &StorageSandboxDiagnosis) -> bool {
    item.status != StorageDiagnosticStatus::Ready
        && matches!(
            item.reason,
            None | Some(StorageDiagnosticReason::StorageUnavailable)
        )
}

fn classify(item: &StorageSandboxDiagnosis) -> Outcome {
    if item.status == StorageDiagnosticStatus::Ready {
        return Outcome::AlreadyReady;
    }
    if item
        .reason
        .is_some_and(|reason| reason != StorageDiagnosticReason::StorageUnavailable)
    {
        return Outcome::Investigation(Failure::from_diagnosis(item));
    }
    // A running Windows VM can exclude read-only discovery. Offer a verified graceful
    // stop and repeat inspection; do not interpret this provisional result as damage.
    if item.running
        && (item.status != StorageDiagnosticStatus::Unavailable
            || item.reason == Some(StorageDiagnosticReason::StorageUnavailable))
    {
        return Outcome::Pending;
    }
    match item.status {
        StorageDiagnosticStatus::Eligible
        | StorageDiagnosticStatus::MaintenanceRequired
        | StorageDiagnosticStatus::InProgress => Outcome::Pending,
        _ => Outcome::Investigation(Failure::from_diagnosis(item)),
    }
}

fn inspection_label(item: &StorageSandboxDiagnosis) -> &'static str {
    if item.status == StorageDiagnosticStatus::Ready {
        return "ready";
    }
    if item.running && classify(item) == Outcome::Pending {
        return "running; inspection may require a stop";
    }
    match item.status {
        StorageDiagnosticStatus::Eligible => "ready to repair",
        StorageDiagnosticStatus::MaintenanceRequired => "maintenance required",
        StorageDiagnosticStatus::InProgress => "upgrade can resume",
        _ => "needs investigation",
    }
}

fn cancel_pending(entries: &mut [Entry]) {
    for entry in entries
        .iter_mut()
        .filter(|entry| entry.outcome == Outcome::Pending)
    {
        entry.outcome = Outcome::Cancelled;
    }
}

fn summary(entries: &[Entry]) -> Vec<String> {
    entries
        .iter()
        .map(|entry| {
            let status = match entry.outcome {
                Outcome::Pending => entry
                    .diagnosis
                    .as_ref()
                    .map(|item| {
                        if classify(item) != Outcome::Pending {
                            "inspection requires a related VM to stop"
                        } else {
                            inspection_label(item)
                        }
                    })
                    .unwrap_or("inspection pending"),
                Outcome::AlreadyReady => "already ready",
                Outcome::Repaired => "repaired; ready to start",
                Outcome::Investigation(_) => "needs investigation",
                Outcome::Skipped(reason) => reason,
                Outcome::Cancelled => "cancelled; repair not attempted",
            };
            let mut line = format!("{}: {status}", terminal_text(&entry.name));
            if !entry.stopped.is_empty() {
                line.push_str(&format!(
                    "; stopped {}",
                    entry
                        .stopped
                        .iter()
                        .map(|name| terminal_text(name))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            } else if entry.actions.stop_attempted {
                line.push_str("; stop attempted, completion not confirmed");
            }
            if entry.actions.repair_attempted && !entry.actions.repaired {
                line.push_str("; repair attempted, keep recovery records");
            }
            line
        })
        .collect()
}

fn review_results(screen: &mut Screen, entries: &[Entry]) -> io::Result<()> {
    let unresolved: Vec<_> = entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| matches!(entry.outcome, Outcome::Investigation(_)))
        .map(|(index, _)| index)
        .collect();
    if unresolved.is_empty() {
        return Ok(());
    }
    let runtime = RuntimeVersion::inspect();
    // A named unresolved repair opens directly on its explanation, then returns to results.
    if entries.len() == 1 {
        review_failure(screen, entries, unresolved[0], &runtime)?;
    }
    loop {
        let mut labels: Vec<_> = unresolved
            .iter()
            .map(|&index| format!("Investigate '{}'", entries[index].name))
            .collect();
        labels.push("Finish".into());
        let choices = labels.iter().map(String::as_str).collect::<Vec<_>>();
        let Some(choice) = screen.choose_action("Repair results", &summary(entries), &choices)?
        else {
            return Ok(());
        };
        let Some(&index) = unresolved.get(choice) else {
            return Ok(());
        };
        review_failure(screen, entries, index, &runtime)?;
    }
}

fn review_failure(
    screen: &mut Screen,
    entries: &[Entry],
    index: usize,
    runtime: &RuntimeVersion,
) -> io::Result<()> {
    let entry = &entries[index];
    let Outcome::Investigation(failure) = entry.outcome else {
        return Ok(());
    };
    let actions = report_actions(entries, index);
    let context = vec![
        failure.message().into(),
        String::new(),
        report::preservation(actions, failure).into(),
        String::new(),
        "Please report this to the microsandbox maintainers.".into(),
    ];
    let choice = screen.choose_action(
        &format!("Couldn't safely repair '{}'.", entry.name),
        &context,
        &["Review diagnostic report", "Back to results"],
    )?;
    if choice != Some(0) {
        return Ok(());
    }
    let text = report::render(entry.diagnosis.as_ref(), failure, actions, runtime);
    let lines = text.lines().map(str::to_owned).collect::<Vec<_>>();
    if screen.choose_action(
        "Review diagnostic report",
        &lines,
        &["Print report for copying", "Back to results"],
    )? == Some(0)
    {
        // This explicitly requested output stays in terminal history. The next screen owns
        // only its subsequently written rows; neither a browser nor clipboard is accessed.
        screen.finish()?;
        println!("\n{text}");
    }
    Ok(())
}

fn report_actions(entries: &[Entry], index: usize) -> Actions {
    Actions {
        other_actions_attempted: entries.iter().enumerate().any(|(other, entry)| {
            other != index && (entry.actions.stop_attempted || entry.actions.repair_attempted)
        }),
        ..entries[index].actions
    }
}

fn print_summary(entries: &[Entry], cancelled: bool) {
    println!(
        "{}",
        if cancelled {
            "Repair cancelled. Results:"
        } else {
            "Repair results:"
        }
    );
    for line in summary(entries) {
        println!("  {line}");
    }
    if entries
        .iter()
        .any(|entry| entry.actions.stop_attempted || entry.actions.repair_attempted)
    {
        println!("The shared catalog may have been updated. Completed actions were not undone.");
    }
    if entries.iter().any(|entry| entry.actions.repaired) {
        println!("Repaired sandboxes remain stopped; start them when ready.");
    }
}

fn finish(screen: &mut Screen, entries: &[Entry], cancelled: bool) -> anyhow::Result<()> {
    screen.finish()?;
    print_summary(entries, cancelled);
    let code = if cancelled {
        2
    } else if entries.iter().any(|entry| {
        entry.inspection_unavailable && matches!(entry.outcome, Outcome::Investigation(_))
    }) {
        3
    } else if entries
        .iter()
        .any(|entry| !matches!(entry.outcome, Outcome::AlreadyReady | Outcome::Repaired))
    {
        2
    } else {
        0
    };
    if code == 0 {
        Ok(())
    } else {
        Err(StorageDoctorExit { code }.into())
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};

    use super::*;

    struct FakeState {
        status: StorageDiagnosticStatus,
        running: bool,
        stale_stop: bool,
        blocked_by: Option<String>,
        repair_fails: bool,
    }

    struct FakeOperations {
        states: BTreeMap<String, FakeState>,
        repaired: Vec<String>,
        maintenance_confirmed: Vec<bool>,
        stops: Vec<String>,
        cancel_during_stop: Option<Cancellation>,
        cancel_during_repair: Option<Cancellation>,
        blocker_error: Option<String>,
    }

    struct Answers(VecDeque<Option<bool>>);

    impl Interaction for Answers {
        fn confirm(&mut self, _: &str, _: &[String], _: &str) -> io::Result<Option<bool>> {
            Ok(self.0.pop_front().expect("unexpected confirmation"))
        }
        fn clear(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Operations for FakeOperations {
        type Blocker = String;
        async fn inspect(&mut self, name: &str) -> MicrosandboxResult<StorageSandboxDiagnosis> {
            let state = &self.states[name];
            Ok(diagnosis(name, state.status, state.running))
        }
        async fn blockers(&mut self, name: &str) -> MicrosandboxResult<Vec<String>> {
            if let Some(error) = &self.blocker_error {
                return Err(MicrosandboxError::Custom(error.clone()));
            }
            Ok(if self.states[name].running {
                vec![name.into()]
            } else if let Some(peer) = &self.states[name].blocked_by {
                if self.states[peer].running {
                    vec![peer.clone()]
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            })
        }
        fn blocker_name(blocker: &String) -> &str {
            blocker
        }
        async fn stop(&mut self, name: &String) -> MicrosandboxResult<()> {
            if let Some(cancellation) = self.cancel_during_stop.take() {
                cancellation.request();
                tokio::task::yield_now().await;
            }
            let state = self.states.get_mut(name).unwrap();
            if state.stale_stop {
                return Err(MicrosandboxError::Runtime(
                    "the selected blocker changed; inspect storage again".into(),
                ));
            }
            state.running = false;
            for state in self
                .states
                .values_mut()
                .filter(|state| state.blocked_by.as_ref() == Some(name))
            {
                state.status = StorageDiagnosticStatus::Eligible;
            }
            self.stops.push(name.clone());
            Ok(())
        }
        async fn repair(
            &mut self,
            name: &str,
            maintenance: bool,
        ) -> MicrosandboxResult<StorageRecovery> {
            if let Some(cancellation) = self.cancel_during_repair.take() {
                cancellation.request();
                tokio::task::yield_now().await;
            }
            assert!(
                !self.states[name].running,
                "must never repair a running target"
            );
            assert_ne!(
                self.states[name].status,
                StorageDiagnosticStatus::RecoveryRequired
            );
            if self.states[name].repair_fails {
                return Err(MicrosandboxError::Runtime(
                    "recorded migration source changed".into(),
                ));
            }
            self.repaired.push(name.into());
            self.maintenance_confirmed.push(maintenance);
            Ok(StorageRecovery {
                name: name.into(),
                ready: true,
                originals_retained: true,
            })
        }
    }

    fn diagnosis(
        name: &str,
        status: StorageDiagnosticStatus,
        running: bool,
    ) -> StorageSandboxDiagnosis {
        StorageSandboxDiagnosis {
            name: name.into(),
            guest_mounts: BTreeMap::new(),
            status,
            running,
            protection_registered: false,
            reason: None,
            inspection: None,
        }
    }

    fn fixtures(states: &[(&str, StorageDiagnosticStatus, bool)]) -> (Vec<Entry>, FakeOperations) {
        (
            states
                .iter()
                .map(|&(name, status, running)| Entry::inspected(diagnosis(name, status, running)))
                .collect(),
            FakeOperations {
                states: states
                    .iter()
                    .map(|&(name, status, running)| {
                        (
                            name.into(),
                            FakeState {
                                status,
                                running,
                                stale_stop: false,
                                blocked_by: None,
                                repair_fails: false,
                            },
                        )
                    })
                    .collect(),
                repaired: Vec::new(),
                maintenance_confirmed: Vec::new(),
                stops: Vec::new(),
                cancel_during_stop: None,
                cancel_during_repair: None,
                blocker_error: None,
            },
        )
    }

    #[tokio::test]
    async fn failed_blocker_discovery_preserves_specific_storage_diagnosis() {
        for failure in [Failure::SelectionUnknown, Failure::Unclassified] {
            let (mut entries, mut backend) =
                fixtures(&[("unknown", StorageDiagnosticStatus::RecoveryRequired, false)]);
            entries[0].outcome = Outcome::Investigation(failure);
            backend.blocker_error = Some("cannot establish host authority".into());

            discover_blockers(&mut entries, &mut backend, &Cancellation::default()).await;

            let expected = if failure == Failure::Unclassified {
                Failure::Permissions
            } else {
                failure
            };
            assert_eq!(entries[0].outcome, Outcome::Investigation(expected));
            assert_eq!(
                entries[0].inspection_unavailable,
                failure == Failure::Unclassified
            );
            assert!(backend.stops.is_empty());
            assert!(backend.repaired.is_empty());
        }
    }

    #[tokio::test]
    async fn mixed_batch_repairs_supported_storage_without_selecting_unresolved_views() {
        let (mut entries, mut backend) = fixtures(&[
            ("unknown", StorageDiagnosticStatus::RecoveryRequired, false),
            ("app", StorageDiagnosticStatus::Eligible, false),
            ("worker", StorageDiagnosticStatus::InProgress, false),
            ("ready", StorageDiagnosticStatus::Ready, false),
        ]);
        assert!(
            !process_batch(
                &mut entries,
                &mut backend,
                &mut Answers(VecDeque::new()),
                false,
                &Cancellation::default(),
            )
            .await
            .unwrap()
        );
        assert_eq!(backend.repaired, ["app", "worker"]);
        assert!(matches!(entries[0].outcome, Outcome::Investigation(_)));
        assert_eq!(entries[1].outcome, Outcome::Repaired);
        assert_eq!(entries[2].outcome, Outcome::Repaired);
        assert_eq!(entries[3].outcome, Outcome::AlreadyReady);
        assert!(report_actions(&entries, 0).other_actions_attempted);
        assert!(
            !report::preservation(report_actions(&entries, 0), Failure::Unclassified)
                .contains("left unchanged")
        );
    }

    #[tokio::test]
    async fn stopped_target_can_stop_a_verified_peer_then_reinspect_before_repair() {
        for accepted in [true, false] {
            let (mut entries, mut backend) = fixtures(&[
                ("target", StorageDiagnosticStatus::RecoveryRequired, false),
                ("independent", StorageDiagnosticStatus::Eligible, false),
            ]);
            backend.states.get_mut("target").unwrap().blocked_by = Some("peer".into());
            backend.states.insert(
                "peer".into(),
                FakeState {
                    status: StorageDiagnosticStatus::Eligible,
                    running: true,
                    stale_stop: false,
                    blocked_by: None,
                    repair_fails: false,
                },
            );
            discover_blockers(&mut entries, &mut backend, &Cancellation::default()).await;
            assert_eq!(entries[0].outcome, Outcome::Pending);
            assert!(summary(&entries)[0].contains("related VM"));
            let mut answers = Answers(VecDeque::from([Some(accepted)]));
            assert!(
                !process_batch(
                    &mut entries,
                    &mut backend,
                    &mut answers,
                    false,
                    &Cancellation::default()
                )
                .await
                .unwrap()
            );
            assert_eq!(backend.states["peer"].running, !accepted);
            if accepted {
                assert_eq!(backend.stops, ["peer"]);
                assert_eq!(backend.repaired, ["target", "independent"]);
                assert_eq!(entries[0].outcome, Outcome::Repaired);
                assert_eq!(entries[0].stopped, ["peer"]);
            } else {
                assert_eq!(backend.repaired, ["independent"]);
                assert_eq!(entries[0].outcome, Outcome::Skipped("stop declined"));
            }
        }
    }

    #[tokio::test]
    async fn repair_failure_records_possible_progress_and_continues_independent_targets() {
        let (mut entries, mut backend) = fixtures(&[
            ("changed", StorageDiagnosticStatus::Eligible, false),
            ("app", StorageDiagnosticStatus::Eligible, false),
        ]);
        backend.states.get_mut("changed").unwrap().repair_fails = true;
        assert!(
            !process_batch(
                &mut entries,
                &mut backend,
                &mut Answers(VecDeque::new()),
                false,
                &Cancellation::default(),
            )
            .await
            .unwrap()
        );
        assert_eq!(backend.repaired, ["app"]);
        assert_eq!(
            entries[0].outcome,
            Outcome::Investigation(Failure::StaleOperation)
        );
        assert!(entries[0].actions.repair_attempted);
        assert!(!entries[0].actions.repaired);
        assert!(summary(&entries)[0].contains("keep recovery records"));
        assert!(
            report::preservation(report_actions(&entries, 0), Failure::StaleOperation)
                .contains("may have recorded migration")
        );
    }

    #[tokio::test]
    async fn declined_stop_skips_that_target_and_keeps_independent_repairs() {
        let (mut entries, mut backend) = fixtures(&[
            ("api", StorageDiagnosticStatus::Eligible, true),
            ("app", StorageDiagnosticStatus::Eligible, false),
        ]);
        let mut answers = Answers(VecDeque::from([Some(false)]));
        assert!(
            !process_batch(
                &mut entries,
                &mut backend,
                &mut answers,
                false,
                &Cancellation::default()
            )
            .await
            .unwrap()
        );
        assert!(backend.states["api"].running);
        assert!(backend.stops.is_empty());
        assert_eq!(backend.repaired, ["app"]);
        assert_eq!(entries[0].outcome, Outcome::Skipped("stop declined"));
    }

    #[tokio::test]
    async fn stale_stop_never_retries_consent_on_a_replacement_vm() {
        let (mut entries, mut backend) = fixtures(&[
            ("api", StorageDiagnosticStatus::Eligible, true),
            ("app", StorageDiagnosticStatus::Eligible, false),
        ]);
        backend.states.get_mut("api").unwrap().stale_stop = true;
        let mut answers = Answers(VecDeque::from([Some(true)]));
        assert!(
            !process_batch(
                &mut entries,
                &mut backend,
                &mut answers,
                false,
                &Cancellation::default()
            )
            .await
            .unwrap()
        );
        assert!(backend.states["api"].running);
        assert!(backend.stops.is_empty());
        assert_eq!(backend.repaired, ["app"]);
        assert!(entries[0].actions.stop_attempted);
        assert_eq!(
            entries[0].outcome,
            Outcome::Investigation(Failure::StaleOperation)
        );
    }

    #[tokio::test]
    async fn cancellation_keeps_completed_stops_visible_and_does_not_apply_repairs() {
        let (mut entries, mut backend) = fixtures(&[
            ("api", StorageDiagnosticStatus::Eligible, true),
            ("worker", StorageDiagnosticStatus::Eligible, true),
        ]);
        let mut answers = Answers(VecDeque::from([Some(true), None]));
        assert!(
            process_batch(
                &mut entries,
                &mut backend,
                &mut answers,
                false,
                &Cancellation::default()
            )
            .await
            .unwrap()
        );
        assert_eq!(backend.stops, ["api"]);
        assert!(!backend.states["api"].running);
        assert!(backend.states["worker"].running);
        assert!(backend.repaired.is_empty());
        assert!(summary(&entries)[0].contains("stopped api"));
        assert_eq!(entries[0].outcome, Outcome::Cancelled);
    }

    #[tokio::test]
    async fn interrupt_during_repair_finishes_that_import_before_cancelling_the_batch() {
        let (mut entries, mut backend) = fixtures(&[
            ("app", StorageDiagnosticStatus::Eligible, false),
            ("next", StorageDiagnosticStatus::Eligible, false),
        ]);
        let cancellation = Cancellation::default();
        backend.cancel_during_repair = Some(cancellation.clone());
        assert!(
            process_batch(
                &mut entries,
                &mut backend,
                &mut Answers(VecDeque::new()),
                false,
                &cancellation,
            )
            .await
            .unwrap()
        );
        assert_eq!(backend.repaired, ["app"]);
        assert_eq!(entries[0].outcome, Outcome::Repaired);
        assert!(entries[0].actions.repaired);
        assert_eq!(entries[1].outcome, Outcome::Cancelled);
        assert!(!entries[1].actions.repair_attempted);
        assert!(summary(&entries)[0].contains("repaired; ready to start"));
    }

    #[tokio::test]
    async fn interrupt_during_stop_waits_for_its_result_and_never_starts_repair() {
        let (mut entries, mut backend) = fixtures(&[
            ("api", StorageDiagnosticStatus::Eligible, true),
            ("next", StorageDiagnosticStatus::Eligible, false),
        ]);
        let cancellation = Cancellation::default();
        backend.cancel_during_stop = Some(cancellation.clone());
        let mut answers = Answers(VecDeque::from([Some(true)]));
        assert!(
            process_batch(
                &mut entries,
                &mut backend,
                &mut answers,
                false,
                &cancellation,
            )
            .await
            .unwrap()
        );
        assert_eq!(backend.stops, ["api"]);
        assert!(!backend.states["api"].running);
        assert_eq!(entries[0].actions.stopped, 1);
        assert!(backend.repaired.is_empty());
        assert!(
            entries
                .iter()
                .all(|entry| entry.outcome == Outcome::Cancelled)
        );
        assert!(summary(&entries)[0].contains("stopped api"));
    }

    #[tokio::test]
    async fn maintenance_is_explicit_and_does_not_apply_to_ready_storage() {
        let (mut entries, mut backend) =
            fixtures(&[("ready", StorageDiagnosticStatus::Ready, false)]);
        assert!(
            !process_batch(
                &mut entries,
                &mut backend,
                &mut Answers(VecDeque::new()),
                true,
                &Cancellation::default(),
            )
            .await
            .unwrap()
        );
        assert!(backend.repaired.is_empty());

        for answer in [Some(true), Some(false), None] {
            let (mut entries, mut backend) =
                fixtures(&[("old", StorageDiagnosticStatus::MaintenanceRequired, false)]);
            let mut answers = Answers(VecDeque::from([answer]));

            let cancelled = process_batch(
                &mut entries,
                &mut backend,
                &mut answers,
                true,
                &Cancellation::default(),
            )
            .await
            .unwrap();

            assert_eq!(cancelled, answer.is_none());
            assert!(answers.0.is_empty(), "must ask for maintenance consent");
            if answer == Some(true) {
                assert_eq!(backend.repaired, ["old"]);
                assert_eq!(backend.maintenance_confirmed, [true]);
                assert_eq!(entries[0].outcome, Outcome::Repaired);
            } else {
                assert!(backend.repaired.is_empty());
                assert!(backend.maintenance_confirmed.is_empty());
                assert_eq!(
                    entries[0].outcome,
                    if answer.is_none() {
                        Outcome::Cancelled
                    } else {
                        Outcome::Skipped("maintenance not confirmed")
                    }
                );
            }
        }
    }
}
