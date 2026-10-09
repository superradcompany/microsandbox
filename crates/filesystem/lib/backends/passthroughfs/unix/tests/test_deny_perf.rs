//! Micro benchmarks for bind-mount deny-list overhead.
//!
//! The deny check runs in the host-side passthrough backend, not in the guest
//! VM, so it can be measured directly against an in-process [`PassthroughFs`]
//! without booting a sandbox.
//!
//! To keep the comparison fair, **one directory tree is created once** and
//! reused by every scenario, and the whole tree is warmed before measuring so
//! the first scenario does not inherit the cold caches left by tree creation.
//! Every scenario is measured against a **deny-free baseline on the same tree,
//! interleaved within each round** — each pair is timed in both orders and the
//! ratios/deltas are averaged, so machine-state drift and first/second-measurement
//! bias cancel out.
//!
//! # How to run
//!
//! This is deliberately **not** a correctness test (it makes no assertions and
//! only prints tables), so it is `#[ignore]`d and does not run in normal `cargo
//! test` invocations. It is Unix-only (it drives the Unix `PassthroughFs`); the
//! Windows backend has no in-process harness here and is not covered.
//!
//! Use a **release** build for representative steady-state numbers (debug builds
//! inflate the relative cost of string/path handling and overstate overhead).
//! The recommended entry point is the variance wrapper, which runs the
//! measurement several times (default 10, override with `RUNS`) and reports the
//! spread between runs so noisy metrics are easy to spot:
//!
//! ```bash
//! cargo test --release -p microsandbox-filesystem --lib \
//!     -- --ignored deny_pattern_kind_perf_variance --nocapture
//! RUNS=20 cargo test --release -p microsandbox-filesystem --lib \
//!     -- --ignored deny_pattern_kind_perf_variance --nocapture
//! ```
//!
//! A single-run table is also available for a quick look without the run-to-run
//! aggregate:
//!
//! ```bash
//! cargo test --release -p microsandbox-filesystem --lib \
//!     -- --ignored deny_pattern_kind_perf_comparison --nocapture
//! ```
//!
//! # What it measures
//!
//! - `pass lookup/op`: a single `lookup` of a name that *passes* the deny
//!   check (the common case; a passing lookup still pays the full deny check).
//! - `deny lookup/op`: a single `lookup` of a name the deny list hides, which
//!   returns `ENOENT` and short-circuits before the underlying file is opened.
//!   This isolates the cost of the deny check itself. Absent for the baseline.
//! - `readdir pass`: a full listing of `data`, whose entries are mostly *not*
//!   denied (the normal case; the deny check runs but rarely matches).
//! - `readdir deny`: a full listing of a dedicated deny-heavy directory whose
//!   entries are mostly *denied* (the "hide a subtree" case).
//!
//! The baseline `deny` cases are skipped, since they are not sensible; the
//! baseline does not have a deny list.
//!
//! A single `readdir` call always blends passing and denied entries — unlike a
//! `lookup`, which is pass-or-deny — so `readdir` is reported at two deny
//! *densities* rather than a binary split. Dir-only patterns match a single
//! literal name, so no deny-heavy directory is a natural case for them; their
//! `readdir` cost is the per-entry `is_dir` determination, which `readdir pass`
//! already captures. They are skipped for `readdir deny`.
//!
//! The `x` columns in the single-run output are the ratio to the shared
//! deny-free baseline (`deny lookup` is normalized against the baseline `pass
//! lookup`). The `ns/entry` columns report `(scenario − baseline) /
//! FILES_PER_DIR` for readdir — the extra time per listed entry relative to no
//! deny.
//!
//! # Interpreting the results
//!
//! - Lookup overhead is usually small: every lookup already pays an
//!   open/stat/close, so the extra deny work is a minor fraction.
//! - `readdir` is where per-entry deny cost shows up most (it touches every
//!   entry), and path patterns are typically the most expensive because they
//!   reconstruct each entry's mount-relative path. This is most visible in
//!   `readdir deny`, where every entry matches and path reconstruction
//!   dominates.
//!
//! The absolute numbers are machine-dependent; compare the relative `x` ratios
//! and `ns/entry` deltas across platforms rather than the ns figures.

use std::{
    path::Path,
    time::{Duration, Instant},
};

use super::*;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Number of files created in the shared directory tree. Large enough for
/// per-entry deny overhead to accumulate and be measurable.
const FILES_PER_DIR: usize = 1000;
/// Number of `lookup` / `readdir` repetitions per scenario, per round.
const REPETITIONS: usize = 25;
/// Number of rounds per scenario; the median round is reported to damp noise.
const ROUNDS: usize = 5;

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

/// Print a comparison of lookup/readdir cost across deny pattern kinds in a
/// single run. Not a correctness test; run explicitly with `-- --ignored` in a
/// release build.
#[test]
#[ignore]
fn deny_pattern_kind_perf_comparison() {
    let tmp = tempfile::tempdir().unwrap();
    let (scenarios, rows) = measure_tree(tmp.path());
    print_table(&scenarios, &rows);
}

/// Run the measurement `RUNS` times (default 10, override via the `RUNS` env
/// var) over the same tree and report the run-to-run spread for every metric,
/// so noisy metrics are easy to distinguish from stable ones. Not a correctness
/// test; run explicitly with `-- --ignored` in a release build.
#[test]
#[ignore]
fn deny_pattern_kind_perf_variance() {
    let runs: usize = std::env::var("RUNS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);

    let tmp = tempfile::tempdir().unwrap();
    build_tree(tmp.path());
    warm_tree(tmp.path());

    let scenarios = scenarios();

    let mut row_sets: Vec<Vec<Measured>> = Vec::with_capacity(runs);
    for _ in 0..runs {
        row_sets.push(scenarios.iter().map(|s| measure(tmp.path(), s)).collect());
    }

    print_variance(runs, &scenarios, &row_sets);
}

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// How to populate a deny-heavy directory so the scenario's patterns deny most
/// of its entries, while the directory itself stays servable (so it can be
/// looked up and listed).
#[derive(Clone, Copy)]
enum DenyHeavyKind {
    /// Fill with `*.log` files (matched by a `*.log` name-only pattern).
    Logs,
    /// Fill with `*.secret` files (matched by a `data/**/*.secret` path pattern).
    Secrets,
}

/// A single benchmark scenario: a deny config plus the operation targets that
/// make that config's overhead visible.
struct Scenario {
    label: &'static str,
    patterns: &'static [&'static str],
    /// A name, as a direct child of `data`, that the deny list hides.
    denied: Option<&'static [u8]>,
    /// `(subdirectory of `data`, kind)` to build a deny-heavy readdir, or
    /// `None` when a deny-heavy directory is not a natural case.
    deny_heavy: Option<(&'static str, DenyHeavyKind)>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Create the shared directory tree once, so every scenario measures the same
/// underlying files and caches.
fn build_tree(root: &Path) {
    let dir = root.join("data");
    std::fs::create_dir_all(&dir).unwrap();
    for i in 0..FILES_PER_DIR {
        std::fs::write(dir.join(format!("file-{i:04}.txt")), b"x").unwrap();
    }
    std::fs::write(dir.join(".env"), b"secret").unwrap();
    std::fs::write(dir.join("debug.log"), b"log").unwrap();
    std::fs::write(dir.join("x.secret"), b"secret").unwrap();
    std::fs::create_dir_all(dir.join("node_modules")).unwrap();

    // Deny-heavy directories: their contents are denied by the matching
    // scenario, but the directory itself stays servable so it can be listed.
    let logs = dir.join("logs");
    std::fs::create_dir_all(&logs).unwrap();
    for i in 0..FILES_PER_DIR {
        std::fs::write(logs.join(format!("log-{i:04}.log")), b"x").unwrap();
    }
    let zone = dir.join("zone");
    std::fs::create_dir_all(&zone).unwrap();
    for i in 0..FILES_PER_DIR {
        std::fs::write(zone.join(format!("file-{i:04}.secret")), b"x").unwrap();
    }
}

/// Fully read every directory in the tree several times so the kernel's
/// page/dentry caches are resident before any measurement.
///
/// `build_tree` writes thousands of files, leaving the caches it touched cold
/// for whatever scenario runs first. Warming the whole tree once eliminates the
/// first-run bias so the baseline and every scenario measure the same steady
/// state.
fn warm_tree(root: &Path) {
    for _ in 0..5 {
        for dir in ["data", "data/logs", "data/zone"] {
            let _ = std::fs::read_dir(root.join(dir)).unwrap().count();
        }
    }
}

/// Per-scenario benchmark result: median scenario latencies plus per-round
/// ratios/deltas against a baseline measured on the same fs in the same round.
struct Measured {
    /// Scenario pass lookup latency per op.
    pass_lookup: Duration,
    /// Median per-round ratio of scenario pass lookup to baseline pass lookup.
    pass_lookup_x: f64,
    /// Scenario denied lookup latency per op (ZERO if the scenario has none).
    deny_lookup: Duration,
    /// Median per-round ratio of denied lookup to baseline pass lookup.
    deny_lookup_x: f64,
    /// Scenario pass-heavy readdir latency per op.
    readdir: Duration,
    /// Median per-round ratio of scenario readdir to baseline readdir.
    readdir_x: f64,
    /// Median per-round extra ns per entry vs baseline readdir.
    readdir_ns_per_entry: f64,
    /// Scenario deny-heavy readdir latency per op (ZERO if none).
    deny_readdir: Duration,
    /// Median per-round ratio of deny-heavy readdir to baseline readdir.
    deny_readdir_x: f64,
    /// Median per-round extra ns per entry vs baseline readdir.
    deny_ns_per_entry: f64,
}

/// Build a [`PassthroughFs`] over `root` with the given deny patterns.
fn build_fs(root: &Path, patterns: &[&str]) -> PassthroughFs {
    let cfg = PassthroughConfig {
        root_dir: root.to_path_buf(),
        deny: patterns.iter().map(|p| p.to_string()).collect(),
        ..Default::default()
    };
    let fs = PassthroughFs::new(cfg).unwrap();
    fs.init(FsOptions::empty()).unwrap();
    fs
}

/// The benchmark scenarios, fixed across runs so run-to-run variance reflects
/// machine/cache state rather than a changing scenario set.
fn scenarios() -> [Scenario; 4] {
    [
        Scenario {
            label: "baseline",
            patterns: &[],
            denied: None,
            deny_heavy: None,
        },
        Scenario {
            label: "name-only",
            patterns: &[".env", "*.log"],
            denied: Some(b".env".as_slice()),
            deny_heavy: Some(("logs", DenyHeavyKind::Logs)),
        },
        Scenario {
            label: "dir-only",
            patterns: &["node_modules/"],
            denied: Some(b"node_modules".as_slice()),
            deny_heavy: None,
        },
        Scenario {
            label: "path",
            patterns: &["data/**/*.secret"],
            denied: Some(b"x.secret".as_slice()),
            deny_heavy: Some(("zone", DenyHeavyKind::Secrets)),
        },
    ]
}

/// Build and warm the shared tree once, then measure every scenario over it,
/// returning the scenarios alongside their [`Measured`] rows.
fn measure_tree(root: &Path) -> ([Scenario; 4], Vec<Measured>) {
    // Warm the kernel's page/dentry caches over the whole tree before any
    // measurement. Without this the first scenario to run (the baseline) pays
    // the cold caches left by `build_tree`, while later scenarios run warm,
    // making the no-deny baseline look slower than every deny scenario.
    build_tree(root);
    warm_tree(root);

    let scenarios = scenarios();
    let rows: Vec<Measured> = scenarios.iter().map(|s| measure(root, s)).collect();
    (scenarios, rows)
}

/// Measure a scenario over the shared tree by alternating it with a deny-free
/// baseline on the *same* tree, so both share identical machine/cache state
/// within each round and any drift cancels out. Across `ROUNDS` rounds the
/// median per-round ratio/delta is reported.
///
/// A denied/deny-heavy case is skipped (returning [`Duration::ZERO`] and a `0.0`
/// ratio) when the scenario has no denied name (baseline) or no natural
/// deny-heavy directory (dir-only).
fn measure(root: &Path, scenario: &Scenario) -> Measured {
    let fs = build_fs(root, scenario.patterns);
    let base = build_fs(root, &[]);
    let ctx = Context {
        uid: 0,
        gid: 0,
        pid: 1,
    };

    let dir_inode = lookup(&fs, &ctx, ROOT_INODE, b"data").unwrap().inode;
    let base_dir_inode = lookup(&base, &ctx, ROOT_INODE, b"data").unwrap().inode;

    // Deny-heavy directory inode (child of `data`), when the scenario has one.
    let deny_heavy_inode = match scenario.deny_heavy {
        Some((name, _)) => Some(lookup(&fs, &ctx, dir_inode, name.as_bytes()).unwrap().inode),
        None => None,
    };

    // Look up a file that passes the deny check (the common case), so each
    // iteration pays the full deny check without short-circuiting.
    let pass_name = CString::new(format!("file-{:04}.txt", FILES_PER_DIR - 1)).unwrap();
    let denied_name = scenario.denied.map(|d| CString::new(d).unwrap());

    // Warm-up both filesystems' operations so the kernel caches and the
    // in-process inode tables are fully resident before any timing.
    for _ in 0..3 {
        lookup(&fs, &ctx, dir_inode, pass_name.as_bytes()).unwrap();
        lookup(&base, &ctx, base_dir_inode, pass_name.as_bytes()).unwrap();
        for (f, ino) in [(&fs, dir_inode), (&base, base_dir_inode)] {
            let h = opendir(f, &ctx, ino).unwrap();
            let _ = f.readdir(ctx, ino, h, 1 << 20, 0).unwrap();
        }
        if let Some(deny_heavy_inode) = deny_heavy_inode {
            let h = opendir(&fs, &ctx, deny_heavy_inode).unwrap();
            let _ = fs.readdir(ctx, deny_heavy_inode, h, 1 << 20, 0).unwrap();
        }
    }

    let mut pass_lookup_xs = Vec::with_capacity(ROUNDS);
    let mut deny_lookup_xs = Vec::with_capacity(ROUNDS);
    let mut readdir_xs = Vec::with_capacity(ROUNDS);
    let mut readdir_deltas = Vec::with_capacity(ROUNDS);
    let mut deny_readdir_xs = Vec::with_capacity(ROUNDS);
    let mut deny_readdir_deltas = Vec::with_capacity(ROUNDS);
    let mut pass_lookups = Vec::with_capacity(ROUNDS);
    let mut deny_lookups = Vec::with_capacity(ROUNDS);
    let mut readdirs = Vec::with_capacity(ROUNDS);
    let mut deny_readdirs = Vec::with_capacity(ROUNDS);

    for _ in 0..ROUNDS {
        // Pass lookup, measured in BOTH orders within the round and averaged,
        // so any systematic "first/second measurement" bias cancels out.
        let (sc_a, ba_a) = (
            lookup_burst(&fs, ctx, dir_inode, &pass_name),
            lookup_burst(&base, ctx, base_dir_inode, &pass_name),
        );
        let (ba_b, sc_b) = (
            lookup_burst(&base, ctx, base_dir_inode, &pass_name),
            lookup_burst(&fs, ctx, dir_inode, &pass_name),
        );
        let scenario_lookup = (sc_a + sc_b) / 2;
        let base_lookup = (ba_a + ba_b) / 2;
        let ratio = ((sc_a.as_secs_f64() / ba_a.as_secs_f64())
            * (sc_b.as_secs_f64() / ba_b.as_secs_f64()))
        .sqrt();
        pass_lookups.push(scenario_lookup);
        pass_lookup_xs.push(ratio);

        // Denied lookup: the deny check matches and short-circuits to ENOENT
        // without touching the underlying file, isolating the cost of the deny
        // check itself. Assert the name is actually denied.
        if let Some(denied_name) = &denied_name {
            let deny_lookup = deny_lookup_burst(&fs, ctx, dir_inode, denied_name);
            deny_lookups.push(deny_lookup);
            deny_lookup_xs.push(deny_lookup.as_secs_f64() / base_lookup.as_secs_f64());
        }

        // Pass-heavy readdir over `data`, measured in both orders within the
        // round and averaged. Each opendir builds a fresh snapshot.
        let (sc_a, ba_a) = (
            readdir_burst(&fs, ctx, dir_inode),
            readdir_burst(&base, ctx, base_dir_inode),
        );
        let (ba_b, sc_b) = (
            readdir_burst(&base, ctx, base_dir_inode),
            readdir_burst(&fs, ctx, dir_inode),
        );
        let scenario_readdir = (sc_a + sc_b) / 2;
        let ratio = ((sc_a.as_secs_f64() / ba_a.as_secs_f64())
            * (sc_b.as_secs_f64() / ba_b.as_secs_f64()))
        .sqrt();
        let delta = (((sc_a.as_secs_f64() - ba_a.as_secs_f64())
            + (sc_b.as_secs_f64() - ba_b.as_secs_f64()))
            / 2.0)
            / FILES_PER_DIR as f64;
        readdirs.push(scenario_readdir);
        readdir_xs.push(ratio);
        readdir_deltas.push(delta);

        // Deny-heavy readdir over the deny-heavy directory. Assert it is
        // actually deny-heavy (omits most entries). Measured in BOTH orders
        // relative to the baseline `data` readdir within the round and averaged,
        // mirroring the pass metrics, so first/second-measurement bias cancels.
        if let Some(deny_heavy_inode) = deny_heavy_inode {
            let (sc_a, ba_a) = (
                deny_readdir_burst(&fs, ctx, deny_heavy_inode),
                readdir_burst(&base, ctx, base_dir_inode),
            );
            let (ba_b, sc_b) = (
                readdir_burst(&base, ctx, base_dir_inode),
                deny_readdir_burst(&fs, ctx, deny_heavy_inode),
            );
            let deny_readdir = (sc_a + sc_b) / 2;
            let ratio = ((sc_a.as_secs_f64() / ba_a.as_secs_f64())
                * (sc_b.as_secs_f64() / ba_b.as_secs_f64()))
            .sqrt();
            deny_readdirs.push(deny_readdir);
            deny_readdir_xs.push(ratio);
            deny_readdir_deltas.push(
                (((sc_a.as_secs_f64() - ba_a.as_secs_f64())
                    + (sc_b.as_secs_f64() - ba_b.as_secs_f64()))
                    / 2.0)
                    / FILES_PER_DIR as f64,
            );
        }
    }

    pass_lookups.sort();
    pass_lookup_xs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    deny_lookups.sort();
    deny_lookup_xs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    readdirs.sort();
    readdir_xs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    readdir_deltas.sort_by(|a, b| a.partial_cmp(b).unwrap());
    deny_readdirs.sort();
    deny_readdir_xs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    deny_readdir_deltas.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mid = ROUNDS / 2;

    let deny_lookup = deny_lookups.first().copied().unwrap_or(Duration::ZERO);
    let deny_lookup_x = deny_lookup_xs.first().copied().unwrap_or(0.0);
    let deny_readdir = deny_readdirs.first().copied().unwrap_or(Duration::ZERO);
    let deny_readdir_x = deny_readdir_xs.first().copied().unwrap_or(0.0);
    let deny_ns_per_entry = deny_readdir_deltas.first().copied().unwrap_or(0.0) * 1e9;

    Measured {
        pass_lookup: pass_lookups[mid],
        pass_lookup_x: pass_lookup_xs[mid],
        deny_lookup,
        deny_lookup_x,
        readdir: readdirs[mid],
        readdir_x: readdir_xs[mid],
        readdir_ns_per_entry: readdir_deltas[mid] * 1e9,
        deny_readdir,
        deny_readdir_x,
        deny_ns_per_entry,
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Reporting
//--------------------------------------------------------------------------------------------------

/// Print the full single-run comparison table used by
/// [`deny_pattern_kind_perf_comparison`].
fn print_table(scenarios: &[Scenario], rows: &[Measured]) {
    println!(
        "\n=== deny pattern-kind overhead (FILES_PER_DIR = {FILES_PER_DIR}, \
         REPETITIONS = {REPETITIONS}, ROUNDS = {ROUNDS}, interleaved same-tree baseline, median) ==="
    );
    println!(
        "{:<34} {:>11} {:>7} {:>11} {:>7} {:>11} {:>7} {:>7} {:>11} {:>7} {:>7}",
        "scenario",
        "pass look",
        "x",
        "deny look",
        "x",
        "readdir pass",
        "x",
        "ns/ent",
        "readdir deny",
        "x",
        "ns/ent"
    );
    for (scenario, m) in scenarios.iter().zip(rows) {
        println!(
            "{:<34} {:>9.0}ns {:>6.2}x {:>9.0}ns {:>6.2}x {:>9.0}ns {:>6.2}x {:>6.0} {:>9.0}ns {:>6.2}x {:>6.0}",
            scenario.label,
            m.pass_lookup.as_nanos() as f64 / REPETITIONS as f64,
            m.pass_lookup_x,
            m.deny_lookup.as_nanos() as f64 / REPETITIONS as f64,
            m.deny_lookup_x,
            m.readdir.as_nanos() as f64 / REPETITIONS as f64,
            m.readdir_x,
            m.readdir_ns_per_entry,
            m.deny_readdir.as_nanos() as f64 / REPETITIONS as f64,
            m.deny_readdir_x,
            m.deny_ns_per_entry,
        );
    }
    println!();
}

/// Print one compact line summarizing a single run of every scenario, so `N`
/// runs read as `N` scannable rows. Reports the `x` ratios and `ns/entry`
/// deltas (the machine-state-independent figures) per scenario.
/// Print the reviewer-facing headline matrix: one row per deny-pattern kind,
/// one column per operation, showing the median `x` ratio (relative to the
/// deny-free baseline) across runs with the run-to-run spread as a percentage
/// in parentheses. A short "scenarios" explanation precedes the matrix so a
/// reviewer new to the deny feature can read it without the source. The `x`
/// ratios are the machine-independent signal; `ns/entry` figures are too noisy
/// run-to-run to headline and are deliberately omitted. A blank cell means the
/// operation is not a natural case for that scenario.
fn print_variance(runs: usize, scenarios: &[Scenario], row_sets: &[Vec<Measured>]) {
    println!("\n=== deny pattern-kind overhead: median ratio vs baseline over {runs} runs ===");
    println!(
        "method: one shared tree, warmed; each op timed interleaved with the deny-free \
         baseline in both orders within each of {ROUNDS} rounds; ratios are the median \
         across runs; span% is (max-min)/median run-to-run spread."
    );
    println!("\nScenarios:");
    println!("{:<12} {:<28}", "name", "deny patterns");
    for scenario in scenarios.iter() {
        let patterns = if scenario.patterns.is_empty() {
            "(none)".to_string()
        } else {
            scenario.patterns.join(", ")
        };
        println!("{:<12} {:<28}", scenario.label, patterns);
    }
    println!(
        "\n{:<26} {:>13} {:>13} {:>13} {:>15}",
        "operation per scenario", "pass lookup", "deny lookup", "readdir", "readdir (deny)"
    );
    for (i, scenario) in scenarios.iter().enumerate() {
        println!(
            "{:<26} {:>13} {:>13} {:>13} {:>15}",
            scenario.label,
            cell(&median_span(i, row_sets, |m| m.pass_lookup_x)),
            cell(&median_span(i, row_sets, |m| m.deny_lookup_x)),
            cell(&median_span(i, row_sets, |m| m.readdir_x)),
            cell(&median_span(i, row_sets, |m| m.deny_readdir_x)),
        );
    }
    println!();
    println!(
        "Read each cell as `ratio x (span%)`: how many times slower than the deny-free \
         baseline, with the run-to-run spread as a percentage of that ratio. A ratio below \
         1.0 on a denied lookup means the deny check short-circuits before the file is \
         opened. `readdir (deny)` is a listing of a deny-heavy directory (mostly denied \
         entries) — the \"hide a subtree\" case. A blank cell is a case that scenario does \
         not exercise. Prefer the ratios; absolute `ns/entry` figures are omitted here \
         because they are too noisy run-to-run to be trustworthy."
    );
    println!();
}

/// `median x (span%)` for a single metric of scenario `i`, or `"-"` when the
/// metric is absent (all runs report zero).
fn median_span(
    i: usize,
    row_sets: &[Vec<Measured>],
    get: impl Fn(&Measured) -> f64,
) -> Option<(f64, f64)> {
    let mut values: Vec<f64> = row_sets.iter().map(|rows| get(&rows[i])).collect();
    if values.iter().all(|&v| v == 0.0) {
        return None;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mid = values.len() / 2;
    let median = values[mid];
    let span = values[values.len() - 1] - values[0];
    Some((median, span / median * 100.0))
}

/// Render a `(median x, span%)` cell, or a placeholder when absent.
fn cell(ms: &Option<(f64, f64)>) -> String {
    match ms {
        Some((median, span_pct)) => format!("{median:.2}x ({span_pct:.1}%)"),
        None => "-".to_string(),
    }
}

/// Look up `name` in `parent` via the filesystem, returning its entry.
fn lookup(fs: &PassthroughFs, ctx: &Context, parent: u64, name: &[u8]) -> std::io::Result<Entry> {
    let c = CString::new(name).unwrap();
    fs.lookup(*ctx, parent, &c)
}

/// Open a directory by inode and return the handle.
fn opendir(fs: &PassthroughFs, ctx: &Context, inode: u64) -> std::io::Result<u64> {
    let (handle, _opts) = fs.opendir(*ctx, inode, 0)?;
    Ok(handle.unwrap())
}

/// Time `REPETITIONS` passing lookups of `name` in `parent`.
fn lookup_burst(fs: &PassthroughFs, ctx: Context, parent: u64, name: &CString) -> Duration {
    let t0 = Instant::now();
    for _ in 0..REPETITIONS {
        fs.lookup(ctx, parent, name).unwrap();
    }
    t0.elapsed()
}

/// Time `REPETITIONS` denied lookups of `denied_name`, asserting each is ENOENT.
fn deny_lookup_burst(
    fs: &PassthroughFs,
    ctx: Context,
    parent: u64,
    denied_name: &CString,
) -> Duration {
    let t0 = Instant::now();
    for _ in 0..REPETITIONS {
        let err = match fs.lookup(ctx, parent, denied_name) {
            Ok(_) => panic!("denied name must not be served"),
            Err(e) => e,
        };
        assert_eq!(err.raw_os_error(), Some(LINUX_ENOENT));
    }
    t0.elapsed()
}

/// Time `REPETITIONS` full listings of `inode`, each via a fresh opendir so a
/// new point-in-time snapshot is built (matching real `do_readdir`).
fn readdir_burst(fs: &PassthroughFs, ctx: Context, inode: u64) -> Duration {
    let t0 = Instant::now();
    for _ in 0..REPETITIONS {
        let h = opendir(fs, &ctx, inode).unwrap();
        let _ = fs.readdir(ctx, inode, h, 1 << 20, 0).unwrap();
    }
    t0.elapsed()
}

/// Time `REPETITIONS` listings of a deny-heavy directory, asserting each is
/// actually deny-heavy (omits nearly all entries).
fn deny_readdir_burst(fs: &PassthroughFs, ctx: Context, inode: u64) -> Duration {
    let t0 = Instant::now();
    for _ in 0..REPETITIONS {
        let h = opendir(fs, &ctx, inode).unwrap();
        let listed = fs.readdir(ctx, inode, h, 1 << 20, 0).unwrap();
        assert!(
            listed.len() <= 2,
            "deny-heavy dir should be nearly empty, got {} entries",
            listed.len()
        );
    }
    t0.elapsed()
}
