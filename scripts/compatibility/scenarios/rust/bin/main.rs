//! Live checks shared by the released and candidate Rust SDK matrix entries.

use std::env;
use std::error::Error;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use microsandbox::{NetworkPolicy, Sandbox, SaveOpts, Snapshot};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const CASES: &[&str] = &[
    "tmpfs-0",
    "tmpfs-1",
    "tmpfs-3",
    "defaults",
    "persistence",
    "network-deny",
    "snapshot",
];
const MARKER: &str = "/root/msb-compat-marker";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

type CheckResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

#[tokio::main]
async fn main() -> CheckResult<()> {
    let report_path = PathBuf::from(env::var("MSB_COMPAT_REPORT")?);
    let image = env::var("MSB_COMPAT_IMAGE")?;
    let selected = env::var("MSB_COMPAT_CASE").unwrap_or_else(|_| "all".into());
    let expected_sdk = env::var("MSB_COMPAT_SDK_VERSION")?;
    let cases = if selected == "all" {
        CASES.to_vec()
    } else if CASES.contains(&selected.as_str()) {
        vec![selected.as_str()]
    } else {
        return Err(format!("unknown compatibility case: {selected}").into());
    };
    // This is the requested version only. The runner records Cargo's actual resolved
    // package source/version separately; an environment label is not SDK provenance.
    let mut report = json!({
        "language": "rust", "sdk_expected": expected_sdk, "image": image,
        "status": "running", "cases": [],
    });
    std::fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    let mut failed = false;
    for case in cases {
        let started = Instant::now();
        let mut names = Vec::new();
        let mut checks = Vec::new();
        let result = tokio::time::timeout(
            Duration::from_secs(240),
            run_case(case, &image, &report_path, &mut names, &mut checks),
        )
        .await;
        let error = match result {
            Ok(Ok(())) => None,
            Ok(Err(error)) => Some(error.to_string()),
            Err(_) => Some("case exceeded its 240 second deadline".into()),
        };
        // A failed assertion must still stop any detached snapshot restore. Keep
        // cleanup failures visible because leaked VMs can poison subsequent cases.
        let mut cleanup_errors = Vec::new();
        for name in names.iter().rev() {
            if let Err(error) = cleanup(name).await {
                cleanup_errors.push(format!("{name}: {error}"));
            }
        }
        let passed = error.is_none() && cleanup_errors.is_empty();
        failed |= !passed;
        report["cases"].as_array_mut().unwrap().push(json!({
            "case": case, "status": if passed { "passed" } else { "failed" },
            "duration_ms": started.elapsed().as_millis(), "checks": checks,
            "error": error, "cleanup_errors": cleanup_errors,
        }));
        std::fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    }
    report["status"] = json!(if failed { "failed" } else { "passed" });
    std::fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    if failed {
        return Err("one or more Rust compatibility cases failed".into());
    }
    Ok(())
}

async fn run_case(
    case: &str,
    image: &str,
    report_path: &std::path::Path,
    names: &mut Vec<String>,
    checks: &mut Vec<Value>,
) -> CheckResult<()> {
    let name = format!("compat-rust-{case}-{}", std::process::id());
    let mut builder = Sandbox::builder(&name)
        .image(image)
        .env("MSB_COMPAT_SENTINEL", "spaces = unicode-λ")
        .env("MSB_COMPAT_EMPTY", "");
    if let Some(count) = case.strip_prefix("tmpfs-") {
        for index in 0..count.parse::<usize>()? {
            builder = builder.volume(format!("/compat-tmpfs-{index}"), |mount| {
                mount.tmpfs().size(16u32)
            });
        }
    }
    if case == "network-deny" {
        builder = builder.network(|network| network.policy(NetworkPolicy::allow_all()));
    }
    // Register names before launch so a timed-out handshake cannot leave a
    // running sandbox outside the cleanup set.
    names.push(name.clone());
    let sandbox = builder.create().await?;
    verify_runtime(&name, checks)?;
    check(
        &sandbox,
        "exec and environment",
        r#"test "$MSB_COMPAT_SENTINEL" = 'spaces = unicode-λ' && test "${MSB_COMPAT_EMPTY+x}" = x && test -z "$MSB_COMPAT_EMPTY" && printf compat-exec-ok"#,
        "compat-exec-ok",
        checks,
    )
    .await?;

    match case {
        "tmpfs-0" | "tmpfs-1" | "tmpfs-3" => {
            let count = case.strip_prefix("tmpfs-").unwrap().parse::<usize>()?;
            let output = shell(&sandbox, "cat /proc/mounts").await?;
            let actual = output
                .lines()
                .filter(|line| {
                    line.split_whitespace()
                        .nth(1)
                        .is_some_and(|path| path.starts_with("/compat-tmpfs-"))
                })
                .collect::<Vec<_>>();
            if actual.len() != count
                || actual
                    .iter()
                    .any(|line| line.split_whitespace().nth(2) != Some("tmpfs"))
            {
                return Err(
                    format!("expected {count} requested tmpfs mounts, saw {actual:?}").into(),
                );
            }
            checks.push(
                json!({"check": "tmpfs mount count and type", "count": count, "mounts": actual}),
            );
            for index in 0..count {
                check(
                    &sandbox,
                    "tmpfs write and read",
                    &format!("printf mount-{index} > /compat-tmpfs-{index}/marker && cat /compat-tmpfs-{index}/marker"),
                    &format!("mount-{index}"),
                    checks,
                ).await?;
            }
        }
        "defaults" => {
            let resources = &sandbox.config().spec.resources;
            if resources.cpus != 1 || resources.memory_mib != 512 {
                return Err(format!(
                    "unexpected defaults: {} CPUs, {} MiB",
                    resources.cpus, resources.memory_mib
                )
                .into());
            }
            check(
                &sandbox,
                "guest default CPU count",
                "awk '/^processor[[:space:]]*:/{n++} END{print n}' /proc/cpuinfo",
                "1",
                checks,
            )
            .await?;
            let memory = shell(&sandbox, "awk '/^MemTotal:/{print $2}' /proc/meminfo").await?;
            let memory_kib: u64 = memory.trim().parse()?;
            // Kernel reservations reduce MemTotal, so verify the launch geometry
            // with a bounded range rather than equating it to configured RAM.
            if !(384 * 1024..=512 * 1024).contains(&memory_kib) {
                return Err(
                    format!("guest RAM disagrees with 512 MiB default: {memory_kib} KiB").into(),
                );
            }
            checks.push(json!({"check": "resource defaults", "cpus": resources.cpus, "memory_mib": resources.memory_mib, "guest_memory_kib": memory_kib}));
        }
        "persistence" => {
            shell(&sandbox, &format!("printf persisted > {MARKER} && sync")).await?;
            sandbox.stop().await?;
            let restarted = Sandbox::start(&name).await?;
            verify_runtime(&name, checks)?;
            check(
                &restarted,
                "disk marker after stop/start",
                &format!("cat {MARKER}"),
                "persisted",
                checks,
            )
            .await?;
            restarted.stop().await?;
        }
        "network-deny" => network_denial(&sandbox, image, &name, names, checks).await?,
        "snapshot" => {
            shell(&sandbox, &format!("printf captured > {MARKER} && sync")).await?;
            sandbox.stop().await?;
            let snapshot = Snapshot::builder(format!("{name}-state"))
                .from_sandbox(&name)
                .create()
                .await?;
            let child_name = format!("{name}-disk");
            names.push(child_name.clone());
            let child = Sandbox::restore_ref(snapshot.reference())
                .name(&child_name)
                .restore()
                .await?;
            verify_runtime(&child_name, checks)?;
            check(
                &child,
                "disk snapshot restore",
                &format!("cat {MARKER}"),
                "captured",
                checks,
            )
            .await?;
            child.stop().await?;
            let archive = report_path.with_extension("snapshot.tar.zst");
            snapshot
                .save_to(
                    &archive,
                    SaveOpts {
                        with_image: true,
                        ..SaveOpts::default()
                    },
                )
                .await?;
            let archive_name = format!("{name}-archive");
            names.push(archive_name.clone());
            let restored = Sandbox::restore(archive.to_string_lossy().into_owned())
                .name(&archive_name)
                .restore()
                .await?;
            verify_runtime(&archive_name, checks)?;
            check(
                &restored,
                "snapshot archive restore",
                &format!("cat {MARKER}"),
                "captured",
                checks,
            )
            .await?;
            restored.stop().await?;
            checks.push(json!({"check": "archive created", "bytes": std::fs::metadata(&archive)?.len(), "path": archive}));
        }
        _ => return Err(format!("unimplemented case: {case}").into()),
    }
    if !matches!(case, "persistence" | "snapshot") {
        sandbox.stop().await?;
    }
    Ok(())
}

async fn network_denial(
    allowed: &Sandbox,
    image: &str,
    name: &str,
    names: &mut Vec<String>,
    checks: &mut Vec<Value>,
) -> CheckResult<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let server = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut request = [0u8; 2048];
            let _ = stream.read(&mut request).await;
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\ncompat-network").await;
        }
    });
    let result: CheckResult<()> = async {
        // Raw gateway IPv4 avoids a DNS failure masquerading as egress policy
        // enforcement. First prove the same HTTP service is actually reachable.
        let probe = network_probe(allowed, port).await?;
        check(allowed, "allow-all network positive control", &probe, "compat-network", checks).await?;
        let denied_name = format!("{name}-denied");
        names.push(denied_name.clone());
        let denied = Sandbox::builder(&denied_name).image(image)
            .network(|network| network.policy(NetworkPolicy::none())).create().await?;
        verify_runtime(&denied_name, checks)?;
        shell(&denied, "command -v wget && command -v awk").await?;
        let denied_probe = network_probe(&denied, port).await?;
        let output = denied.exec("/bin/sh", ["-c", denied_probe.as_str()]).await?;
        if output.status().success || !output.stdout()?.is_empty() {
            return Err("deny-all policy allowed the reachable host HTTP endpoint".into());
        }
        checks.push(json!({"check": "deny-all network blocks reachable endpoint", "exit_code": output.status().code, "stderr": output.stderr()?}));
        check(allowed, "network positive control after denial", &probe, "compat-network", checks).await?;
        denied.stop().await?;
        Ok(())
    }.await;
    server.abort();
    result
}

async fn shell(sandbox: &Sandbox, script: &str) -> CheckResult<String> {
    let output = sandbox.exec("/bin/sh", ["-c", script]).await?;
    if !output.status().success {
        return Err(format!(
            "guest command failed ({}): {script}; stderr: {}",
            output.status().code,
            output.stderr()?
        )
        .into());
    }
    Ok(output.stdout()?)
}

async fn network_probe(sandbox: &Sandbox, port: u16) -> CheckResult<String> {
    let gateway = shell(
        sandbox,
        "awk '/^nameserver /{print $2; exit}' /etc/resolv.conf",
    )
    .await?;
    let gateway: std::net::Ipv4Addr = gateway.trim().parse()?;
    Ok(format!("wget -T 3 -O - http://{gateway}:{port}/"))
}

fn verify_runtime(name: &str, checks: &mut Vec<Value>) -> CheckResult<()> {
    let verifier = env::var("MSB_COMPAT_VERIFY_RUNTIME")?;
    let python = env::var("MSB_COMPAT_PYTHON").unwrap_or_else(|_| "python3".into());
    let output = Command::new(python).arg(verifier).arg(name).output()?;
    if !output.status.success() {
        return Err(format!(
            "runtime provenance check failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    checks.push(json!({"check": "live runtime provenance", "sandbox": name, "stdout": String::from_utf8_lossy(&output.stdout)}));
    let output = Command::new(env::var("MSB_COMPAT_CLI")?)
        .args(["inspect", name])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "CLI could not inspect SDK-created sandbox {name}: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    checks.push(json!({"check": "CLI reads SDK sandbox", "sandbox": name}));
    Ok(())
}

async fn check(
    sandbox: &Sandbox,
    label: &str,
    script: &str,
    expected: &str,
    checks: &mut Vec<Value>,
) -> CheckResult<()> {
    let stdout = shell(sandbox, script).await?;
    if stdout.trim_end() != expected {
        return Err(format!("{label}: expected {expected:?}, received {stdout:?}").into());
    }
    checks.push(json!({"check": label, "stdout": stdout}));
    Ok(())
}

async fn cleanup(name: &str) -> CheckResult<()> {
    let handle = Sandbox::get(name).await?;
    if handle
        .stop_with_timeout(Duration::from_secs(15))
        .await
        .is_err()
    {
        handle.kill().await?;
    }
    Sandbox::remove(name).await?;
    Ok(())
}
