//! Per-scenario runner: build a `dig` command, execute it inside the
//! guest, parse the DNS response header, and assert against the
//! expected outcome.

use microsandbox::Sandbox;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Expected outcome of a single `dig` invocation.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Expect {
    /// `status: NOERROR` with an `ANSWER SECTION` present.
    Resolves,
    /// `status: REFUSED` (block list, rebind, or policy denial).
    Refused,
    /// Neither a successful answer nor a REFUSED response — upstream was
    /// unreachable (RST, connection refused, DoT handshake failed, etc.).
    NoAnswer,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Run one scenario: execute `cmd` inside the guest, parse the dig
/// output, and `assert!` the expected outcome. The assertion message
/// carries the scenario name, expected outcome, and the first line of
/// dig output so the failure panic reads cleanly.
pub(crate) async fn assert_scenario(sb: &Sandbox, name: &str, cmd: &str, want: Expect) {
    let raw = match sb.shell(cmd).await {
        Ok(o) => o.stdout().unwrap_or_default().to_string(),
        Err(e) => format!("<shell error: {e}>"),
    };
    let passed = matches_expectation(&raw, want);
    println!("  {} {name}", if passed { "✓" } else { "✗" });
    assert!(
        passed,
        "scenario failed: {name}\n  expected: {want:?}\n  got: {}\n  full dig output:\n{raw}",
        raw.lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .unwrap_or("<no output>"),
    );
}

/// Build a `dig` command with sensible defaults. Trims the trailing
/// stats block but keeps comments. We need the `;; ->>HEADER<<- ...
/// status: X` line for RCODE parsing and `;; ANSWER SECTION:` to
/// confirm there's an answer. `+nocomments` would suppress both.
pub(crate) fn dig(name: &str, extra_args: &[&str]) -> String {
    let mut cmd = String::from("dig +nostats +time=3 +tries=1");
    for arg in extra_args {
        cmd.push(' ');
        cmd.push_str(arg);
    }
    cmd.push(' ');
    cmd.push_str(name);
    cmd.push_str(" 2>&1");
    cmd
}

//--------------------------------------------------------------------------------------------------
// Functions: Internal
//--------------------------------------------------------------------------------------------------

/// Match dig output against the expected outcome. Full-header parsing
/// so we distinguish REFUSED from NXDOMAIN / timeout.
fn matches_expectation(raw: &str, want: Expect) -> bool {
    let status = parse_status(raw);
    let has_answer = raw.contains("ANSWER SECTION:");
    let dig_failed = raw.contains("no servers could be reached")
        || raw.contains("communications error")
        || raw.contains("connection refused")
        || raw.contains("connection timed out");
    match want {
        Expect::Resolves => status.as_deref() == Some("NOERROR") && has_answer,
        Expect::Refused => status.as_deref() == Some("REFUSED"),
        Expect::NoAnswer => !has_answer && (dig_failed || status.is_none()),
    }
}

/// Extract the RCODE from a `dig` header line like:
/// `;; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 12345`.
fn parse_status(output: &str) -> Option<String> {
    for line in output.lines() {
        if let Some(pos) = line.find("status: ") {
            let rest = &line[pos + "status: ".len()..];
            let end = rest.find(',').unwrap_or(rest.len());
            return Some(rest[..end].trim().to_string());
        }
    }
    None
}
