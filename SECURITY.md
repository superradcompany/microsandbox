# Security Policy

The microsandbox team welcomes security reports and is committed to addressing security issues promptly. microsandbox is an isolation primitive, so security issues in it affect everyone who builds on it. We treat reports as a high priority.

## Reporting a vulnerability

The preferred channel is [GitHub's private vulnerability reporting][gh-private]. It gives us a private channel to discuss the issue and coordinate a fix, and it integrates cleanly with CVE assignment when warranted.

If GitHub isn't an option, email [security@superrad.company][support-email].

Security issues should not be reported via the public GitHub issue tracker, in Discord, or on social media before we've shipped a fix.

### What to include

To help us triage quickly:

- A description of the issue and its impact
- A minimal reproduction (PoC code, sandbox config, or commands)
- The microsandbox version (`microsandbox --version`) or commit SHA
- Host platform (Linux distro and kernel, or macOS version and chip)
- Any logs, traces, or screenshots that help

## Scope

In scope:

- **microsandbox core** ([`github.com/superradcompany/microsandbox`][repo])
- **microsandbox SDKs** (Python and Node)
- **microsandbox managed cloud** and its control plane (when generally available)
- Build, signing, and release infrastructure (binaries, package registries)

Vulnerability classes we're particularly interested in:

- Sandbox escape (guest workload to host)
- Isolation bypass between sandboxes
- Network policy or egress-filter bypass
- Host privilege escalation
- Secret or credential leakage outside the intended boundary
- Snapshot or restore paths leaking data across sandboxes
- Authentication or authorization bugs in the control plane
- Supply-chain issues (compromised builds, malicious dependencies)

Out of scope:

- Issues requiring physical access to the host
- Self-DoS (e.g. crashing your own sandbox with adversarial input)
- Theoretical issues without a working PoC
- Already-known issues in upstream dependencies (please report those to the upstream project)
- Best-practice or hardening suggestions that aren't exploitable

## What to expect from us

We're a small team and we're honest about our response capacity. Our targets:

| Stage | Target |
|---|---|
| Initial acknowledgment | Within 3 business days |
| Triage and severity assessment | Within 7 days |
| Fix for critical-severity issues | Within 30 days |
| Fix for high-severity issues | Within 60 days |
| Public advisory | After the fix ships |

We'll keep you informed throughout: when we've triaged, when a fix is in progress, when it ships, and when an advisory is published.

## Security advisories

We're committed to transparency in security disclosure. We publish advisories through our GitHub repository's [security advisories portal][sec-advisories] and the [RustSec advisory database][rustsec-db].

## Coordinated disclosure

We follow coordinated disclosure with a default **90-day embargo** from the date of initial acknowledgment. We may publish sooner if a fix ships earlier, or extend the timeline (in discussion with the reporter) for genuinely complex fixes.

If a vulnerability is being actively exploited in the wild, we'll prioritize the fix and shorten the embargo as needed.

## Recognition

We credit reporters in our security advisories unless you'd prefer to remain anonymous. Include your preferred name and a link (GitHub, X, personal site) in your report if you'd like to be credited.

We don't currently run a paid bug bounty program. We may introduce one as the company grows.

## Questions

If anything here is unclear, email [security@superrad.company][support-email].

[gh-private]: https://github.com/superradcompany/microsandbox/security/advisories/new
[support-email]: mailto:security@superrad.company
[repo]: https://github.com/superradcompany/microsandbox
[sec-advisories]: https://github.com/superradcompany/microsandbox/security/advisories
[rustsec-db]: https://github.com/RustSec/advisory-db
