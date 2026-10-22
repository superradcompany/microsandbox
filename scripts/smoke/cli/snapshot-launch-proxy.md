# Snapshot-backed proxy launch qualification

`snapshot-launch-proxy.py` exercises the destination configuration workflow reported in #1736 using actual guest commands and local SOCKS/DNS fixtures. Supply a self-contained native Alpine disk snapshot archive, a candidate CLI, matching guest agent and firmware. The harness imports the archive into a private home, creates and prepares a source, captures a new disk snapshot, then removes the source sandbox before testing destination launches.

```sh
python3 scripts/smoke/cli/snapshot-launch-proxy.py \
  --candidate /absolute/path/to/msb \
  --agent /absolute/path/to/agentd \
  --firmware /absolute/path/to/libkrunfw \
  --archive /absolute/path/to/alpine-disk.msb \
  --output /tmp/snapshot-proxy-results
```

Use a fresh output directory and optionally `--temp-root` for short disk-backed homes. The proxy fixtures serve a fixed HTTP response for a reserved documentation address without connecting to that address. The DNS fixture answers only its test name and never forwards queries. These are local protocol fixtures, not production proxy servers. HTTP CONNECT and SOCKS4 fixtures accept only the exact test target, bound request buffering, and omit header/user-ID values from event reports. They do not change host network settings or trust stores.

The sixteen cases cover HTTP CONNECT, SOCKS4 with and without an explicit user ID, unauthenticated/authenticated SOCKS5 run, create/exec/restart, authenticated root config, atomic proxy replacement by a later root file, CLI flags and scoped network config, actual DNS-rebind protection enabled/disabled, first-request policy denial, bad authentication, a missing destination credential and an unavailable proxy. The combined run cases verify UID/GID 1000, working directory, hostname, environment, a readonly host directory, a writable named volume, host-CA bytes installed in the guest, command stdout/stderr and exit code 37. File replacement cases deliberately remove the lower proxy's password environment variable to prove that its credentials are no longer resolved.

The DNS cases return a reserved address under default-allow policy, with no explicit address/domain allow rule granting the existing rebind exemption. Protection must block the guest request before it reaches SOCKS; explicit `--no-dns-rebind-protection` must permit the same request, observed by both local fixtures. Merely inspecting a saved boolean is insufficient. Host-CA checks compare the shipped PEM with the guest's installed trust file; they do not establish every TLS client's trust-store behavior or a corporate TLS interception session.

Reports retain exact command/exit results and CLI/agent/firmware/archive/harness hashes. Proxy records contain authentication outcomes and destination addresses, never passwords or request headers. Source descriptor/payload hashes and the original archive must remain unchanged. Cleanup checks the private catalog for remaining sandbox rows; a missing credential may leave a failed launch entry that the harness explicitly removes. Failed assertions and cleanup are qualification failures.

This is a scaled functional reproduction using two CPUs, 256 MiB RAM, one named volume and one host directory. It is not the original eight-CPU/16-GiB workload, a full-memory restore matrix, encrypted HTTP-proxy transport, all SDK bindings, power-loss testing, or proof of completed PR2 scope. The config-file field also needs parser/merge tests, and older CLIs must reject it rather than silently ignore it.

```sh
python3 -m unittest discover -s scripts/smoke/cli -p test_snapshot_launch_proxy.py
```
