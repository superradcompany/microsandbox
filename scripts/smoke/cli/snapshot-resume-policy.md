# Full-resume destination policy qualification

`snapshot-resume-policy.py` starts a background HTTP workload, captures it in a full checkpoint, deletes the source sandbox and resumes seven destinations. The workload continues from captured RAM; post-restore `exec` commands only read progress, and do not generate the network traffic being tested.

```sh
python3 scripts/smoke/cli/snapshot-resume-policy.py \
  --candidate /absolute/path/to/msb \
  --agent /absolute/path/to/agentd \
  --firmware /absolute/path/to/libkrunfw \
  --archive /absolute/path/to/native-alpine-disk.msb \
  --output /tmp/snapshot-resume-policy-results
```

Use a fresh output directory, a native self-contained Alpine disk archive, matching guest agent/firmware, and optionally `--temp-root`. The local SOCKS fixtures serve a fixed HTTP response for a documentation address without forwarding traffic. The old proxy stays alive after source deletion to detect accidental fallback. An ephemeral loopback-bound published port requests the existing private guest IPv4 allocation path even when the test host has no external route; the fixture does not require a guest service on that port. DNS-rebind protection is explicitly disabled for these reserved-address policy tests; the separate proxy launch harness tests that protection.

The seven cases require destination HTTP traffic and two newly completed guest response-body checks through authenticated SOCKS5, HTTP CONNECT, and SOCKS4 with and without an explicit user ID; no proxy contact for destination deny; observed authentication rejection and no HTTP handling for incorrect credentials; and launch refusal before proxy contact for a missing credential. The allowed protocol, denied and incorrect-credential cases also prove that the captured background workload continues making attempts. Events are recorded at create return and after the guest checks. The counter pairs are atomically replaced and contain attempts/successful body checks; no command-line credentials, environment values or HTTP headers are recorded by the proxy.

The suite checks source-checkpoint and archive immutability, removes destination sandboxes and verifies that the private catalog is empty. Failures remain qualification failures. It does not prove transparent migration of an established remote TCP connection, every full-resume protocol/TLS policy, every SDK, or complete PR2 scope. Do not infer those guarantees from successful new requests made by the resumed process.

```sh
python3 -m unittest discover -s scripts/smoke/cli -p test_snapshot_resume_policy.py
```
