# Released SDK launch fixtures

`launch-v0.6.10.json` and `launch-v0.6.18.json` were captured from the corresponding published macOS arm64 Python wheels using `scripts/smoke/sdk/cross-version-launch.py`. The capture reads the inherited config descriptor without advancing its offset, then executes the selected runtime normally. Both released SDKs completed create, exec, stop, restart, and remove against the modified runtime.

The payloads preserve the released wire shape and a deny-all network policy. Host paths and sandbox names are normalized, and the process-specific metrics reservation is replaced with `null`. The v0.6.10 payload has flat networking; v0.6.18 has a resolved network envelope. Neither payload is generated from current `LaunchConfig` serialization.

Live checks also ran the current SDK against the actual v0.6.10 and v0.6.18 runtime/firmware pairs. Release archives were verified against their `checksums.sha256`. Each direction used a fresh, short `MSB_HOME`, default and deny-all networking, command-output assertions, shutdown, restart, and removal. A blocked outbound request verifies that the deny-all policy survives the codec.

To repeat a direction, set `MSB_HOME`, `MSB_PATH`, and `MSB_LIBKRUNFW_PATH`, then run the smoke script with the Python interpreter containing the chosen SDK. For the source SDK, also set `PYTHONPATH` to `sdk/python` and build its native extension first. Codesign a locally built macOS runtime with `msb-entitlements.plist` before running it. These checks exercise launching and ordinary lifecycle operations, not database downgrades or every feature of every historical release.
