// Init-handoff example: hand PID 1 inside the guest off to systemd.
//
// Note: this uses mirror.gcr.io/jrei/systemd-debian:12, a community-built
// Debian image with systemd preinstalled. Most slim base images
// (debian:bookworm-slim, ubuntu:24.04, etc.) strip systemd entirely; see
// docs/sandboxes/customization.mdx for image-picking guidance.

import { MiB, Sandbox } from "microsandbox";

console.log("Creating sandbox with init handoff (image=jrei/systemd-debian:12)");

// Boot a microVM and hand PID 1 off to systemd after agentd's setup.
// `"auto"` asks agentd to probe /sbin/init, /lib/systemd/systemd,
// /usr/lib/systemd/systemd and pick the first that exists. For
// reproducible CI, pass an absolute path instead.
await using sandbox = await Sandbox.builder("init-handoff")
  .image("mirror.gcr.io/jrei/systemd-debian:12")
  .cpus(2)
  .memory(MiB(1024))
  .replace()
  .init("auto")
  .create();

// Verify the handoff worked: PID 1 should now be systemd.
const comm = await sandbox.shell("cat /proc/1/comm");
console.log("/proc/1/comm:", comm.stdout().trim());

const exe = await sandbox.shell("readlink /proc/1/exe");
console.log("/proc/1/exe ->", exe.stdout().trim());

// Wait for systemd to reach a steady state.
const status = await sandbox.shell("systemctl is-system-running --wait");
console.log("systemctl is-system-running:", status.stdout().trim());

// Show running services to prove systemd is actually managing the system.
const services = await sandbox.shell(
  "systemctl list-units --type=service --state=running --no-legend --no-pager",
);
console.log("Running services:\n" + services.stdout().trimEnd());

// `await using` triggers stop_and_wait at scope exit, which takes the
// signal-based path (SIGRTMIN+4 -> systemd shutdown -> kernel exit).
console.log("Sandbox stopped at end of scope.");
