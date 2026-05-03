// Init-handoff example: hand PID 1 off to systemd.
// Uses jrei/systemd-debian:12 — most slim base images strip systemd.

import { MiB, Sandbox } from "microsandbox";

// "auto" probes /sbin/init, /lib/systemd/systemd, /usr/lib/systemd/systemd.
await using sandbox = await Sandbox.builder("init-handoff")
  .image("mirror.gcr.io/jrei/systemd-debian:12")
  .cpus(2)
  .memory(MiB(1024))
  .replace()
  .init("auto")
  .create();

const comm = await sandbox.shell("cat /proc/1/comm");
console.log("/proc/1/comm:", comm.stdout().trim());

const exe = await sandbox.shell("readlink /proc/1/exe");
console.log("/proc/1/exe ->", exe.stdout().trim());

const status = await sandbox.shell("systemctl is-system-running --wait");
console.log("systemctl is-system-running:", status.stdout().trim());

const services = await sandbox.shell(
  "systemctl list-units --type=service --state=running --no-legend --no-pager",
);
console.log("Running services:\n" + services.stdout().trimEnd());
