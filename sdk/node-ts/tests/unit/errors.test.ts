import { describe, expect, it } from "vitest";
import {
  ExecTimeoutError,
  StopTimeoutError,
  ImageNotFoundError,
  MetricsDisabledError,
  MicrosandboxError,
  NoDefaultCommandError,
  SandboxNotFoundError,
  SandboxReplacedError,
  SnapshotSourceRecoveryError,
  SandboxStopTimedOutError,
} from "../../dist/index.js";
import { mapNapiError } from "../../dist/internal/error-mapping.js";

describe("mapNapiError", () => {
  it("preserves graceful stop timeout as a distinct error", () => {
    const raw = new Error('[StopTimeout] sandbox "busy" timed out; no kill was requested');
    const mapped = mapNapiError(raw);
    expect(mapped).toBeInstanceOf(StopTimeoutError);
    expect((mapped as StopTimeoutError).code).toBe("stopTimeout");
    expect(mapped.message).toContain("no kill was requested");
    expect(mapped.cause).toBe(raw);
  });
  for (const kind of ["installed", "archive", null]) {
    it(`retains source recovery metadata with ${kind ?? "unpublished"} artifact`, () => {
      const recovery = {
        source_sandbox: "team/source", checkpoint_id: "checkpoint-1",
        checkpoint_root: "sha256:root", checkpoint_path: "/runtime/checkpoint",
        artifact: kind === null ? null : {
          kind, path: "/snapshots/saved", snapshot_id: "snap_1", digest: "sha256:descriptor",
        },
        detail: "thaw acknowledgement lost\nsource recovery is uncertain",
        publication_error: kind === null ? "disk full" : null,
      };
      const raw = new Error(`[SnapshotSourceRecovery] ${JSON.stringify({
        message: "capture completed, source recovery failed", recovery,
      })}`);
      const mapped = mapNapiError(raw) as SnapshotSourceRecoveryError;
      expect(mapped).toBeInstanceOf(SnapshotSourceRecoveryError);
      expect(mapped.code).toBe("snapshotSourceRecovery");
      expect(mapped.message).toBe("capture completed, source recovery failed");
      expect(mapped.cause).toBe(raw);
      expect(mapped.recovery).toEqual({
        sourceSandbox: "team/source", checkpointId: "checkpoint-1",
        checkpointRoot: "sha256:root", checkpointPath: "/runtime/checkpoint",
        artifact: kind === null ? null : {
          kind, path: "/snapshots/saved", snapshotId: "snap_1", digest: "sha256:descriptor",
        },
        detail: recovery.detail, publicationError: recovery.publication_error,
      });
    });
  }

  for (const payload of ["not json", "null", "{}", '{"message":"failed","recovery":{}}']) {
    it(`preserves malformed recovery envelopes: ${payload}`, () => {
      const raw = new Error(`[SnapshotSourceRecovery] ${payload}`);
      expect(mapNapiError(raw)).toBe(raw);
    });
  }

  it("translates a tagged napi error into the matching subclass", () => {
    const raw = new Error("[SandboxNotFound] no such sandbox: foo");
    const mapped = mapNapiError(raw);
    expect(mapped).toBeInstanceOf(SandboxNotFoundError);
    expect((mapped as SandboxNotFoundError).message).toBe(
      "no such sandbox: foo",
    );
    expect((mapped as SandboxNotFoundError).code).toBe("sandboxNotFound");
    expect((mapped as MicrosandboxError).cause).toBe(raw);
  });

  it("parses a millisecond timeout out of ExecTimeout messages", () => {
    const raw = new Error("[ExecTimeout] killed after 250ms");
    const err = mapNapiError(raw) as ExecTimeoutError;
    expect(err).toBeInstanceOf(ExecTimeoutError);
    expect(err.timeoutMs).toBe(250);
  });

  it("parses a second-based timeout", () => {
    const raw = new Error("[ExecTimeout] killed after 5s");
    const err = mapNapiError(raw) as ExecTimeoutError;
    expect(err.timeoutMs).toBe(5000);
  });

  it("passes through unrecognised tags", () => {
    const raw = new Error("[Unknown] something else");
    expect(mapNapiError(raw)).toBe(raw);
  });

  it("maps a stop deadline to SandboxStopTimedOutError", () => {
    const raw = new Error(
      "[SandboxStopTimedOut] timed out waiting for sandbox to stop",
    );
    const mapped = mapNapiError(raw);

    expect(mapped).toBeInstanceOf(SandboxStopTimedOutError);
    expect((mapped as SandboxStopTimedOutError).code).toBe(
      "sandboxStopTimedOut",
    );
  });

  it("passes through plain Error messages", () => {
    const raw = new Error("not a tagged error");
    expect(mapNapiError(raw)).toBe(raw);
  });

  it("dispatches across all common variants", () => {
    expect(mapNapiError(new Error("[ImageNotFound] python:3.12"))).toBeInstanceOf(
      ImageNotFoundError,
    );
  });

  it("maps MetricsDisabled to MetricsDisabledError", () => {
    const raw = new Error("[MetricsDisabled] metrics disabled for sandbox: foo");
    const mapped = mapNapiError(raw);
    expect(mapped).toBeInstanceOf(MetricsDisabledError);
    expect((mapped as MetricsDisabledError).message).toBe(
      "metrics disabled for sandbox: foo",
    );
    expect((mapped as MetricsDisabledError).code).toBe("metricsDisabled");
    expect((mapped as MicrosandboxError).cause).toBe(raw);
  });

  it("maps NoDefaultCommand to its typed SDK error", () => {
    const raw = new Error("[NoDefaultCommand] sandbox has no default command");
    const mapped = mapNapiError(raw);
    expect(mapped).toBeInstanceOf(NoDefaultCommandError);
    expect((mapped as NoDefaultCommandError).code).toBe("noDefaultCommand");
    expect((mapped as MicrosandboxError).cause).toBe(raw);
  });

  it("maps stale sandbox identities to SandboxReplacedError", () => {
    const raw = new Error(
      "[SandboxReplaced] sandbox worker was replaced (expected local:1, found local:2)",
    );
    const mapped = mapNapiError(raw);
    expect(mapped).toBeInstanceOf(SandboxReplacedError);
    expect((mapped as SandboxReplacedError).code).toBe("sandboxReplaced");
    expect((mapped as MicrosandboxError).cause).toBe(raw);
  });
});
