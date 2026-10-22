import type { SnapshotVerifyReport, SnapshotVerifyCoverage } from "./snapshot.js";

export type SnapshotVerificationState = "complete" | "incomplete" | "invalid" | "empty";
export type SnapshotVerificationFindingKind = "missing" | "invalid" | "unavailable" | "changed" | "unsupported" | "not_recorded";

export interface SnapshotVerificationFinding {
  readonly path: string;
  readonly kind: SnapshotVerificationFindingKind;
  readonly detail: string;
}

export interface CheckpointVerification {
  readonly id: string | null;
  readonly path: string;
  readonly state: Exclude<SnapshotVerificationState, "empty">;
  readonly report: SnapshotVerifyReport | null;
  readonly findings: readonly SnapshotVerificationFinding[];
}

export interface SnapshotGroupVerifyReport {
  readonly group: string;
  readonly state: SnapshotVerificationState;
  readonly checkpoints: readonly CheckpointVerification[];
  readonly payloadHashes: number;
}

/** @internal Reject unknown projections instead of inferring successful verification. */
export function parseGroupVerification(value: unknown): SnapshotGroupVerifyReport {
  const wire = object(value);
  const state = choice(wire.state, ["complete", "incomplete", "invalid", "empty"] as const);
  if (typeof wire.payload_hashes !== "number" || !Number.isSafeInteger(wire.payload_hashes) || wire.payload_hashes < 0) fail();
  return {
    group: text(wire.group), state, payloadHashes: wire.payload_hashes as number,
    checkpoints: array(wire.checkpoints).map(value => {
      const member = object(value);
      return {
        id: member.id === null ? null : text(member.id), path: text(member.path),
        state: choice(member.state, ["complete", "incomplete", "invalid"] as const),
        report: member.report === null ? null : artifactReport(member.report),
        findings: array(member.findings).map(value => {
          const finding = object(value);
          return { path: text(finding.path), detail: text(finding.detail),
            kind: choice(finding.kind, ["missing", "invalid", "unavailable", "changed", "unsupported", "not_recorded"] as const) };
        }),
      };
    }),
  };
}

function artifactReport(value: unknown): SnapshotVerifyReport {
  const report = object(value);
  const rawCoverage = object(report.coverage);
  const kind = choice(rawCoverage.kind, ["complete", "incomplete"] as const);
  let coverage: SnapshotVerifyCoverage = { kind: "complete" };
  if (kind === "incomplete") {
    const unrecorded = array(rawCoverage.unrecorded).map(text);
    if (!unrecorded.length) fail();
    coverage = { kind, unrecorded };
  }
  const upper = object(report.upper);
  const upperKind = choice(upper.kind, ["not_recorded", "verified"] as const);
  const checkpoint = report.checkpoint === null ? undefined : { kind: "verified" as const, root: text(object(report.checkpoint).root) };
  const common = { digest: text(report.digest), path: text(report.path), coverage,
    ...(checkpoint === undefined ? {} : { checkpoint }),
  };
  return upperKind === "not_recorded"
    ? { ...common, upper: { kind: "notRecorded" } }
    : { ...common, upper: { kind: "verified", algorithm: text(upper.algorithm), digest: text(upper.digest) } };
}

function fail(): never { throw new Error("invalid native snapshot group verification report"); }
function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return fail();
  return value as Record<string, unknown>;
}
function text(value: unknown): string { return typeof value === "string" ? value : fail(); }
function array(value: unknown): unknown[] { return Array.isArray(value) ? value : fail(); }
function choice<T extends string>(value: unknown, choices: readonly T[]): T {
  return typeof value === "string" && (choices as readonly string[]).includes(value) ? value as T : fail();
}
