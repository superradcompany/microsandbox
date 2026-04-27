import { describe, expect, it } from "vitest";
import {
  ExecTimeoutError,
  ImageNotFoundError,
  MicrosandboxError,
  SandboxNotFoundError,
} from "../../dist/index.js";
import { mapNapiError } from "../../dist/internal/error-mapping.js";

describe("mapNapiError", () => {
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

  it("passes through plain Error messages", () => {
    const raw = new Error("not a tagged error");
    expect(mapNapiError(raw)).toBe(raw);
  });

  it("dispatches across all common variants", () => {
    expect(mapNapiError(new Error("[ImageNotFound] python:3.12"))).toBeInstanceOf(
      ImageNotFoundError,
    );
  });
});
