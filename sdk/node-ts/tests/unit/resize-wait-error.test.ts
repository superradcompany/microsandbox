import { describe, expect, it } from "vitest";
import { ResizeWaitError, RuntimeError } from "../../dist/errors.js";
import { mapNapiError } from "../../dist/internal/error-mapping.js";

describe("resize wait errors", () => {
  it("retains structured outcomes and the native cause", () => {
    const source = new Error('[ResizeWait] '+JSON.stringify({reason:"history_unavailable", sandbox:"box", operation_id:"old", status:[], message:"missing history"}));
    const error = mapNapiError(source) as ResizeWaitError;
    expect(error).toBeInstanceOf(ResizeWaitError);
    expect(error.reason).toBe("history_unavailable");
    expect(error.operationId).toBe("old");
    expect(error.sandbox).toBe("box");
    expect(error.status).toEqual([]);
    expect(error.cause).toBe(source);
  });
  it("does not invent a known outcome from unknown or malformed payloads", () => {
    for (const payload of ["invalid", JSON.stringify({reason:"future",sandbox:null,operation_id:null,status:[],message:"future"})]) {
      const error=mapNapiError(new Error('[ResizeWait] '+payload));
      expect(error).toBeInstanceOf(RuntimeError);
      expect(error).not.toBeInstanceOf(ResizeWaitError);
    }
  });
});
