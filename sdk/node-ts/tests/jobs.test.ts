import { describe, expect, it } from "vitest";
import { Job, JobAttachment, JobError, JobListBuilder, jobCall, jobPageFromJson } from "../dist/jobs.js";
import type { NapiJob, NapiJobAttachment } from "../dist/internal/napi.js";

describe("managed job boundary", () => {
  it("preserves byte output and scoped replay cursors", async () => {
    const native = { id: "job_123", logs: async () => JSON.stringify([{ timestamp: 1, source: "stdout", data_base64: "/wAK", cursor: "job_123:1" }]) } as unknown as NapiJob;
    const job = new Job(native);
    expect((await job.logs())[0]?.data).toEqual(Buffer.from([255, 0, 10]));
    expect((await job.logs())[0]?.cursor).toBe("job_123:1");
  });
  it("async disposal detaches without issuing EOF or kill", async () => {
    let detached = 0;
    const native = { detach: async () => { detached++; } } as unknown as NapiJobAttachment;
    await new JobAttachment(native)[Symbol.asyncDispose]();
    expect(detached).toBe(1);
  });
  it("retains the job ID on an uncertain launch", async () => {
    await expect(jobCall(async () => { throw new Error('[Job] {"code":"launch_unconfirmed","message":"inspect first","jobId":"job_123"}'); })).rejects.toMatchObject(new JobError("launch_unconfirmed", "inspect first", "job_123"));
  });
  it("converts pagination and uses active-only defaults", () => {
    expect(new JobListBuilder().includeAll).toBe(false);
    expect(jobPageFromJson('{"items":[],"next_cursor":"job_next"}').nextCursor).toBe("job_next");
  });
});
