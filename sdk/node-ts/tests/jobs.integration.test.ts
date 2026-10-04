import { describe, expect, it } from "vitest";
import { Sandbox, JobError, type Job, type JobAttachment } from "../src/index.js";

describe.skipIf(!process.env.MSB_HOME || !process.env.MSB_JOB_TEST_SANDBOX)("managed jobs on a disposable VM", () => {
  it("preserves ownership and binary I/O across detach, and cancels an idle log stream", async () => {
    const sb = await (await Sandbox.get(process.env.MSB_JOB_TEST_SANDBOX!)).connect();
    const jobs: Job[] = [];
    const attachments: JobAttachment[] = [];
    try {
      const job = await sb.execDetached("cat");
      jobs.push(job);
      const first = await job.attach();
      attachments.push(first);
      await expect(job.attach()).rejects.toMatchObject({ name: "JobError", code: "input_busy" });
      await first.writeStdin(Buffer.from([255, 0, 10]));
      expect(await first.recv()).toMatchObject({ type: "output", value: { data: Buffer.from([255, 0, 10]) } });
      await first.detach();
      const found = await sb.getJob(job.id);
      const second = await found.attach();
      attachments.push(second);
      await second.writeStdin(Buffer.from("reattached\n"));
      await found.eof();
      expect((await found.wait()).success).toBe(true);
      await second.detach();
      expect(Buffer.concat((await found.logs()).map(x => x.data))).toEqual(Buffer.concat([Buffer.from([255, 0, 10]), Buffer.from("reattached\n")]));
      let cursor: string | null = null;
      for (;;) {
        const page = await sb.listJobsWith(b => cursor ? b.all().cursor(cursor) : b.all());
        if (page.items.some(x => x.id === job.id)) break;
        expect(page.nextCursor, "job missing from retained history").not.toBeNull();
        cursor = page.nextCursor;
      }

      const sleepy = await sb.execDetached("sleep", ["30"]);
      jobs.push(sleepy);
      const stream = await sleepy.followLogs();
      const pending = stream.next();
      await stream.close();
      expect(await pending).toBe(null);
    } finally {
      for (const attachment of attachments) await attachment.detach().catch(() => {});
      for (const job of jobs) {
        await job.kill().catch(error => { if (!(error instanceof JobError)) throw error; });
        await job.wait();
      }
    }
  }, 20_000);
});
