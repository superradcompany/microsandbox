/** Exercise the candidate npm packages against production before publishing. */
import { setTimeout as sleep } from "node:timers/promises";
import { pathToFileURL } from "node:url";

export type SmokeSdk = Pick<typeof import("microsandbox"), "Sandbox" | "SandboxNotFoundError">;
export const MARKER = "microsandbox-release-smoke-ok";

export async function exercise(sdk: SmokeSdk, name: string): Promise<void> {
  const sandbox = await sdk.Sandbox.builder(name)
    .image("mirror.gcr.io/library/alpine:3.20")
    .cpus(1)
    .memory(512)
    .ephemeral(true)
    .maxDuration(600)
    .idleTimeout(120)
    .create();
  const output = await sandbox.shell(`printf '${MARKER}\\n'`);
  if (output.code !== 0 || output.stdout() !== `${MARKER}\n`) {
    throw new Error("Candidate SDK command returned unexpected exit status or output");
  }
  console.log("Production create and command execution passed");
}

export async function cleanup(
  sdk: SmokeSdk,
  name: string,
  pause: (ms: number) => Promise<void> = sleep,
): Promise<void> {
  try {
    const handle = await sdk.Sandbox.get(name);
    await handle.destroy({ timeoutMs: 120_000 });
  } catch (error) {
    // Ephemeral stop may already have removed the sandbox.
    if (!(error instanceof sdk.SandboxNotFoundError)) throw error;
  }
  // A successful delete response alone is not proof of removal.
  for (let attempt = 0; attempt < 15; attempt++) {
    try {
      await sdk.Sandbox.get(name);
    } catch (error) {
      if (!(error instanceof sdk.SandboxNotFoundError)) throw error;
      console.log("Production sandbox cleanup confirmed");
      return;
    }
    await pause(2_000);
  }
  throw new Error(`Smoke sandbox still exists after cleanup: ${name}`);
}

async function main(): Promise<void> {
  const action = process.argv[2];
  if (action !== "run" && action !== "cleanup") throw new Error("Expected run or cleanup");
  const apiKey = process.env.MSB_API_KEY;
  if (!apiKey?.trim()) throw new Error("Set the GitHub repository secret MSB_API_KEY");
  if (process.env.MSB_BACKEND !== "cloud" || process.env.MSB_API_URL !== "https://api.microsandbox.dev") {
    throw new Error("Smoke test requires MSB_BACKEND=cloud and MSB_API_URL=https://api.microsandbox.dev");
  }
  const name = process.env.MSB_SMOKE_SANDBOX_NAME ?? "";
  if (!/^release-smoke-[0-9]+-[0-9]+$/.test(name)) {
    throw new Error("MSB_SMOKE_SANDBOX_NAME must be release-smoke-<run-id>-<attempt>");
  }
  // Hard deadline also stops hung native operations. The workflow runs cleanup
  // in a separate process even when this process fails or times out.
  const deadline = setTimeout(() => {
    console.error(`Production smoke ${action} timed out`);
    process.exit(1);
  }, action === "run" ? 300_000 : 180_000);
  try {
    // Resolve the installed candidate package, never a source-tree native override.
    const sdk = await import("microsandbox");
    console.log(`Production sandbox ${name}; action ${action}`);
    if (action === "run") await exercise(sdk, name);
    else await cleanup(sdk, name);
  } finally {
    clearTimeout(deadline);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().then(() => process.exit(0), (error: unknown) => {
    console.error(error);
    process.exit(1);
  });
}
