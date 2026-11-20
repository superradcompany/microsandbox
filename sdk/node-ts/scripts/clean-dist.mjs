import { rmSync } from "node:fs";

// Removed source modules must not survive in a later npm archive as stale exports.
rmSync(new URL("../dist", import.meta.url), { recursive: true, force: true });
