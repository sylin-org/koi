#!/usr/bin/env node

// Thin composition root: resolve this package's carried binary and exec it.
// All decisions live in lib/launcher.js; see its header for the placement law.

import path from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(import.meta.url);

try {
  const exitCode = await import("../lib/launcher.js").then(({ runLauncher }) =>
    runLauncher({
      args: process.argv.slice(2),
      packageRoot,
      require,
      spawnProcess: (command, args, options) =>
        new Promise((resolve) => {
          const child = spawnSync(command, args, { ...options, stdio: "inherit" });
          if (child.error) throw child.error;
          resolve(child.status ?? 1);
        }),
    }),
  );
  process.exitCode = exitCode;
} catch (error) {
  process.stderr.write(`koi: error: ${error.message}\n`);
  process.exitCode = 1;
}
