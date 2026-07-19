#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { runBootstrap } from "../lib/bootstrap.js";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

try {
  const manifest = JSON.parse(
    await readFile(path.join(packageRoot, "release-manifest.json"), "utf8"),
  );
  const exitCode = await runBootstrap({ manifest, args: process.argv.slice(2) });
  process.exitCode = exitCode;
} catch (error) {
  process.stderr.write(`koi: error: ${error.message}\n`);
  process.exitCode = 1;
}
