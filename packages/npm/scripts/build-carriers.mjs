#!/usr/bin/env node
// Assemble the six platform carrier packages from a validated release.
//
//   node scripts/build-carriers.mjs --artifacts <dir> --manifest <path> --out <dir>
//
// The artifacts directory holds the downloaded release-* GitHub artifacts
// (archive + .sha256 per target). Every archive's SHA-256 is recomputed and
// checked against the release manifest BEFORE extraction — the manifest stays
// the single publication contract (ADR-025 §1, ADR-034 D5). Carriers carry the
// extracted binary plus a package.json whose version equals the release; the
// entry package pins them exactly.

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import process from "node:process";

const TARGETS = {
  "aarch64-apple-darwin": { carrier: "@sylin-org/koi-darwin-arm64", os: "darwin", cpu: "arm64", binary: "koi" },
  "x86_64-apple-darwin": { carrier: "@sylin-org/koi-darwin-x64", os: "darwin", cpu: "x64", binary: "koi" },
  "aarch64-unknown-linux-musl": { carrier: "@sylin-org/koi-linux-arm64", os: "linux", cpu: "arm64", binary: "koi" },
  "x86_64-unknown-linux-musl": { carrier: "@sylin-org/koi-linux-x64", os: "linux", cpu: "x64", binary: "koi" },
  "aarch64-pc-windows-msvc": { carrier: "@sylin-org/koi-win32-arm64", os: "win32", cpu: "arm64", binary: "koi.exe" },
  "x86_64-pc-windows-msvc": { carrier: "@sylin-org/koi-win32-x64", os: "win32", cpu: "x64", binary: "koi.exe" },
};

function parseArgs(argv) {
  const options = { artifacts: "artifacts", out: "packages/npm-carriers" };
  for (let index = 2; index < argv.length; index += 2) {
    const key = argv[index]?.replace(/^--/, "");
    const value = argv[index + 1];
    if (!value) throw new Error(`missing value for --${key}`);
    if (key === "artifacts") options.artifacts = value;
    else if (key === "manifest") options.manifest = value;
    else if (key === "out") options.out = value;
    else throw new Error(`unknown option --${key}`);
  }
  if (!options.manifest) throw new Error("--manifest is required");
  return options;
}

function sha256File(file) {
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

function findArchive(dir, tag, target) {
  const files = readdirSync(dir);
  return files.find((name) => name === `koi-${tag}-${target}.tar.gz`)
    ?? files.find((name) => name === `koi-${tag}-${target}.zip`);
}

function extract(archivePath, scratch) {
  mkdirSync(scratch, { recursive: true });
  if (archivePath.endsWith(".zip")) {
    execFileSync("unzip", ["-q", "-o", archivePath, "-d", scratch]);
  } else {
    execFileSync("tar", ["-xzf", archivePath, "-C", scratch]);
  }
}

function findBinary(dir, binaryName) {
  const found = [];
  const walk = (current) => {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name === binaryName) found.push(full);
    }
  };
  walk(dir);
  return found;
}

const options = parseArgs(process.argv);
const manifest = JSON.parse(readFileSync(options.manifest, "utf8"));
const entry = JSON.parse(readFileSync(path.resolve("packages/npm/package.json"), "utf8"));

if (manifest.version !== entry.version || manifest.tag !== `v${manifest.version}`) {
  throw new Error(
    `entry package ${entry.version} does not match release manifest ${manifest.version}`,
  );
}
for (const target of Object.keys(TARGETS)) {
  if (!/^[a-f0-9]{64}$/.test(manifest.artifacts?.[target]?.sha256 ?? "")) {
    throw new Error(`release manifest lacks a valid digest for ${target}`);
  }
}

rmSync(options.out, { recursive: true, force: true });

for (const [target, spec] of Object.entries(TARGETS)) {
  const expectedDigest = manifest.artifacts[target].sha256;
  const archiveDir = path.join(options.artifacts, `release-${target}`);
  if (!existsSync(archiveDir)) throw new Error(`missing downloaded artifact directory ${archiveDir}`);

  const archiveName = findArchive(archiveDir, manifest.tag, target);
  if (!archiveName) throw new Error(`no release archive for ${target} under ${archiveDir}`);
  const archivePath = path.join(archiveDir, archiveName);

  const actualDigest = sha256File(archivePath);
  if (actualDigest !== expectedDigest) {
    throw new Error(
      `${target} archive digest mismatch: manifest says ${expectedDigest}, bytes are ${actualDigest}`,
    );
  }

  const scratch = path.join(options.out, ".scratch", target);
  extract(archivePath, scratch);
  const binaries = findBinary(scratch, spec.binary);
  if (binaries.length !== 1) {
    throw new Error(`expected one '${spec.binary}' in the ${target} archive; found ${binaries.length}`);
  }

  const carrierRoot = path.join(options.out, spec.carrier);
  mkdirSync(path.join(carrierRoot, "bin"), { recursive: true });
  copyFileSync(binaries[0], path.join(carrierRoot, "bin", spec.binary));
  rmSync(path.join(options.out, ".scratch"), { recursive: true, force: true });

  writeFileSync(
    path.join(carrierRoot, "package.json"),
    `${JSON.stringify(
      {
        name: spec.carrier,
        version: manifest.version,
        description: `Koi native binary for ${target} (carried by @sylin-org/koi)`,
        license: "MIT OR Apache-2.0",
        repository: { type: "git", url: "git+https://github.com/sylin-org/koi.git" },
        engines: { node: ">=18" },
        os: [spec.os],
        cpu: [spec.cpu],
        files: ["bin"],
        publishConfig: { access: "public" },
      },
      null,
      2,
    )}\n`,
  );
  process.stdout.write(`carrier ${spec.carrier}@${manifest.version} ready (${actualDigest.slice(0, 12)}…)\n`);
}

process.stdout.write(`six carriers assembled under ${options.out}\n`);
