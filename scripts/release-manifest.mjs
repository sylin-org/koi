#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile, stat, writeFile } from "node:fs/promises";
import path from "node:path";

import { releaseMetadata } from "./release-version.mjs";

export const RELEASE_TARGETS = Object.freeze([
  "aarch64-apple-darwin",
  "aarch64-pc-windows-msvc",
  "aarch64-unknown-linux-musl",
  "x86_64-apple-darwin",
  "x86_64-pc-windows-msvc",
  "x86_64-unknown-linux-musl",
]);

const REPOSITORY = "https://github.com/sylin-org/koi";

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

async function fileSha256(file) {
  return sha256(await readFile(file));
}

function archiveName(version, target) {
  const suffix = target.includes("windows") ? ".zip" : ".tar.gz";
  return `koi-v${version}-${target}${suffix}`;
}

async function readSidecar(sidecar, archive) {
  const fields = (await readFile(sidecar, "utf8")).trim().split(/\s+/);
  const digest = fields[0]?.toLowerCase();
  const namedFile = fields.at(-1)?.replace(/^\*/, "");
  if (!/^[a-f0-9]{64}$/.test(digest ?? "")) {
    throw new Error(`${path.basename(sidecar)} does not start with a SHA-256 digest`);
  }
  if (namedFile && path.basename(namedFile) !== archive) {
    throw new Error(`${path.basename(sidecar)} names '${namedFile}', expected '${archive}'`);
  }
  return digest;
}

export async function buildReleaseManifest({
  version: rawVersion,
  artifactsDir,
  installSh = "install.sh",
  installPs1 = "install.ps1",
}) {
  const { version, tag } = releaseMetadata(rawVersion);
  const artifacts = {};

  for (const target of RELEASE_TARGETS) {
    const archive = archiveName(version, target);
    const archivePath = path.join(artifactsDir, archive);
    const sidecarPath = `${archivePath}.sha256`;
    const expected = await readSidecar(sidecarPath, archive);
    const actual = await fileSha256(archivePath);
    if (expected !== actual) {
      throw new Error(`${archive} checksum mismatch: sidecar ${expected}, archive ${actual}`);
    }

    artifacts[target] = {
      archive,
      sha256: actual,
      size: (await stat(archivePath)).size,
      url: `${REPOSITORY}/releases/download/${tag}/${archive}`,
    };
  }

  const installerEntries = [
    ["posix", installSh],
    ["windows", installPs1],
  ];
  const installers = {};
  for (const [name, file] of installerEntries) {
    const filename = path.basename(file);
    installers[name] = {
      path: filename,
      sha256: await fileSha256(file),
      url: `https://raw.githubusercontent.com/sylin-org/koi/${tag}/${filename}`,
    };
  }

  return {
    schemaVersion: 1,
    project: "koi",
    version,
    tag,
    repository: REPOSITORY,
    installers,
    artifacts,
  };
}

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith("--") || value === undefined) {
      throw new Error("usage: release-manifest.mjs --version X.Y.Z --artifacts DIR --output FILE");
    }
    options[key.slice(2)] = value;
  }
  for (const required of ["version", "artifacts", "output"]) {
    if (!options[required]) throw new Error(`missing --${required}`);
  }
  return options;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const manifest = await buildReleaseManifest({
    version: options.version,
    artifactsDir: options.artifacts,
    installSh: options["install-sh"] ?? "install.sh",
    installPs1: options["install-ps1"] ?? "install.ps1",
  });
  await writeFile(options.output, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  process.stdout.write(`release manifest: ${options.output}\n`);
}

// Compare the entrypoint name rather than file URLs: this repository is commonly
// reached through a Windows junction, so equivalent paths need not stringify alike.
if (path.basename(process.argv[1] ?? "") === "release-manifest.mjs") {
  main().catch((error) => {
    process.stderr.write(`release manifest: ${error.message}\n`);
    process.exitCode = 1;
  });
}
