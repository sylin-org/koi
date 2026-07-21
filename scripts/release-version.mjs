#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import path from "node:path";

// SemVer 2.0 without build metadata. Public Koi releases need one canonical
// identity across Cargo, Git tags, npm, GHCR, and release artifact names; build
// metadata is intentionally excluded because registries may ignore it when
// deciding whether two versions are identical.
const RELEASE_VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?$/;

export function releaseMetadata(value) {
  const supplied = String(value ?? "");
  const version = supplied.replace(/^v/, "");
  const match = RELEASE_VERSION.exec(version);
  if (!match) {
    throw new Error(
      `version must be SemVer without build metadata and may have one leading v; got '${supplied}'`,
    );
  }

  const prerelease = match[4] !== undefined;
  return Object.freeze({
    version,
    tag: `v${version}`,
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    prerelease,
    npmTag: prerelease ? "next" : "latest",
    cargoRequirement: prerelease ? version : `${match[1]}.${match[2]}`,
  });
}

export function workspaceReleaseMetadata(cargoToml) {
  const workspacePackage = String(cargoToml).match(
    /(?:^|\r?\n)\[workspace\.package\]\s*\r?\n([\s\S]*?)(?=\r?\n\[|$)/,
  );
  if (!workspacePackage) {
    throw new Error("Cargo.toml has no [workspace.package] section");
  }
  const version = workspacePackage[1].match(/^\s*version\s*=\s*"([^"]+)"\s*$/m);
  if (!version) {
    throw new Error("Cargo.toml [workspace.package] has no version");
  }
  return releaseMetadata(version[1]);
}

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const key = argv[index];
    if (!key?.startsWith("--")) {
      throw new Error("usage: release-version.mjs [--version X.Y.Z | --cargo Cargo.toml]");
    }
    const value = argv[index + 1];
    if (value === undefined || value.startsWith("--")) {
      throw new Error(`missing value for ${key}`);
    }
    options[key.slice(2)] = value;
    index += 1;
  }
  if (options.version && options.cargo) {
    throw new Error("use either --version or --cargo, not both");
  }
  return options;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const metadata = options.version
    ? releaseMetadata(options.version)
    : workspaceReleaseMetadata(await readFile(options.cargo ?? "Cargo.toml", "utf8"));

  process.stdout.write(`${JSON.stringify(metadata)}\n`);
}

if (path.basename(process.argv[1] ?? "") === "release-version.mjs") {
  main().catch((error) => {
    process.stderr.write(`release version: ${error.message}\n`);
    process.exitCode = 1;
  });
}
