#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";

import { RELEASE_TARGETS } from "./release-manifest.mjs";

export const REQUIRED_HOSTED_CHECKS = Object.freeze([
  "prepare",
  "test",
  "build",
  "finalize-windows",
  "channels",
]);

export const REQUIRED_NATIVE_EVIDENCE = Object.freeze([
  "windows",
  "cachyos-linux",
  "bluefin-linux",
  "alpine-linux",
  "debian-linux",
]);

const REPOSITORY = "https://github.com/sylin-org/koi";
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function resultMap(results, key) {
  if (!Array.isArray(results)) return new Map();
  return new Map(results.map((result) => [result?.[key], result]));
}

function hostedEvidence(results, runUrl, blockers) {
  const byName = resultMap(results, "name");
  return REQUIRED_HOSTED_CHECKS.map((name) => {
    const status = byName.get(name)?.status ?? "missing";
    if (status !== "success") blockers.push(`hosted check ${name}: ${status}`);
    return { name, status, url: runUrl };
  });
}

function nativeEvidence(results, sourceSha, blockers) {
  const byPlatform = resultMap(results, "platform");
  return REQUIRED_NATIVE_EVIDENCE.map((platform) => {
    const supplied = byPlatform.get(platform);
    const evidence = supplied ?? {
      platform,
      status: "pending",
      sourceSha: null,
      artifactSha256: null,
      url: null,
    };
    if (evidence.status !== "success") {
      blockers.push(`native evidence ${platform}: ${evidence.status ?? "missing"}`);
    } else {
      if (evidence.sourceSha !== sourceSha) {
        blockers.push(`native evidence ${platform}: source SHA mismatch`);
      }
      if (!DIGEST_PATTERN.test(evidence.artifactSha256 ?? "")) {
        blockers.push(`native evidence ${platform}: invalid artifact SHA-256`);
      }
      if (typeof evidence.url !== "string" || evidence.url.length === 0) {
        blockers.push(`native evidence ${platform}: missing evidence link`);
      }
    }
    return evidence;
  });
}

function validateManifest(manifest, blockers) {
  if (manifest?.schemaVersion !== 1) blockers.push("artifact manifest: unsupported schema");
  if (manifest?.repository !== REPOSITORY) blockers.push("artifact manifest: wrong repository");
  for (const target of RELEASE_TARGETS) {
    const artifact = manifest?.artifacts?.[target];
    if (!artifact) {
      blockers.push(`artifact manifest: missing ${target}`);
    } else if (!DIGEST_PATTERN.test(artifact.sha256 ?? "")) {
      blockers.push(`artifact manifest: invalid digest for ${target}`);
    }
  }
}

export function buildCandidateValidation({
  sourceSha,
  runUrl,
  manifest,
  manifestBytes,
  manifestFile,
  hostedResults,
  nativeResults = [],
}) {
  const infrastructureBlockers = [];
  if (!SHA_PATTERN.test(sourceSha ?? "")) {
    infrastructureBlockers.push("source: expected an exact 40-character Git SHA");
  }
  if (typeof runUrl !== "string" || runUrl.length === 0) {
    infrastructureBlockers.push("hosted evidence: missing workflow run link");
  }
  validateManifest(manifest, infrastructureBlockers);

  const hosted = hostedEvidence(hostedResults, runUrl, infrastructureBlockers);
  const candidateBlockers = [...infrastructureBlockers];
  const native = nativeEvidence(nativeResults, sourceSha, candidateBlockers);
  const infrastructurePassed = infrastructureBlockers.length === 0;

  return {
    schemaVersion: 1,
    sources: [{ repository: REPOSITORY, sha: sourceSha }],
    artifactManifest: {
      file: path.basename(manifestFile),
      sha256: sha256(manifestBytes),
      schemaVersion: manifest?.schemaVersion ?? null,
      version: manifest?.version ?? null,
      tag: manifest?.tag ?? null,
      targets: RELEASE_TARGETS.map((target) => ({
        target,
        sha256: manifest?.artifacts?.[target]?.sha256 ?? null,
      })),
    },
    hostedEvidence: hosted,
    nativeEvidence: native,
    previewTargets: [
      {
        targets: ["aarch64-apple-darwin", "x86_64-apple-darwin"],
        qualification: "build-only; macOS physical support remains unverified",
      },
    ],
    verdict: {
      infrastructure: infrastructurePassed ? "passed" : "failed",
      candidate: candidateBlockers.length === 0 ? "accepted" : "pending",
      blockers: candidateBlockers,
    },
  };
}

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith("--") || value === undefined) {
      throw new Error(
        "usage: candidate-validation.mjs --source-sha SHA --manifest FILE --hosted-results FILE --run-url URL --output FILE [--native-evidence FILE]",
      );
    }
    options[key.slice(2)] = value;
  }
  for (const required of ["source-sha", "manifest", "hosted-results", "run-url", "output"]) {
    if (!options[required]) throw new Error(`missing --${required}`);
  }
  return options;
}

async function readJson(file) {
  return JSON.parse(await readFile(file, "utf8"));
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const manifestBytes = await readFile(options.manifest);
  const report = buildCandidateValidation({
    sourceSha: options["source-sha"],
    runUrl: options["run-url"],
    manifest: JSON.parse(manifestBytes),
    manifestBytes,
    manifestFile: options.manifest,
    hostedResults: await readJson(options["hosted-results"]),
    nativeResults: options["native-evidence"] ? await readJson(options["native-evidence"]) : [],
  });
  await writeFile(options.output, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  process.stdout.write(`candidate validation: ${options.output}\n`);
  if (report.verdict.infrastructure !== "passed") process.exitCode = 1;
}

if (path.basename(process.argv[1] ?? "") === "candidate-validation.mjs") {
  main().catch((error) => {
    process.stderr.write(`candidate validation: ${error.message}\n`);
    process.exitCode = 1;
  });
}
