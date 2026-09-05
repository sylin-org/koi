import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  buildCandidateValidation,
  REQUIRED_HOSTED_CHECKS,
  REQUIRED_NATIVE_EVIDENCE,
} from "./candidate-validation.mjs";
import { RELEASE_TARGETS } from "./release-manifest.mjs";

const SOURCE_SHA = "a".repeat(40);
const ARTIFACT_SHA = "b".repeat(64);
const RUN_URL = "https://github.com/sylin-org/koi/actions/runs/123";

function manifest() {
  return {
    schemaVersion: 1,
    repository: "https://github.com/sylin-org/koi",
    version: "1.0.0-rc.3",
    tag: "v1.0.0-rc.3",
    artifacts: Object.fromEntries(
      RELEASE_TARGETS.map((target) => [target, { sha256: ARTIFACT_SHA }]),
    ),
  };
}

function build(overrides = {}) {
  const value = manifest();
  const manifestBytes = Buffer.from(`${JSON.stringify(value)}\n`);
  return buildCandidateValidation({
    sourceSha: SOURCE_SHA,
    runUrl: RUN_URL,
    manifest: value,
    manifestBytes,
    manifestFile: "artifacts/koi-v1.0.0-rc.3-manifest.json",
    hostedResults: REQUIRED_HOSTED_CHECKS.map((name) => ({ name, status: "success" })),
    nativeResults: [],
    ...overrides,
  });
}

test("records an exact source, manifest, hosted run, and qualified preview targets", () => {
  const report = build();
  assert.equal(report.sources[0].sha, SOURCE_SHA);
  assert.equal(
    report.artifactManifest.sha256,
    createHash("sha256").update(`${JSON.stringify(manifest())}\n`).digest("hex"),
  );
  assert.deepEqual(
    report.hostedEvidence.map(({ name }) => name),
    REQUIRED_HOSTED_CHECKS,
  );
  assert.match(report.previewTargets[0].qualification, /build-only.*unverified/);
  assert.equal(report.verdict.infrastructure, "passed");
  assert.equal(report.verdict.candidate, "pending");
  assert.equal(report.nativeEvidence.every(({ status }) => status === "pending"), true);
});

test("a missing, skipped, or failed hosted job rejects infrastructure", () => {
  for (const status of ["missing", "skipped", "failure"]) {
    const hostedResults = REQUIRED_HOSTED_CHECKS.filter(
      (name) => status !== "missing" || name !== "channels",
    ).map((name) => ({ name, status: name === "channels" ? status : "success" }));
    const report = build({ hostedResults });
    assert.equal(report.verdict.infrastructure, "failed");
    assert.match(report.verdict.blockers.join("\n"), /hosted check channels/);
  }
});

test("an incompatible manifest fails and the corrected contract passes", () => {
  const incompatible = manifest();
  delete incompatible.artifacts[RELEASE_TARGETS[0]];
  const failed = build({
    manifest: incompatible,
    manifestBytes: Buffer.from(JSON.stringify(incompatible)),
  });
  assert.equal(failed.verdict.infrastructure, "failed");
  assert.match(failed.verdict.blockers.join("\n"), /artifact manifest: missing/);
  assert.equal(build().verdict.infrastructure, "passed");
});

test("candidate acceptance requires linked native evidence for the same source", () => {
  const nativeResults = REQUIRED_NATIVE_EVIDENCE.map((platform) => ({
    platform,
    status: "success",
    sourceSha: SOURCE_SHA,
    artifactSha256: ARTIFACT_SHA,
    url: `fleet/${platform}/journal.md`,
  }));
  assert.equal(build({ nativeResults }).verdict.candidate, "accepted");

  nativeResults[0] = { ...nativeResults[0], sourceSha: "c".repeat(40) };
  const mismatched = build({ nativeResults });
  assert.equal(mismatched.verdict.candidate, "pending");
  assert.match(mismatched.verdict.blockers.join("\n"), /source SHA mismatch/);
});
