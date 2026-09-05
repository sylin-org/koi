import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { releaseMetadata, workspaceReleaseMetadata } from "./release-version.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("classifies stable releases as public defaults", () => {
  assert.deepEqual(releaseMetadata("1.2.3"), {
    version: "1.2.3",
    tag: "v1.2.3",
    major: 1,
    minor: 2,
    patch: 3,
    prerelease: false,
    npmTag: "latest",
    cargoRequirement: "1.2",
  });
});

test("classifies release candidates as opt-in prereleases", () => {
  assert.deepEqual(releaseMetadata("v1.0.0-rc.1"), {
    version: "1.0.0-rc.1",
    tag: "v1.0.0-rc.1",
    major: 1,
    minor: 0,
    patch: 0,
    prerelease: true,
    npmTag: "next",
    cargoRequirement: "1.0.0-rc.1",
  });
});

test("reads only the workspace package version", () => {
  const cargo = `
[workspace]
members = ["crates/example"]

[workspace.package]
version = "1.0.0-rc.2"
edition = "2024"

[workspace.dependencies]
example = { version = "99.0.0" }
`;
  assert.equal(workspaceReleaseMetadata(cargo).version, "1.0.0-rc.2");
});

test("rejects ambiguous or noncanonical public versions", () => {
  for (const invalid of [
    "1.0",
    "01.0.0",
    "1.0.0-01",
    "1.0.0-",
    "1.0.0+build.1",
    "vv1.0.0",
  ]) {
    assert.throws(() => releaseMetadata(invalid), /version must be SemVer/);
  }
});

test("all publication channels check the centralized release decision", async () => {
  const [bump, release, ciWorkflow, releaseWorkflow, publishWorkflow] = await Promise.all([
    readFile(path.join(root, "scripts/bump-version.ps1"), "utf8"),
    readFile(path.join(root, "scripts/release.ps1"), "utf8"),
    readFile(path.join(root, ".github/workflows/ci.yml"), "utf8"),
    readFile(path.join(root, ".github/workflows/release.yml"), "utf8"),
    readFile(path.join(root, ".github/workflows/publish.yml"), "utf8"),
  ]);

  assert.match(bump, /release-version\.mjs --cargo Cargo\.toml/);
  assert.match(bump, /release-version\.mjs --version \$NewVersion/);
  assert.match(release, /release-version\.mjs --cargo Cargo\.toml/);
  assert.match(releaseWorkflow, /GITHUB_REF_NAME.*!=.*\$TAG/);
  assert.match(releaseWorkflow, /--prerelease --latest=false/);
  assert.match(releaseWorkflow, /flavor: latest=false/);
  assert.match(releaseWorkflow, /npm publish --access public --tag/);
  assert.match(publishWorkflow, /release-version\.mjs --cargo Cargo\.toml/);
  assert.match(publishWorkflow, /crates\/\$\{pkg_name\}\/\$\{VERSION\}/);

  assert.match(ciWorkflow, /branches: \[main, dev\]/);
  for (const contract of [
    "packages/ts/test/client.test.js",
    "packages/npm/test/launcher.test.js",
    "scripts/release-version.test.mjs",
    "scripts/release-manifest.test.mjs",
    "scripts/candidate-validation.test.mjs",
  ]) {
    assert.match(ciWorkflow, new RegExp(contract.replaceAll(".", "\\.")));
    assert.match(releaseWorkflow, new RegExp(contract.replaceAll(".", "\\.")));
  }
  assert.doesNotMatch(publishWorkflow, /workflow_dispatch/);
  assert.match(releaseWorkflow, /permissions:\s+contents: read/);
  assert.match(releaseWorkflow, /candidate-summary:[\s\S]*github\.event_name == 'workflow_dispatch'/);
  for (const job of ["release", "docker", "publish-crates", "publish-npm"]) {
    assert.match(
      releaseWorkflow,
      new RegExp(`${job}:[\\s\\S]*?if: github\\.event_name == 'push' && startsWith`),
    );
  }

  for (const surface of [bump, release, ciWorkflow, releaseWorkflow, publishWorkflow]) {
    assert.doesNotMatch(surface, /\(\d\+\\\.\d\+\\\.\d\+\)/);
  }
});
