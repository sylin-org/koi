import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { buildReleaseManifest, RELEASE_TARGETS } from "./release-manifest.mjs";

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");

async function fixture() {
  const root = await mkdtemp(path.join(tmpdir(), "koi-release-manifest-"));
  const artifactsDir = path.join(root, "artifacts");
  await mkdir(artifactsDir);
  for (const target of RELEASE_TARGETS) {
    const suffix = target.includes("windows") ? ".zip" : ".tar.gz";
    const archive = `koi-v1.2.3-${target}${suffix}`;
    const contents = Buffer.from(`fixture:${target}`);
    await writeFile(path.join(artifactsDir, archive), contents);
    await writeFile(path.join(artifactsDir, `${archive}.sha256`), `${digest(contents)}  ${archive}\n`);
  }
  const installSh = path.join(root, "install.sh");
  const installPs1 = path.join(root, "install.ps1");
  await writeFile(installSh, "#!/bin/sh\n");
  await writeFile(installPs1, "Write-Host koi\n");
  return { root, artifactsDir, installSh, installPs1 };
}

test("builds a deterministic, complete release contract", async (t) => {
  const files = await fixture();
  t.after(() => rm(files.root, { recursive: true, force: true }));
  const manifest = await buildReleaseManifest({ version: "v1.2.3", ...files });

  assert.equal(manifest.version, "1.2.3");
  assert.equal(manifest.tag, "v1.2.3");
  assert.deepEqual(Object.keys(manifest.artifacts), RELEASE_TARGETS);
  assert.match(manifest.installers.posix.url, /\/v1\.2\.3\/install\.sh$/);
  assert.equal(manifest.artifacts["x86_64-pc-windows-msvc"].archive.endsWith(".zip"), true);
});

test("rejects an archive that disagrees with its checksum sidecar", async (t) => {
  const files = await fixture();
  t.after(() => rm(files.root, { recursive: true, force: true }));
  const archive = path.join(files.artifactsDir, "koi-v1.2.3-x86_64-unknown-linux-musl.tar.gz");
  await writeFile(archive, "tampered");

  await assert.rejects(
    buildReleaseManifest({ version: "1.2.3", ...files }),
    /checksum mismatch/,
  );
});
