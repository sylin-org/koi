import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { artifactFor, installerFor, runBootstrap, stableBinaryPath } from "../lib/bootstrap.js";

const script = Buffer.from("echo koi\n");
const hash = createHash("sha256").update(script).digest("hex");
const manifest = {
  version: "1.2.3",
  tag: "v1.2.3",
  installers: {
    posix: { path: "install.sh", url: "https://example.test/install.sh", sha256: hash },
    windows: { path: "install.ps1", url: "https://example.test/install.ps1", sha256: hash },
  },
  artifacts: {
    "x86_64-unknown-linux-musl": { archive: "koi-v1.2.3-x86_64-unknown-linux-musl.tar.gz", sha256: hash },
    "aarch64-apple-darwin": { archive: "koi-v1.2.3-aarch64-apple-darwin.tar.gz", sha256: hash },
    "x86_64-pc-windows-msvc": { archive: "koi-v1.2.3-x86_64-pc-windows-msvc.zip", sha256: hash },
  },
};

test("selects only the platform installer", () => {
  assert.equal(installerFor("linux", manifest).path, "install.sh");
  assert.equal(installerFor("darwin", manifest).path, "install.sh");
  assert.equal(installerFor("win32", manifest).path, "install.ps1");
  assert.throws(() => installerFor("aix", manifest), /unsupported platform/);
});

test("selects the native artifact from the manifest", () => {
  assert.equal(artifactFor("linux", "x64", manifest).target, "x86_64-unknown-linux-musl");
  assert.equal(artifactFor("darwin", "arm64", manifest).target, "aarch64-apple-darwin");
  assert.throws(() => artifactFor("linux", "ia32", manifest), /unsupported architecture/);
});

test("pins the installer and forwards arguments to the stable native binary", async () => {
  const calls = [];
  const result = await runBootstrap({
    manifest,
    args: ["mdns", "discover"],
    platform: "linux",
    arch: "x64",
    env: { HOME: "/home/koi" },
    homedir: () => "/home/koi",
    getuid: () => 1000,
    downloadInstaller: async () => script,
    runProcess: async (command, args, options) => {
      calls.push({ command, args, env: options.env });
      return 0;
    },
  });

  assert.equal(result, 0);
  assert.equal(calls[0].command, "/bin/sh");
  assert.equal(calls[0].env.KOI_VERSION, "v1.2.3");
  assert.equal(calls[0].env.KOI_EXPECTED_SHA256, hash);
  assert.equal(calls[1].command, "/home/koi/.local/bin/koi");
  assert.deepEqual(calls[1].args, ["mdns", "discover"]);
});

test("refuses a modified installer before executing it", async () => {
  let executed = false;
  await assert.rejects(
    runBootstrap({
      manifest,
      platform: "win32",
      arch: "x64",
      downloadInstaller: async () => Buffer.from("tampered"),
      runProcess: async () => { executed = true; return 0; },
    }),
    /installer checksum mismatch/,
  );
  assert.equal(executed, false);
});

test("does not treat the npm cache as the installation directory", () => {
  assert.equal(
    stableBinaryPath({
      platform: "win32",
      env: { LOCALAPPDATA: "C:\\Users\\Koi\\AppData\\Local" },
    }),
    "C:\\Users\\Koi\\AppData\\Local\\Programs\\koi\\koi.exe",
  );
  assert.equal(
    stableBinaryPath({ platform: "linux", env: {}, homedir: () => "/home/koi", getuid: () => 0 }),
    "/usr/local/bin/koi",
  );
});
