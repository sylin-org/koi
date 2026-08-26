import assert from "node:assert/strict";
import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  CARRIER_PACKAGE_NAMES,
  carrierFor,
  resolveCarrierBinary,
  runLauncher,
  stableBinaryPath,
} from "../lib/launcher.js";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const launcherSource = path.join(repoRoot, "packages", "npm", "bin", "koi.js");

test("the carrier table covers exactly the six supported native targets", () => {
  const expectedTargets = new Set([
    "aarch64-apple-darwin",
    "aarch64-pc-windows-msvc",
    "aarch64-unknown-linux-musl",
    "x86_64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "x86_64-unknown-linux-musl",
  ]);
  for (const platform of ["darwin", "linux", "win32"]) {
    for (const arch of ["x64", "arm64"]) {
      const carrier = carrierFor(platform, arch);
      assert.equal(expectedTargets.delete(carrier.target), true, `${carrier.target} unmapped`);
      assert.match(carrier.packageName, new RegExp(`^@sylin-org/koi-${platform}-${arch}$`));
      assert.equal(carrier.binaryName, platform === "win32" ? "koi.exe" : "koi");
    }
  }
  assert.deepEqual([...expectedTargets], []);
  assert.equal(CARRIER_PACKAGE_NAMES.length, 6);
  assert.throws(() => carrierFor("aix", "x64"), /unsupported platform/);
  assert.throws(() => carrierFor("linux", "ia32"), /unsupported platform/);
});

test("every carrier is pinned exactly to the entry package version", async () => {
  const pkg = JSON.parse(
    await readFileSync(path.join(repoRoot, "packages", "npm", "package.json"), "utf8"),
  );
  assert.equal(pkg.name, "@sylin-org/koi");
  for (const name of CARRIER_PACKAGE_NAMES) {
    assert.equal(
      pkg.optionalDependencies[name],
      pkg.version,
      `${name} must pin exactly ${pkg.version}`,
    );
  }
  assert.deepEqual(Object.keys(pkg.optionalDependencies).sort(), [...CARRIER_PACKAGE_NAMES].sort());
});

test("resolveCarrierBinary finds a staged carrier inside the package node_modules", () => {
  const staging = stagedCarrier("linux", "x64");
  try {
    const resolved = resolveCarrierBinary({
      packageRoot: staging,
      platform: "linux",
      arch: "x64",
    });
    assert.equal(
      resolved.binaryPath,
      path.join(
        staging,
        "node_modules",
        "@sylin-org",
        "koi-linux-x64",
        "bin",
        "koi",
      ),
    );
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }
});

test("resolveCarrierBinary fails with actionable guidance when npm skipped optionals", () => {
  const staging = mkdtemp();
  try {
    assert.throws(
      () => resolveCarrierBinary({ packageRoot: staging, platform: "win32", arch: "x64" }),
      /--no-optional|sylin\.org\/koi/,
    );
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }
});

test("plain arguments exec the carried binary directly", async () => {
  const staging = stagedCarrier("linux", "x64");
  try {
    const calls = [];
    const exit = await runLauncher({
      args: ["mdns", "discover"],
      packageRoot: staging,
      platform: "linux",
      arch: "x64",
      env: {},
      homedir: () => "/home/koi",
      spawnProcess: async (command, args) => {
        calls.push({ command, args });
        return 7;
      },
    });
    assert.equal(exit, 7);
    assert.match(
      calls[0].command.replace(/\\/g, "/"),
      /node_modules\/@sylin-org\/koi-linux-x64\/bin\/koi$/,
    );
    assert.deepEqual(calls[0].args, ["mdns", "discover"]);
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }
});

test("`install` places the binary at the stable location and execs THAT", async () => {
  const staging = stagedCarrier("linux", "x64");
  // Forward slashes: the launcher targets POSIX for non-win32 platforms, and
  // Windows APIs accept forward slashes, so both sides agree on separators.
  const installDir = mkdtemp().replace(/\\/g, "/");
  try {
    const calls = [];
    const exit = await runLauncher({
      args: ["install"],
      packageRoot: staging,
      platform: "linux",
      arch: "x64",
      env: { KOI_INSTALL_DIR: installDir },
      homedir: () => "/home/koi",
      spawnProcess: async (command, args) => {
        calls.push({ command, args });
        return 0;
      },
    });
    assert.equal(exit, 0);
    // The launcher targets POSIX for non-win32 platforms, so the joined path
    // uses forward slashes even when the test host is Windows.
    const stable = `${installDir.replace(/\\/g, "/")}/koi`;
    assert.equal(existsSync(stable), true, "the stable copy must exist");
    assert.equal(calls[0].command, stable, "service-facing install runs from the stable path");
    assert.deepEqual(calls[0].args, ["install"]);
    assert.equal(existsSync(`${stable}.npm-staging`), false, "no staging residue");
  } finally {
    rmSync(staging, { recursive: true, force: true });
    rmSync(installDir, { recursive: true, force: true });
  }
});

test("stableBinaryPath honors KOI_INSTALL_DIR and platform defaults", () => {
  assert.equal(
    stableBinaryPath({ platform: "linux", env: { KOI_INSTALL_DIR: "/opt/koi" }, homedir: () => "/h", getuid: () => 1 }),
    "/opt/koi/koi",
  );
  assert.equal(
    stableBinaryPath({ platform: "linux", env: {}, homedir: () => "/h", getuid: () => 0 }),
    "/usr/local/bin/koi",
  );
  assert.equal(
    stableBinaryPath({ platform: "linux", env: {}, homedir: () => "/h", getuid: () => 1000 }),
    "/h/.local/bin/koi",
  );
  assert.equal(
    stableBinaryPath({
      platform: "win32",
      env: { LOCALAPPDATA: "C:\\Users\\k\\AppData\\Local" },
      homedir: () => "",
    }),
    "C:\\Users\\k\\AppData\\Local\\Programs\\koi\\koi.exe",
  );
});

// ── helpers ──────────────────────────────────────────────────────────────

function mkdtemp() {
  const dir = path.join(
    os.tmpdir(),
    `koi-carrier-test-${Date.now()}-${Math.random().toString(16).slice(2)}`,
  );
  mkdirSync(dir, { recursive: true });
  return dir;
}

function stagedCarrier(platform, arch) {
  const staging = mkdtemp();
  const binDir = path.join(staging, "node_modules", "@sylin-org", `koi-${platform}-${arch}`, "bin");
  mkdirSync(binDir, { recursive: true });
  const binary = path.join(binDir, carrierFor(platform, arch).binaryName);
  copyFileSync(launcherSource, binary);
  if (process.platform !== "win32") chmodSync(binary, 0o755);
  return staging;
}
