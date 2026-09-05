import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: "utf8", ...options });
  assert.equal(result.status, 0, `${command} failed:\n${result.stdout}\n${result.stderr}`);
  return result.stdout;
}

async function fixture(version) {
  const temp = await mkdtemp(path.join(tmpdir(), "koi-bootstrap-"));
  const target = "x86_64-unknown-linux-musl";
  const archive = `koi-${version}-${target}.tar.gz`;
  const payload = path.join(temp, `koi-${version}-${target}`);
  const releases = path.join(temp, "releases");
  const bin = path.join(temp, "fake-bin");
  const install = path.join(temp, "install dir");
  await mkdir(payload);
  await mkdir(releases);
  await mkdir(bin);
  await writeFile(
    path.join(payload, "koi"),
    "#!/bin/sh\ncase \"$*\" in\n  status) echo fixture-status ;;\n  '--standalone mdns discover') echo fixture-discovery ;;\n  *) exit 64 ;;\nesac\n",
  );
  await chmod(path.join(payload, "koi"), 0o755);
  run("tar", ["-czf", path.join(releases, archive), "-C", temp, path.basename(payload)]);
  const bytes = await readFile(path.join(releases, archive));
  const digest = createHash("sha256").update(bytes).digest("hex");
  await writeFile(path.join(releases, `${archive}.sha256`), `${digest}  ${archive}\n`);
  await writeFile(
    path.join(bin, "curl"),
    "#!/bin/sh\nfor last do :; done\ncase \"$*\" in\n  *' -o '*)\n    out=''\n    prev=''\n    for arg do [ \"$prev\" = -o ] && out=$arg; prev=$arg; done\n    cp \"$KOI_FIXTURE_RELEASES/$(basename \"$last\")\" \"$out\" ;;\n  *) exit 64 ;;\nesac\n",
  );
  await chmod(path.join(bin, "curl"), 0o755);
  return { temp, releases, bin, install };
}

for (const [channel, version] of [
  ["stable", "v0.9.0"],
  ["prerelease", "v1.0.0-rc.2"],
]) {
  test(`POSIX ${channel} bootstrap prints an executable daemon-free action`, async (t) => {
    const files = await fixture(version);
    t.after(() => rm(files.temp, { recursive: true, force: true }));
    const output = run("sh", [path.join(root, "install.sh")], {
      env: {
        ...process.env,
        KOI_VERSION: version,
        KOI_INSTALL_DIR: files.install,
        KOI_NO_MODIFY_PATH: "1",
        KOI_FIXTURE_RELEASES: files.releases,
        PATH: `${files.bin}:${process.env.PATH}`,
      },
    });

    assert.match(output, /binary only; no service started/);
    const line = output.split("\n").find((candidate) => candidate.includes("one-time discovery:"));
    assert.ok(line, "installer did not print a discovery action");
    const action = line.replace(/^koi: one-time discovery: /, "");
    assert.equal(run("sh", ["-c", action]).trim(), "fixture-discovery");
    assert.equal(action, `'${files.install}/koi' --standalone mdns discover`);
  });
}

test("PowerShell output uses the installed path and explicit standalone mode", async () => {
  const source = await readFile(path.join(root, "install.ps1"), "utf8");
  assert.match(source, /binary only; no service started/);
  assert.match(source, /one-time discovery: & `"\$installedExe`" --standalone mdns discover/);
  assert.match(source, /Administrator terminal.*& `"\$installedExe`" install/);
});
