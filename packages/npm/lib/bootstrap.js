import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

const SHA256 = /^[a-f0-9]{64}$/;

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

export function installerFor(platform, manifest) {
  const name = platform === "win32"
    ? "windows"
    : platform === "linux" || platform === "darwin"
      ? "posix"
      : null;
  if (!name) throw new Error(`unsupported platform '${platform}'`);

  const installer = manifest?.installers?.[name];
  if (!installer || !SHA256.test(installer.sha256 ?? "")) {
    throw new Error(`release manifest has no valid ${name} installer`);
  }
  if (!installer.url?.startsWith("https://")) {
    throw new Error("release manifest installer URL must use HTTPS");
  }
  if (!installer.path || path.basename(installer.path) !== installer.path) {
    throw new Error("release manifest installer path must be a filename");
  }
  return { name, ...installer };
}

export function artifactFor(platform, arch, manifest) {
  const cpu = arch === "x64" ? "x86_64" : arch === "arm64" ? "aarch64" : null;
  if (!cpu) throw new Error(`unsupported architecture '${arch}'`);
  const platformTarget = {
    linux: "unknown-linux-musl",
    darwin: "apple-darwin",
    win32: "pc-windows-msvc",
  }[platform];
  if (!platformTarget) throw new Error(`unsupported platform '${platform}'`);
  const target = `${cpu}-${platformTarget}`;
  const artifact = manifest?.artifacts?.[target];
  if (!artifact || !SHA256.test(artifact.sha256 ?? "")) {
    throw new Error(`release manifest has no valid ${target} artifact`);
  }
  return { target, ...artifact };
}

export function stableBinaryPath({ platform, env, homedir, getuid }) {
  if (env.KOI_INSTALL_DIR) {
    return platform === "win32"
      ? path.win32.join(env.KOI_INSTALL_DIR, "koi.exe")
      : path.posix.join(env.KOI_INSTALL_DIR, "koi");
  }
  if (platform === "win32") {
    if (!env.LOCALAPPDATA) {
      throw new Error("LOCALAPPDATA is unavailable; set KOI_INSTALL_DIR explicitly");
    }
    return path.win32.join(env.LOCALAPPDATA, "Programs", "koi", "koi.exe");
  }
  return getuid?.() === 0
    ? "/usr/local/bin/koi"
    : path.posix.join(homedir(), ".local", "bin", "koi");
}

async function download(url) {
  const response = await fetch(url, { redirect: "follow" });
  if (!response.ok) throw new Error(`could not download installer (${response.status})`);
  if (!response.url.startsWith("https://")) {
    throw new Error("installer download redirected away from HTTPS");
  }
  return Buffer.from(await response.arrayBuffer());
}

function run(command, args, options) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { ...options, stdio: "inherit" });
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (signal) reject(new Error(`${command} stopped by ${signal}`));
      else resolve(code ?? 1);
    });
  });
}

export async function runBootstrap({
  manifest,
  args = [],
  platform = process.platform,
  arch = process.arch,
  env = process.env,
  homedir = os.homedir,
  getuid = process.getuid,
  downloadInstaller = download,
  runProcess = run,
}) {
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(manifest?.version ?? "")) {
    throw new Error("release manifest has no valid version");
  }
  if (manifest.tag !== `v${manifest.version}`) {
    throw new Error("release manifest version and tag disagree");
  }

  const installer = installerFor(platform, manifest);
  const artifact = artifactFor(platform, arch, manifest);
  const bytes = await downloadInstaller(installer.url);
  const actual = sha256(bytes);
  if (actual !== installer.sha256) {
    throw new Error(`installer checksum mismatch (expected ${installer.sha256}, got ${actual})`);
  }

  const temporary = await mkdtemp(path.join(os.tmpdir(), "koi-npx-"));
  const script = path.join(temporary, installer.path);
  await writeFile(script, bytes, { mode: 0o700 });
  const installEnv = {
    ...env,
    KOI_VERSION: manifest.tag,
    KOI_EXPECTED_SHA256: artifact.sha256,
  };

  try {
    const installCommand = platform === "win32" ? "powershell.exe" : "/bin/sh";
    const installArgs = platform === "win32"
      ? ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script]
      : [script];
    const installCode = await runProcess(installCommand, installArgs, { env: installEnv });
    if (installCode !== 0) throw new Error(`native installer exited with code ${installCode}`);

    if (args.length === 0) return 0;
    const binary = stableBinaryPath({ platform, env: installEnv, homedir, getuid });
    return await runProcess(binary, args, { env: installEnv });
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}
