import { chmodSync, copyFileSync, existsSync, mkdirSync, renameSync, rmSync } from "node:fs";
import path from "node:path";

// Carrier resolution and execution for @sylin-org/koi (ADR-034 D5).
//
// The entry package carries no binary. npm installs exactly one platform
// carrier (@sylin-org/koi-<platform>-<arch>, selected by its os/cpu fields),
// and this launcher resolves that carrier's binary and execs it.
//
// The placement law (restated by ADR-034 from ADR-025 §3): a service is never
// registered from an npm-managed path. `koi install` therefore first places a
// copy of the carried binary at Koi's stable per-user location and runs THAT,
// so the service registration points at a path npm never owns.

const CARRIERS = [
  { platform: "darwin", arch: "arm64", target: "aarch64-apple-darwin" },
  { platform: "darwin", arch: "x64", target: "x86_64-apple-darwin" },
  { platform: "linux", arch: "arm64", target: "aarch64-unknown-linux-musl" },
  { platform: "linux", arch: "x64", target: "x86_64-unknown-linux-musl" },
  { platform: "win32", arch: "arm64", target: "aarch64-pc-windows-msvc" },
  { platform: "win32", arch: "x64", target: "x86_64-pc-windows-msvc" },
];

export const CARRIER_PACKAGE_NAMES = CARRIERS.map(
  ({ platform, arch }) => `@sylin-org/koi-${platform}-${arch}`,
);

export function carrierFor(platform, arch) {
  const carrier = CARRIERS.find((c) => c.platform === platform && c.arch === arch);
  if (!carrier) {
    throw new Error(`unsupported platform '${platform}-${arch}' for the koi binary`);
  }
  return {
    ...carrier,
    packageName: `@sylin-org/koi-${platform}-${arch}`,
    binaryName: platform === "win32" ? "koi.exe" : "koi",
  };
}

function candidatePaths(packageRoot, packageName, binaryName) {
  // npm lays optional dependencies inside the depending package's own
  // node_modules; hoisted layouts (workspaces, legacy trees) are covered by
  // require.resolve as a fallback.
  return [
    path.join(packageRoot, "node_modules", packageName, "bin", binaryName),
  ];
}

export function resolveCarrierBinary({ packageRoot, platform, arch, require }) {
  const carrier = carrierFor(platform, arch);
  for (const candidate of candidatePaths(packageRoot, carrier.packageName, carrier.binaryName)) {
    if (existsSync(candidate)) return { ...carrier, binaryPath: candidate };
  }
  if (require) {
    try {
      const resolved = require.resolve(`${carrier.packageName}/bin/${carrier.binaryName}`);
      if (existsSync(resolved)) return { ...carrier, binaryPath: resolved };
    } catch {
      // fall through to the actionable error below
    }
  }
  throw new Error(
    `the platform package ${carrier.packageName} is not installed. npm skips ` +
      "carriers under --no-optional or --ignore-scripts-adjacent flags; reinstall " +
      "without those flags, or install Koi directly from https://sylin.org/koi",
  );
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

/// Place the carried binary at the stable location (temp-then-rename so a
/// concurrently running koi keeps serving until the swap), and return that
/// path. This is the ONLY route from npm to a registered service.
export function placeAtStableLocation({ binaryPath, platform, env, homedir, getuid }) {
  const destination = stableBinaryPath({ platform, env, homedir, getuid });
  mkdirSync(path.dirname(destination), { recursive: true });
  const staging = `${destination}.npm-staging`;
  rmSync(staging, { force: true });
  copyFileSync(binaryPath, staging);
  if (platform !== "win32") chmodSync(staging, 0o755);
  renameSync(staging, destination);
  return destination;
}

export async function runLauncher({
  args = [],
  packageRoot,
  platform = process.platform,
  arch = process.arch,
  env = process.env,
  homedir = () => "",
  getuid = undefined,
  require = undefined,
  spawnProcess = undefined,
}) {
  const { binaryPath } = resolveCarrierBinary({ packageRoot, platform, arch, require });
  let command = binaryPath;
  if (args[0] === "install") {
    command = placeAtStableLocation({ binaryPath, platform, env, homedir, getuid });
  }
  if (!spawnProcess) return 0; // resolution-only mode (tests, dry inspection)
  return await spawnProcess(command, args, { env });
}
