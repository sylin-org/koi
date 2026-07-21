import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));

let manifest;
try {
  manifest = JSON.parse(await readFile(path.join(root, "release-manifest.json"), "utf8"));
} catch {
  throw new Error("release-manifest.json is missing; stage a validated release before packing");
}

if (manifest.version !== pkg.version || manifest.tag !== `v${pkg.version}`) {
  throw new Error(`package ${pkg.version} does not match release manifest ${manifest.version ?? "unknown"}`);
}
const repositoryMatch = /^https:\/\/github\.com\/([^/]+)\/([^/]+)$/.exec(manifest.repository ?? "");
if (!repositoryMatch) {
  throw new Error("release manifest has no canonical GitHub repository identity");
}
const expectedPackageName = `@${repositoryMatch[1]}/${repositoryMatch[2]}`;
if (pkg.name !== expectedPackageName) {
  throw new Error(`package name ${pkg.name} does not match release repository ${expectedPackageName}`);
}
const expectedTargets = [
  "aarch64-apple-darwin",
  "aarch64-pc-windows-msvc",
  "aarch64-unknown-linux-musl",
  "x86_64-apple-darwin",
  "x86_64-pc-windows-msvc",
  "x86_64-unknown-linux-musl",
];
if (JSON.stringify(Object.keys(manifest.artifacts ?? {}).sort()) !== JSON.stringify(expectedTargets)) {
  throw new Error("release manifest must contain exactly the six supported native targets");
}
for (const target of expectedTargets) {
  if (!/^[a-f0-9]{64}$/.test(manifest.artifacts[target]?.sha256 ?? "")) {
    throw new Error(`release manifest has no valid digest for ${target}`);
  }
}
for (const name of ["posix", "windows"]) {
  if (!manifest.installers?.[name]?.sha256) {
    throw new Error(`release manifest is missing the ${name} installer`);
  }
}

process.stdout.write(`npm bootstrap verified for Koi ${pkg.version}\n`);
