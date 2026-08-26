import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));

if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(pkg.version ?? "")) {
  throw new Error(`package version '${pkg.version}' is not valid SemVer`);
}
if (pkg.name !== "@sylin-org/koi") {
  throw new Error(`package name ${pkg.name} does not match the canonical npm identity`);
}

// The load-bearing invariant: every carrier is pinned to the entry's EXACT
// version. A range here would let npm mix binaries across releases.
const expectedCarriers = [
  "@sylin-org/koi-darwin-arm64",
  "@sylin-org/koi-darwin-x64",
  "@sylin-org/koi-linux-arm64",
  "@sylin-org/koi-linux-x64",
  "@sylin-org/koi-win32-arm64",
  "@sylin-org/koi-win32-x64",
];
const optional = pkg.optionalDependencies ?? {};
for (const name of expectedCarriers) {
  if (optional[name] !== pkg.version) {
    throw new Error(
      `carrier ${name} is '${optional[name] ?? "missing"}'; it must be pinned ` +
        `exactly to the package version ${pkg.version}`,
    );
  }
}
const extras = Object.keys(optional).filter((name) => !expectedCarriers.includes(name));
if (extras.length > 0) {
  throw new Error(`unexpected optional dependencies: ${extras.join(", ")}`);
}

if (!pkg.files?.includes("bin")) {
  throw new Error("package files must ship bin/ (the launcher)");
}
for (const banned of ["release-manifest.json", "postinstall"]) {
  if (JSON.stringify(pkg).includes(banned)) {
    throw new Error(`the carrier model must not reference ${banned}`);
  }
}

process.stdout.write(`npm carriers verified for Koi ${pkg.version}\n`);
