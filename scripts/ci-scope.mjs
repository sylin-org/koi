// Conservative CI selection: only known documentation can omit product builds.
import { execFileSync } from "node:child_process";
import { appendFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

export function isDocumentation(file) {
  if (["LICENSE", "LICENSE-MIT", "LICENSE-APACHE"].includes(file)) return true;
  if (!file.endsWith(".md")) return false;
  return !file.includes("/") ||
    ["docs/", "fleet/", ".agentic/", ".codex/"].some(prefix => file.startsWith(prefix));
}

export function selectScope({ base, head, force = false }, git = execFileSync) {
  if (force) return { product: true, reason: "explicit full validation" };
  const valid = sha => typeof sha === "string" && /^[a-f0-9]{40}$/.test(sha) && !/^0+$/.test(sha);
  if (!valid(base) || !valid(head)) return { product: true, reason: "no trustworthy comparison base" };
  try {
    // Include both sides of renames and every commit in a push. NUL delimiters
    // preserve unusual filenames. PR HEAD is the actual checked merge tree.
    const output = git("git", ["diff", "--no-renames", "--name-only", "-z", base, head, "--"], {
      encoding: "utf8", maxBuffer: 4 * 1024 * 1024,
    });
    const paths = output.split("\0").filter(Boolean);
    const product = paths.some(file => !isDocumentation(file));
    return { product, reason: product ? "product, tooling or unrecognized changes" : "documentation-only or unchanged tree" };
  } catch {
    return { product: true, reason: "comparison unavailable; full validation required" };
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const scope = selectScope({
    base: process.env.CI_BASE_SHA,
    head: process.env.GITHUB_SHA,
    force: process.env.CI_FORCE_FULL === "true",
  });
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `product=${scope.product}\n`);
  console.log(`CI scope: ${scope.product ? "full product checks" : "lightweight documentation checks"} (${scope.reason})`);
}
