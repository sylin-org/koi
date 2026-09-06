import assert from "node:assert/strict";
import test from "node:test";
import { selectScope } from "./ci-scope.mjs";

const base = "a".repeat(40);
const head = "b".repeat(40);
const changed = paths => selectScope({ base, head }, () => paths.join("\0") + "\0");

test("journals, claims and documentation only use lightweight checks", () => {
  assert.equal(changed(["README.md", "docs/getting-started.md", "fleet/windows/journal.md", ".agentic/CONTEXT.md", ".codex/skills/explore/SKILL.md", "LICENSE"]).product, false);
});

test("product, mixed, executable documentation and unknown files keep full checks", () => {
  for (const file of ["crates/koi-ui/src/home.rs", "Cargo.lock", "Cargo.toml", "packages/ts/src/index.ts", "scripts/ci-scope.mjs", ".github/workflows/ci.yml", "docs/reference/vectors/trust-vectors.json", "docs/examples/check.sh", "fleet/helper.ps1", "new-area/file", "crates/koi/README.md"]) {
    assert.equal(changed(["fleet/windows/journal.md", file]).product, true, file);
  }
});

test("deleted source and renamed source cannot masquerade as documentation", () => {
  let args;
  const scope = selectScope({ base, head }, (program, passed) => {
    assert.equal(program, "git");
    args = passed;
    return "crates/old.rs\0docs/old.md\0";
  });
  assert.equal(scope.product, true);
  assert.ok(args.includes("--no-renames"));
  assert.deepEqual(args.slice(-3), [base, head, "--"], "compare the full push, not just HEAD's last commit");
});

test("unusual filenames stay whole rather than hiding a source path", () => {
  assert.equal(changed(["crates/code\ndocs/note.md"]).product, true);
  assert.equal(changed(["docs/a note.md"]).product, false);
});

test("manual validation and missing/new-branch bases fail closed to full checks", () => {
  const git = () => { throw new Error("must not diff an invalid base"); };
  for (const bad of [undefined, "", "0".repeat(40), "--help", "not-a-sha"]) {
    assert.equal(selectScope({ base: bad, head }, git).product, true);
    assert.equal(selectScope({ base, head: bad }, git).product, true);
  }
  assert.equal(selectScope({ base, head, force: true }, git).product, true);
});

test("failed git comparisons do not silently skip builds", () => {
  assert.equal(selectScope({ base, head }, () => { throw new Error("missing history"); }).product, true);
});
