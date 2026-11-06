import assert from "node:assert/strict";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const generator = new URL("./AiDocDist.ps1", import.meta.url);
const quote = (value) => `'${value.replaceAll("'", "''")}'`;

function fixture(t) {
  const root = mkdtempSync(path.join(tmpdir(), "koi-ai-doc-dist-"));
  t.after(() => {
    const resolved = path.resolve(root);
    assert.equal(path.dirname(resolved), path.resolve(tmpdir()));
    assert.equal(path.basename(resolved).startsWith("koi-ai-doc-dist-"), true);
    rmSync(resolved, { recursive: true, force: true });
  });
  const files = {
    "README.md": "# Koi\n[Ready](docs/launch/README.md)\n[Details](docs/launch/README.md#artifacts-and-channels)\n",
    "docs/LAUNCH.md": "# Launch\n[Ready](launch/README.md)\n[All ADRs](adr/)\n",
    "docs/launch/README.md": "# Release readiness\n## Artifacts and channels\n[Self](#artifacts-and-channels)\n[Other](trials.md#artifacts-and-channels-1)\n[Custom](trials.md#custom)\n[Old ADR](../adr/001-old.md)\n[Research](../research/note.md)\n[Code](../../crates/example.rs#L1)\n[Named][trial]\n[trial]: <trials.md#artifacts-and-channels> \"Trial\"\n`[literal](leave-this.md)`\n```md\n# Example heading\n[example](leave-this-too.md)\n```\n",
    "docs/launch/trials.md": "# Trials\n## Artifacts and channels\n## Artifacts and channels\n<a id=\"custom\"></a>\n[Ready](README.md#artifacts-and-channels)\n",
    "docs/adr/001-old.md": "# Old decision\n[Ready](../launch/README.md)\n[Historical code](../../crates/removed.rs#L4)\n",
    "docs/adr/046-container-lan-adoption.md": "# Current decision\n[Ready](../launch/README.md)\n",
    "docs/research/note.md": "# Research note\n[Ready](../launch/README.md)\n",
    "docs/plans/retired.md": "# Retired plan\n",
    "fleet/epics/004-container-lan-adoption.md": "# Epic\n[Ready](../../docs/launch/README.md)\n",
    "fleet/launch/LEDGER.md": "# Ledger\n[Ready](../../docs/launch/README.md)\n",
    "crates/example.rs": "// Existing source\n",
  };
  for (const [relative, content] of Object.entries(files)) {
    const target = path.join(root, relative);
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, content);
  }
  mkdirSync(path.join(root, "scripts"));
  const script = path.join(root, "scripts", "AiDocDist.ps1");
  copyFileSync(generator, script);
  return { root, script };
}

function run(args) {
  const result = spawnSync("pwsh", ["-NoLogo", "-NoProfile", ...args], { encoding: "utf8" });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  return result.stdout;
}

test("bundles resolve source-relative paths and real anchors in every corpus mode", (t) => {
  const { root, script } = fixture(t);
  for (const [name, flags] of [["default", []], ["research", ["-IncludeResearch"]], ["adrs", ["-IncludeADRs"]], ["both", ["-IncludeADRs", "-IncludeResearch"]]]) {
    const output = path.join(root, name);
    const log = run(["-File", script, "-OutputDir", output, "-Validate", ...flags]);
    const read = (file) => readFileSync(path.join(output, file), "utf8");
    for (const file of ["koi-readme.md", "koi-docs-launch.md", "koi-launch-epic.md", "koi-launch-ledger.md"]) {
      assert.match(read(file), /\[Ready\]\(koi-launch-all\.md#doc-docs-launch-readme\)/, file);
    }
    const launch = read("koi-launch-all.md");
    assert.match(read("koi-readme.md"), /#doc-docs-launch-readme--artifacts-and-channels\)/);
    assert.match(launch, /<a id="doc-docs-launch-readme--artifacts-and-channels"><\/a>/);
    assert.match(launch, /\[Other\]\(koi-launch-all\.md#doc-docs-launch-trials--artifacts-and-channels-1\)/);
    assert.match(launch, /<a id="doc-docs-launch-trials--artifacts-and-channels-1"><\/a>/);
    assert.match(launch, /\[Custom\]\(koi-launch-all\.md#doc-docs-launch-trials--custom\)/);
    assert.match(launch, /\[trial\]: <koi-launch-all\.md#doc-docs-launch-trials--artifacts-and-channels> "Trial"/);
    assert.match(launch, /`\[literal\]\(leave-this\.md\)`/);
    assert.match(launch, /```md\n# Example heading\n\[example\]\(leave-this-too\.md\)\n```/);
    assert.match(launch, /https:\/\/github.com\/sylin-org\/koi\/blob\/dev\/crates\/example.rs#L1/);
    assert.match(launch, flags.includes("-IncludeADRs") ? /\[Old ADR\]\(koi-adr-all.md#doc-docs-adr-001-old\)/ : /\[Old ADR\]\(https:\/\/github.com\/sylin-org\/koi\/blob\/dev\/docs\/adr\/001-old.md\)/);
    assert.match(launch, flags.includes("-IncludeResearch") ? /\[Research\]\(koi-research-all.md#doc-docs-research-note\)/ : /\[Research\]\(https:\/\/github.com\/sylin-org\/koi\/blob\/dev\/docs\/research\/note.md\)/);
    assert.equal(existsSync(path.join(output, "koi-plans-all.md")), false);
    assert.equal(existsSync(path.join(output, "koi-adr-all.md")), flags.includes("-IncludeADRs"));
    assert.equal(existsSync(path.join(output, "koi-research-all.md")), flags.includes("-IncludeResearch"));
    assert.match(read("koi-docs-launch.md"), flags.includes("-IncludeADRs") ? /\[All ADRs\]\(koi-adr-all.md\)/ : /\[All ADRs\]\(https:\/\/github.com\/sylin-org\/koi\/tree\/dev\/docs\/adr\/\)/);
    assert.match(log, /Local navigation:.*all generated files and anchors resolve/);
    if (flags.includes("-IncludeADRs")) {
      assert.match(log, /Pre-existing source references need review/);
      assert.match(log, /crates\/removed.rs#L4 \(source path does not exist\)/);
      assert.match(read("koi-adr-all.md"), /<a id="doc-docs-adr-046-container-lan-adoption"><\/a>/);
    }
  }
});

test("navigation validation rejects missing generated files and heading anchors", (t) => {
  const { root, script } = fixture(t);
  const output = path.join(root, "negative");
  const target = path.join(output, "koi-readme.md");
  run(["-Command", `
    . ${quote(script)} -OutputDir ${quote(output)} -Validate
    Add-Content -LiteralPath ${quote(target)} -Value '[Broken](koi-launch-all.md#not-a-heading)'
    try { Test-DistributionLinks ${quote(output)}; throw 'Accepted invalid anchor' }
    catch { if ($_.Exception.Message -notlike '*missing bundled anchor*') { throw } }
    Add-Content -LiteralPath ${quote(target)} -Value '[Broken](koi-missing.md)'
    try { Test-DistributionLinks ${quote(output)}; throw 'Accepted missing file' }
    catch { if ($_.Exception.Message -notlike '*missing bundled file*') { throw } }
    exit 0
  `]);
});
