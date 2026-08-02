/* eFeFlow without a window.
 *
 * The core has been kept free of the DOM since the beginning so the parser
 * could be tested against a real `nft list ruleset` dump. This is the other
 * thing that buys: a pipeline can ask the same questions the interface asks,
 * before a ruleset reaches a machine.
 *
 * A linter is its exit status. Everything here is about that and about the
 * shape of what it prints, because both are things a script depends on. */
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync, rmSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { readNftErrors } from "../src/core/lint.js";
import { SAMPLES } from "../src/core/samples.js";

const CLI = new URL("../bin/efeflow.mjs", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");
const FIXTURE = new URL("./fixtures/flawed.nft", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");

const run = (args, input) =>
  spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8", input });

let dir;
const tmp = (name, text) => {
  dir ||= mkdtempSync(join(tmpdir(), "efeflow-test-"));
  const p = join(dir, name);
  writeFileSync(p, text);
  return p;
};
test.after(() => { if (dir) rmSync(dir, { recursive: true, force: true }); });

test("it reports the ruleset the analyser reports", () => {
  const r = run(["lint", "--no-colour", FIXTURE]);
  assert.match(r.stdout, /shadowed/);
  assert.match(r.stdout, /conflict/);
  assert.match(r.stdout, /round-trip 76\/76/);
  assert.equal(r.status, 1, "a ruleset with an error has to fail the build");
});

/* The thing a script actually reads. */
test("--json is a shape, not prose", () => {
  const r = run(["lint", "--json", FIXTURE]);
  assert.equal(r.status, 1);
  const j = JSON.parse(r.stdout);
  assert.equal(j.tool, "efeflow");
  assert.ok(j.version);
  assert.equal(j.files.length, 1);
  assert.ok(j.findings.length >= 5);

  const f = j.findings.find((x) => x.kind === "shadowed");
  assert.ok(f, "the shadowed rule is the whole point");
  for (const k of ["file", "line", "severity", "kind", "at", "where", "message"])
    assert.ok(k in f, `every finding needs ${k}`);
  assert.equal(typeof f.line, "number", "a machine wants file:line, not a chain name");
  assert.equal(f.severity, "warn");

  const rt = j.files[0].roundTrip;
  assert.equal(rt.lines, rt.reproduced, "the fixture round-trips whole");
});

/* A finding about a chain, a set or a table carries a rule index so the
   interface can jump there. Quoting that rule reads as an accusation. */
test("only findings about one rule name a line", () => {
  const j = JSON.parse(run(["lint", "--json", FIXTURE]).stdout);
  for (const f of j.findings) {
    if (f.at === "rule") continue;
    assert.equal(f.line, null, `${f.kind} is about a ${f.at} and must not point at a line`);
    assert.equal(f.text, null, `${f.kind} must not quote a rule it is not about`);
  }
  assert.ok(j.findings.some((f) => f.at === "chain"), "the fixture has a chain-level finding");
});

test("the threshold is the point of a linter", () => {
  const clean = tmp("clean.nft", SAMPLES.find((s) => s.id === "wireguard").nft);
  assert.equal(run(["lint", "--quiet", clean]).status, 0,
    "a ruleset with no errors must not break a build");
  assert.equal(run(["lint", "--quiet", "--fail-on", "warn", clean]).status, 1,
    "unless you asked for warnings to count");
  assert.equal(run(["lint", "--quiet", "--fail-on", "never", FIXTURE]).status, 0,
    "and never means never");
});

test("a file it cannot read is not a clean bill of health", () => {
  const r = run(["lint", join(tmpdir(), "efeflow-does-not-exist.nft")]);
  assert.equal(r.status, 2, "exit 0 here would be a green tick over nothing");
  assert.match(r.stdout, /no such file/);
});

test("it reads a ruleset from a pipe", () => {
  const r = run(["lint", "--json", "-"], readFileSync(FIXTURE, "utf8"));
  const j = JSON.parse(r.stdout);
  assert.equal(j.files[0].file, "<stdin>");
  assert.ok(j.findings.length >= 5);
});

test("--version and --help answer without a file", () => {
  const v = run(["--version"]);
  assert.equal(v.status, 0);
  assert.match(v.stdout.trim(), /^\d+\.\d+\.\d+$/);
  const h = run(["--help"]);
  assert.equal(h.status, 0);
  assert.match(h.stdout, /efeflow lint/);
});

/* Nothing here may claim to be `nft -c`. It keeps what it cannot model rather
   than rejecting it, so a line that is not nftables at all rides through as
   text — and the help has to say so, because a green tick that only means
   nobody checked is worse than no tick. */
test("it does not claim to be nft", () => {
  const h = run(["--help"]).stdout;
  assert.match(h, /not a replacement for/i);
  const r = run(["lint", "--no-colour", "--nft", tmp("odd.nft",
    "table inet t {\n\tchain c {\n\t\tthis is not nftables at all\n\t}\n}\n")]);
  /* on a machine without nft it says which opinion is missing */
  if (/not on this machine/.test(r.stdout)) assert.equal(r.status, 0);
  else assert.match(r.stdout, /refuses it|accepts it/);
});

/* Real output from nft 1.1.6, kept verbatim: a bridge table on a kernel built
   without CONFIG_NF_TABLES_BRIDGE. */
test("what nft says is read back the way nft says it", () => {
  const said = [
    "sample-rogue-dhcp.nft:6:1-2: Error: Could not process rule: Operation not supported",
    "table bridge filter {",
    "^^",
    "sample-rogue-dhcp.nft:6:14-19: Error: Could not process rule: No such file or directory",
    "table bridge filter {",
    "             ^^^^^^",
  ].join("\n");
  assert.deepEqual(readNftErrors(said), [
    { line: 6, message: "Could not process rule: Operation not supported" },
    { line: 6, message: "Could not process rule: No such file or directory" },
  ]);
  assert.deepEqual(readNftErrors(""), []);
  assert.deepEqual(readNftErrors("all fine here"), []);
});

test("the package offers the command", () => {
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(pkg.bin?.efeflow, "./bin/efeflow.mjs");
  assert.ok(pkg.files?.includes("bin"), "an installed package has to carry it");
});
