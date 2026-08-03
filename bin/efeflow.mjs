#!/usr/bin/env node
/* eFeFlow without a window.
 *
 * Everything that decides anything already lives in src/core/ and never
 * touches the DOM — that rule was kept so the parser could be tested against a
 * real `nft list ruleset` dump, and this is the other thing it buys. A
 * pipeline can now ask the same questions the interface asks, before a ruleset
 * reaches a machine.
 *
 *   efeflow lint fw.nft            what nft would reject, and what would not fire
 *   efeflow lint --json fw.nft     the same, for something that is not a person
 *   cat fw.nft | efeflow lint -    from a pipe
 *
 * Exit status is the point of a linter: 0 when nothing at or above the
 * threshold was found, 1 when something was, 2 when the file could not be read
 * at all. `--fail-on` moves the threshold; the default is `error`, so warnings
 * and hints report without breaking a build until you ask them to.
 */
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { argv, stdin, stdout, exit } from "node:process";

import { parseNft, verify } from "../src/core/parse.js";
import { lintRuleset, readNftErrors } from "../src/core/lint.js";
import { analyse } from "../src/core/analyse.js";
import { ruleLine, UID } from "../src/core/model.js";
import { MODEL } from "../src/core/model.js";

const VERSION = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8")).version;

const USAGE = `eFeFlow ${VERSION} — the IDE for nftables, without the window

  efeflow lint [options] <file>...    read a ruleset and report on it
  efeflow lint [options] -            read it from standard input

Options
  --json              machine-readable output on stdout
  --nft               also hand the file to the real \`nft -c\`, if it is on PATH
  --fail-on <level>   exit 1 at this severity or worse: error (default), warn, hint, never
  --quiet             findings only, no summary
  --no-colour         plain text even on a terminal
  --version           print the version and exit

This is not a replacement for \`nft -c\`, and it does not pretend to be. It
keeps what it cannot model rather than rejecting it, so a line that is not
nftables at all is carried through as text and reported by nobody. On a Linux
runner, \`--nft\` asks the authority as well; without it you are getting one
opinion, not two.

What it reports
  syntax      a rule nft would refuse, which stops the whole file loading
  shadowed    a rule an earlier one already decides, so it can never match
  conflict    overlapping DNAT rules sending the same traffic to different hosts
  dormant     a table loaded and not running
  merge       rules a single set lookup would replace
  hardening   a chain that trusts conntrack but never drops invalid
  round-trip  lines this could not reproduce, which is a bug worth reporting

Exit status
  0  nothing at or above the threshold
  1  something was found
  2  a file could not be read, or held nothing that parses
`;

/* ── arguments ─────────────────────────────────────────────────────────── */
const args = argv.slice(2);
const opt = { json: false, quiet: false, colour: stdout.isTTY, failOn: "error" };
const files = [];
let cmd = null;

for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === "--json") opt.json = true;
  else if (a === "--nft") opt.nft = true;
  else if (a === "--quiet" || a === "-q") opt.quiet = true;
  else if (a === "--no-colour" || a === "--no-color") opt.colour = false;
  else if (a === "--fail-on") opt.failOn = args[++i];
  else if (a === "--version" || a === "-V") { stdout.write(VERSION + "\n"); exit(0); }
  else if (a === "--help" || a === "-h") { stdout.write(USAGE); exit(0); }
  else if (!cmd && !a.startsWith("-")) cmd = a;
  else files.push(a);
}

if (!cmd) { stdout.write(USAGE); exit(files.length ? 2 : 0); }
if (cmd !== "lint") { stdout.write(`efeflow: no such command: ${cmd}\n\n` + USAGE); exit(2); }
if (!files.length) { stdout.write("efeflow lint: nothing to read. Give it a file, or - for stdin.\n"); exit(2); }

const RANK = { error: 0, warn: 1, hint: 2 };
if (!(opt.failOn in RANK) && opt.failOn !== "never") {
  stdout.write(`efeflow: --fail-on takes error, warn, hint or never\n`); exit(2);
}

/* ── reading ───────────────────────────────────────────────────────────── */
const readStdin = async () => {
  const chunks = [];
  for await (const c of stdin) chunks.push(c);
  return Buffer.concat(chunks).toString("utf8");
};

/* ── the authority, when it is on this machine ──────────────────────────
   Our linter is a reading of nftables. `nft -c` is nftables. Where both can be
   had, the second one settles it — and where nft is not installed, saying so
   is better than a green tick that only means nobody checked. */
function askNft(src) {
  const probe = spawnSync("nft", ["--version"], { encoding: "utf8" });
  if (probe.error) return { available: false };

  const dir = mkdtempSync(join(tmpdir(), "efeflow-"));
  const file = join(dir, "ruleset.nft");
  try {
    writeFileSync(file, src);
    const r = spawnSync("nft", ["-c", "-f", file], { encoding: "utf8" });
    const said = ((r.stderr || "") + (r.stdout || "")).trim();
    return {
      available: true,
      version: (probe.stdout || "").trim(),
      ok: r.status === 0,
      lines: readNftErrors(said),
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/* ── one ruleset ───────────────────────────────────────────────────────── */
function inspect(name, src) {
  const p = parseNft(src);
  /* analyse() reads the shared model, which is how the interface uses it too */
  Object.assign(MODEL, {
    chains: p.chains, sets: p.sets, objects: p.objects,
    tables: p.tables, prelude: p.prelude,
  });

  const lineOf = (chain, i) => p.ruleLines?.[UID(chain)]?.[i] ?? null;
  const out = [];

  /* what nft would refuse: the one that costs you the entire apply */
  for (const f of lintRuleset(MODEL))
    out.push({
      file: name, line: lineOf(f.chain, f.i), severity: "error", kind: "syntax",
      code: f.code, where: `${f.chain.table} / ${f.chain.id}`, rule: f.i + 1,
      message: f.title[0], text: ruleLine(f.chain.rules[f.i]),
    });

  /* everything the analyser derives */
  for (const f of analyse()) {
    if (f.kind === "syntax") continue;                 /* already above, with a line */
    /* A finding about a chain, a set or a whole table carries a rule index so
       the interface has somewhere to jump to. Quoting that rule here would
       read as an accusation against a line that did nothing wrong. */
    const one = f.at === "rule" && f.chain;
    out.push({
      file: name, line: one ? lineOf(f.chain, f.i) : null,
      severity: f.sev, kind: f.kind, at: f.at, where: f.where,
      rule: one ? f.i + 1 : null, message: f.title[0],
      text: one && f.chain.rules[f.i] ? ruleLine(f.chain.rules[f.i]) : null,
      fixable: !!f.fix,
    });
  }

  /* the claim the import dialog makes to a user, made to a pipeline */
  const v = verify(src);
  const trip = { lines: v.total, reproduced: v.ok, lost: v.total - v.ok };
  /* Naming the line is the whole of this finding's value. "Something did not
     reproduce" is not a bug report — it is the absence of one, and it was what
     this printed: no line, no text, twice, for one line that moved. */
  for (const d of v.diffs || [])
    out.push({
      file: name, line: d.ln ?? null, severity: "error", kind: "round-trip",
      where: name, rule: null,
      message: d.out === "—" ? "this line was not reproduced — please report it"
             : d.src === "—" ? "this line came out of nowhere — please report it"
             : "this line came back changed — please report it",
      text: d.src === "—" ? null : d.src,
      became: d.out === "—" ? null : d.out,
    });

  let nft = null;
  if (opt.nft) {
    nft = askNft(src);
    for (const e of nft.lines || [])
      out.push({
        file: name, line: e.line, severity: "error", kind: "nft",
        at: "rule", where: "nft -c", rule: null, message: e.message, text: null,
      });
  }

  return {
    file: name,
    nft: nft && (nft.available
      ? { version: nft.version, accepted: nft.ok }
      : { available: false }),
    tables: [...new Set(p.chains.map((c) => c.table))].length,
    chains: p.chains.length,
    rules: p.chains.reduce((a, c) => a + c.rules.length, 0),
    unparsed: p.errors.length,
    roundTrip: trip,
    findings: out,
  };
}

/* ── output ────────────────────────────────────────────────────────────── */
const C = {
  error: (s) => (opt.colour ? `\x1b[31m${s}\x1b[0m` : s),
  warn: (s) => (opt.colour ? `\x1b[33m${s}\x1b[0m` : s),
  hint: (s) => (opt.colour ? `\x1b[90m${s}\x1b[0m` : s),
  dim: (s) => (opt.colour ? `\x1b[90m${s}\x1b[0m` : s),
  bold: (s) => (opt.colour ? `\x1b[1m${s}\x1b[0m` : s),
};

function human(r) {
  const L = [];
  for (const f of r.findings) {
    const at = f.line ? `${f.file}:${f.line}` : f.file;
    L.push(`${C.bold(at)}  ${C[f.severity](f.severity.padEnd(5))} ${C.dim(f.kind.padEnd(10))} ${f.message}`);
    if (f.text) L.push(`      ${C.dim(f.text)}`);
    /* what came back instead, where a line came back as something else */
    if (f.became) L.push(`      ${C.dim("→ " + f.became)}`);
  }
  if (!opt.quiet) {
    const t = r.roundTrip;
    const pct = t.lines ? Math.round((t.reproduced / t.lines) * 100) : 100;
    L.push("");
    L.push(`  ${r.rules} rules in ${r.chains} chains across ${r.tables} table${r.tables === 1 ? "" : "s"}` +
           `  ·  round-trip ${t.reproduced}/${t.lines} = ${pct}%` +
           (r.unparsed ? `  ·  ${C.warn(r.unparsed + " lines not understood")}` : ""));
    const n = (s) => r.findings.filter((f) => f.severity === s).length;
    const many = (k, word) => `${n(k)} ${word}${n(k) === 1 ? "" : "s"}`;
    L.push(`  ${C.error(many("error", "error"))}  ${C.warn(many("warn", "warning"))}  ${C.hint(many("hint", "hint"))}`);
    if (r.nft)
      L.push("  " + (r.nft.available === false
        ? C.warn("nft is not on this machine, so only eFeFlow has read this")
        : r.nft.accepted
          ? C.dim(`${r.nft.version} accepts it`)
          : C.error(`${r.nft.version} refuses it`)));
  }
  return L.join("\n");
}

/* ── go ────────────────────────────────────────────────────────────────── */
const reports = [];
let unreadable = 0;

for (const f of files) {
  let src;
  try {
    src = f === "-" ? await readStdin() : readFileSync(f, "utf8");
  } catch (e) {
    unreadable++;
    if (!opt.json) stdout.write(`${f}: ${e.code === "ENOENT" ? "no such file" : e.message}\n`);
    continue;
  }
  reports.push(inspect(f === "-" ? "<stdin>" : f, src));
}

if (opt.json) {
  stdout.write(JSON.stringify({
    tool: "efeflow", version: VERSION,
    files: reports,
    findings: reports.flatMap((r) => r.findings),
  }, null, 2) + "\n");
} else {
  stdout.write(reports.map(human).join("\n\n") + "\n");
}

if (unreadable) exit(2);
if (opt.failOn === "never") exit(0);
const worst = Math.min(...reports.flatMap((r) => r.findings.map((f) => RANK[f.severity])), 9);
exit(worst <= RANK[opt.failOn] ? 1 : 0);
