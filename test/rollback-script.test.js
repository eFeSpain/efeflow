/* The safety net, run rather than read.
 *
 * `nft_arm` is the one thing in this repository that is a shell script living
 * inside a Rust string, and it is also the thing that stands between somebody
 * and a firewall they can no longer reach. `cargo clippy` has no opinion about
 * shell, `npm test` never saw it, and the two bugs below were both invisible
 * to every check that existed.
 *
 * The copy was taken in /tmp, at a fixed name, by a redirect performed as
 * root. `umask 077` sets the mode of a file we create and says nothing about
 * one already sitting there, so any local user on that firewall could put a
 * symlink at the path first and choose where root's copy of the ruleset went —
 * and the far end of the same path is `nft -f` as root, which is the whole
 * firewall.
 *
 * And arming twice overwrote the copy. Apply something that breaks a service,
 * do not confirm it, fix it and apply again: the second arm photographed the
 * broken ruleset as the one to go back to, so the net restored the breakage.
 *
 * The script is extracted from nft.rs rather than restated here. A test that
 * holds its own copy of the thing it is testing proves the copy. */
import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync, mkdtempSync, rmSync, writeFileSync, chmodSync, statSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { platform } from "node:process";

const SRC = readFileSync(new URL("../src-tauri/src/nft.rs", import.meta.url), "utf8");

/** The contents of a Rust string literal starting at `from`, unescaped. */
function literal(from) {
  const open = SRC.indexOf('"', from);
  let out = "";
  for (let i = open + 1; i < SRC.length; i++) {
    const c = SRC[i];
    if (c === '"') return out;
    if (c !== "\\") { out += c; continue; }
    const n = SRC[++i];
    if (n === "n") out += "\n";
    else if (n === "t") out += "\t";
    else if (n === '"' || n === "\\" || n === "'") out += n;
    /* a backslash before a newline continues the literal and eats the
       indentation of the line that follows — which is how a shell script gets
       to be readable inside a Rust source file */
    else if (n === "\n") { while (/\s/.test(SRC[i + 1] ?? "")) i++; }
    else out += n;
  }
  throw new Error("unterminated string literal in nft.rs");
}

const constOf = (name) => {
  const m = SRC.match(new RegExp(`const ${name}: &str = "([^"]*)"`));
  assert.ok(m, `nft.rs no longer declares ${name}`);
  return m[1];
};

const scriptOf = (fn) => {
  const at = SRC.indexOf(`pub fn ${fn}(`);
  assert.ok(at > 0, `nft.rs no longer declares ${fn}`);
  return literal(SRC.indexOf("format!(", at));
};

const DIR = constOf("DIR");
const ROLLBACK = constOf("ROLLBACK");
const SENTINEL = constOf("SENTINEL");

/* The script arrives with Rust's inline format arguments still in it — the
   paths are constants and the seconds and the token are per-arming.
   An unsubstituted one is not a failed assertion, it is a shell redirect into
   a file called `{ROLLBACK}` in whatever directory the suite was run from. */
const render = (fn, at) => {
  const s = Object.entries(at).reduce((acc, [k, v]) => acc.replaceAll(`{${k}}`, v), scriptOf(fn));
  const left = s.match(/\{[A-Za-z_]+\}/);
  assert.equal(left, null, `${fn} has a format argument nothing substituted: ${left?.[0]}`);
  return s;
};
const here = { DIR, ROLLBACK, SENTINEL, secs: 60, tok: "token" };

/* ── what the paths may not be ──────────────────────────────────────────── */

test("the rollback copy is not in a directory strangers can write to", () => {
  for (const [name, p] of [["ROLLBACK", ROLLBACK], ["SENTINEL", SENTINEL]]) {
    assert.ok(!p.startsWith("/tmp/"), `${name} is back in /tmp: ${p}`);
    assert.ok(!p.startsWith("/var/tmp/"), `${name} is in /var/tmp: ${p}`);
    assert.ok(p.startsWith(DIR + "/"), `${name} is outside ${DIR}: ${p}`);
  }
});

test("the directory is created before it is written into, and only for root", () => {
  const arm = render("nft_arm", here);
  assert.ok(arm.includes(`mkdir -p -m 700 ${DIR}`), "no private directory is made");
  assert.ok(arm.indexOf("mkdir") < arm.indexOf(`> ${ROLLBACK}`),
    "the copy is written before the directory it goes in is made private");
});

/* ── and what the script does ───────────────────────────────────────────── */

const canRun = platform === "linux" || platform === "darwin";

test("arming twice keeps the first copy, and retires the first timer", { skip: !canRun }, async () => {
  const w = mkdtempSync(join(tmpdir(), "efeflow-arm-"));
  try {
    const dir = join(w, "run");
    const live = join(w, "live");
    const bin = join(w, "bin");
    execFileSync("mkdir", ["-p", bin]);

    /* an nft that reads and writes one file, so a restore is observable */
    writeFileSync(join(bin, "nft"), [
      "#!/bin/sh",
      'case "$1 $2" in',
      '  "list ruleset") cat "$STATE" ;;',
      '  "-f "*) cp "$2" "$STATE" ;;',
      "  *) exit 1 ;;",
      "esac",
      "",
    ].join("\n"));
    chmodSync(join(bin, "nft"), 0o755);

    const there = { DIR: dir, ROLLBACK: join(dir, "rollback.nft"), SENTINEL: join(dir, "armed") };
    const arm = (secs, tok) =>
      execFileSync("sh", ["-s"], {
        input: render("nft_arm", { ...there, secs, tok }),
        env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, STATE: live },
        encoding: "utf8",
      });
    const read = (p) => (existsSync(p) ? readFileSync(p, "utf8") : null);

    writeFileSync(live, "GOOD\n");
    assert.equal(arm(1, "tok-A"), "GOOD\n", "arm hands back the copy it took");
    assert.equal(statSync(dir).mode & 0o777, 0o700, "the directory is private");
    assert.equal(read(join(dir, "rollback.nft")), "GOOD\n");

    /* an apply happened and was not confirmed; now a second one */
    writeFileSync(live, "BROKEN\n");
    assert.equal(arm(30, "tok-B"), "GOOD\n",
      "the second arm photographed the ruleset it was asked to replace");
    assert.equal(read(join(dir, "rollback.nft")), "GOOD\n", "the good copy survived a re-arm");

    /* tok-A's timer is due about now, and the sentinel is not its any more */
    await new Promise((r) => setTimeout(r, 2500));
    assert.equal(read(join(dir, "armed")), "tok-B", "a retired timer disarmed a live arming");
    assert.equal(readFileSync(live, "utf8"), "BROKEN\n",
      "a retired timer restored over an arming that had replaced it");
  } finally {
    rmSync(w, { recursive: true, force: true });
  }
});
