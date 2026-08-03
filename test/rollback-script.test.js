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

/* `nft -f` applies a file *into* the loaded ruleset. It replaces only what the
   file redeclares and leaves everything else standing, unless the file says
   `flush ruleset` first — which is why the copy has to be a restore script and
   not a listing. Checked against nft 1.1.3 on a real kernel: a table created
   by an apply outlived a rollback that loaded a bare listing. */
const FAKE_NFT = [
  "#!/bin/sh",
  'case "$1 $2" in',
  '  "list ruleset") cat "$STATE" ;;',
  '  "-f "*)',
  '    if head -n 1 "$2" | grep -qx "flush ruleset"; then',
  '      tail -n +2 "$2" > "$STATE"',
  "    else",
  '      cat "$2" >> "$STATE"',
  "    fi ;;",
  "  *) exit 1 ;;",
  "esac",
  "",
].join("\n");

test("arming twice keeps the first copy, and retires the first timer", { skip: !canRun }, async () => {
  const w = mkdtempSync(join(tmpdir(), "efeflow-arm-"));
  try {
    const dir = join(w, "run");
    const live = join(w, "live");
    const bin = join(w, "bin");
    execFileSync("mkdir", ["-p", bin]);

    /* An nft that reads and writes one file, so a restore is observable — and
       that adds rather than replaces, because that is what nftables does. A
       fake that treated `-f` as an overwrite made the rollback look like it
       put the ruleset back when on a real kernel it merges into what is
       already loaded, and a table the apply created survives it. */
    writeFileSync(join(bin, "nft"), FAKE_NFT);
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
    assert.equal(arm(1, "tok-A"), "flush ruleset\nGOOD\n", "arm hands back the copy it took");
    assert.equal(statSync(dir).mode & 0o777, 0o700, "the directory is private");
    assert.equal(read(join(dir, "rollback.nft")), "flush ruleset\nGOOD\n");

    /* an apply happened and was not confirmed; now a second one */
    writeFileSync(live, "BROKEN\n");
    assert.equal(arm(30, "tok-B"), "flush ruleset\nGOOD\n",
      "the second arm photographed the ruleset it was asked to replace");
    assert.equal(read(join(dir, "rollback.nft")), "flush ruleset\nGOOD\n",
      "the good copy survived a re-arm");

    /* tok-A's timer is due about now, and the sentinel is not its any more */
    await new Promise((r) => setTimeout(r, 2500));
    assert.equal(read(join(dir, "armed")), "tok-B", "a retired timer disarmed a live arming");
    assert.equal(readFileSync(live, "utf8"), "BROKEN\n",
      "a retired timer restored over an arming that had replaced it");
  } finally {
    rmSync(w, { recursive: true, force: true });
  }
});

/* ── the two the VM found ────────────────────────────────────────────────
   Both were invisible here until the script met a real kernel: the fake nft
   above replaced the ruleset on `-f`, which is not what nftables does, and
   nothing had ever armed a host that had no firewall yet. */

/** A workspace with the fake nft on PATH and the script's paths pointed into it. */
function bench() {
  const w = mkdtempSync(join(tmpdir(), "efeflow-net-"));
  const dir = join(w, "run"), live = join(w, "live"), bin = join(w, "bin");
  execFileSync("mkdir", ["-p", bin]);
  writeFileSync(join(bin, "nft"), FAKE_NFT);
  chmodSync(join(bin, "nft"), 0o755);
  const paths = { DIR: dir, ROLLBACK: join(dir, "rollback.nft"), SENTINEL: join(dir, "armed") };
  const sh = (script) => execFileSync("sh", ["-s"], {
    input: script,
    env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, STATE: live },
    encoding: "utf8",
  });
  return {
    w, live, paths,
    arm: (secs = 60, tok = "tok") => sh(render("nft_arm", { ...paths, secs, tok })),
    rollback: () => sh(render("nft_rollback", paths)),
    state: () => readFileSync(live, "utf8"),
    copy: () => (existsSync(paths.ROLLBACK) ? readFileSync(paths.ROLLBACK, "utf8") : null),
  };
}

/* A firewall with no rules yet lists as nothing at all, and `[ -s ]` reads a
   zero-byte file as no copy — so the net declined to fire on precisely the
   machine most likely to need it: the one being set up for the first time. */
test("a host with no ruleset still gets a net", { skip: !canRun }, () => {
  const b = bench();
  try {
    writeFileSync(b.live, "");
    b.arm();
    assert.notEqual(b.copy(), "", "an empty listing left an empty copy");
    assert.ok(statSync(b.paths.ROLLBACK).size > 0,
      "a zero-byte copy is read as no copy by every -s test in the script");

    /* something was applied and it cut the connection */
    writeFileSync(b.live, "table inet oops\n");
    b.rollback();
    assert.equal(b.state(), "", "the net had to put an empty firewall back, and did not");
  } finally {
    rmSync(b.w, { recursive: true, force: true });
  }
});

/* `nft -f` adds to what is loaded. A rollback that hands the kernel a bare
   listing leaves behind whatever the apply created — which is the table doing
   the cutting off. */
test("a table the apply created does not survive the rollback", { skip: !canRun }, () => {
  const b = bench();
  try {
    writeFileSync(b.live, "table inet keepme\n");
    b.arm();

    /* the apply: keepme changed, and a table that was not there before */
    writeFileSync(b.live, "table inet keepme CHANGED\ntable inet brandnew\n");
    b.rollback();

    assert.equal(b.state(), "table inet keepme\n");
    assert.doesNotMatch(b.state(), /brandnew/,
      "the table the apply created outlived the rollback that was meant to undo it");
    assert.doesNotMatch(b.state(), /CHANGED/);
  } finally {
    rmSync(b.w, { recursive: true, force: true });
  }
});

test("the copy is a restore script, not a listing", () => {
  const arm = render("nft_arm", here);
  /* the script carries a literal backslash-n for the shell's printf to read,
     so this is a plain string comparison and not a regex with an escape in it */
  assert.ok(arm.includes(String.raw`printf 'flush ruleset\n' > ${ROLLBACK}`),
    "without a flush at the front, `nft -f` merges into the live ruleset");
  assert.ok(arm.includes(`nft list ruleset >> ${ROLLBACK}`),
    "and the listing has to be appended, not overwrite it");
});
