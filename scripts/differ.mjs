#!/usr/bin/env node
/* eFeFlow against the authority.
 *
 * Everything else here is this project checking its own reading of nftables.
 * `test/probe.test.js` states what nft would do and asserts we agree, but the
 * statement is still ours. This asks nft.
 *
 * For each ruleset:
 *
 *   N1 = load it into a private, empty netfilter instance and list it back
 *   R' = parse it with eFeFlow and emit it again
 *   N2 = load R' the same way and list that back
 *
 * N1 and N2 are nft's own canonical form of the two files, so comparing them
 * asks whether the round trip changed what the ruleset *means*. That is a
 * stronger claim than the one verify() makes: a file whose text came back
 * different but whose netlink is identical lost nothing, and a file whose text
 * matched while its netlink moved lost everything and told nobody.
 *
 *   npm run differ                 the samples and the fixtures
 *   npm run differ -- fw.nft …     those, and anything else named
 *   npm run differ -- --require    refuse to be skipped
 *
 * Nothing here can reach the firewall of the machine it runs on. Each load
 * happens inside a network namespace of its own — a netfilter instance that
 * starts empty and does not exist a moment later — so the worst a bad ruleset
 * can do is be rejected.
 */
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, basename } from "node:path";
import { argv, exit, stdout } from "node:process";

import { parseNft } from "../src/core/parse.js";
import { generate } from "../src/core/generate.js";
import { SAMPLES } from "../src/core/samples.js";

const args = argv.slice(2);
const REQUIRE = args.includes("--require");
const files = args.filter((a) => !a.startsWith("-"));

/* ── somewhere to load a ruleset that is not this machine ────────────────
   `unshare -rn` wants unprivileged user namespaces, which some distributions
   and most CI images restrict. Where they are off and sudo is free, a plain
   network namespace does the same job. Both give nft a firewall of its own. */
function sandbox() {
  const probe = (cmd, as) => {
    const r = spawnSync(cmd[0], [...cmd.slice(1), "sh", "-c", "true"], { encoding: "utf8" });
    return r.status === 0 ? { cmd, as } : null;
  };
  return probe(["unshare", "-rn"], "a user namespace")
      ?? probe(["sudo", "-n", "unshare", "-n"], "sudo")
      ?? null;
}

const nft = spawnSync("nft", ["--version"], { encoding: "utf8" });
const box = nft.status === 0 ? sandbox() : null;

if (nft.status !== 0 || !box) {
  const why = nft.status !== 0
    ? "there is no `nft` on this machine"
    : "no network namespace can be entered here — unprivileged user namespaces are off and sudo is not free";
  /* A skip that reports success is a green tick meaning nobody checked, which
     is worse than no tick. CI passes --require so it cannot happen there. */
  stdout.write(`differ: not run — ${why}.\n`);
  exit(REQUIRE ? 2 : 0);
}
stdout.write(`differ: ${nft.stdout.trim()}, in ${box.as}\n\n`);

const work = mkdtempSync(join(tmpdir(), "efeflow-differ-"));
const NFT_ARGS = box.cmd.slice(1);

/** Load a ruleset in a namespace of its own and hand back what nft lists. */
function canonical(src) {
  const f = join(work, "ruleset.nft");
  writeFileSync(f, src);
  /* the devices the rulesets name, so a netdev chain has something to attach
     to; without them nft refuses the chain and the comparison never happens */
  const devices = ["wan0", "lan0", "br-lan", "eth0", "eth1", "veth0", "br0"]
    .map((d) => `ip link add ${d} type dummy 2>/dev/null;`).join(" ");
  const r = spawnSync(box.cmd[0],
    [...NFT_ARGS, "sh", "-c", `${devices} nft -f ${f} 2>&1 && nft list ruleset`],
    { encoding: "utf8" });
  const out = (r.stdout || "") + (r.stderr || "");
  const text = out.split("\n")
    .map((l) => l
      .replace(/\s*#\s*handle\s+\d+\s*$/, "")
      /* what the kernel has counted, and the countdown it stamps on a timed
         element the moment it loads it: two loads a millisecond apart differ
         on every one of them, and neither is anything the file said */
      .replace(/counter packets \d+ bytes \d+/, "counter")
      .replace(/\s+expires\s+[\dhmsd]+/g, ""))
    .filter((l) => l.trim())
    .join("\n");
  return { ok: r.status === 0 && !/Error:/.test(out), text, raw: out };
}

const firstError = (raw) => raw.split("\n").find((l) => /Error/.test(l))?.trim() ?? "";

/* ── what to compare ─────────────────────────────────────────────────────── */
const cases = SAMPLES.map((s) => [`sample: ${s.id}`, s.nft]);
for (const p of [new URL("../test/fixtures/flawed.nft", import.meta.url),
                 new URL("../test/fixtures/probe.nft", import.meta.url)])
  if (existsSync(p)) cases.push([`fixture: ${basename(p.pathname, ".nft")}`, readFileSync(p, "utf8")]);
for (const f of files) {
  if (!existsSync(f)) { stdout.write(`  ??   ${f}: no such file\n`); continue; }
  cases.push([basename(f), readFileSync(f, "utf8")]);
}

/* ── and the comparison ──────────────────────────────────────────────────── */
let bad = 0, ran = 0, skipped = 0;
for (const [name, src] of cases) {
  const before = canonical(src);
  if (!before.ok) {
    /* nft will not take the source itself, so there is nothing to compare
       against — `flawed.nft` is deliberately one of these */
    stdout.write(`  --   ${name}: nft refuses the original — ${firstError(before.raw)}\n`);
    skipped++;
    continue;
  }

  const p = parseNft(src);
  const emitted = generate({
    chains: p.chains, sets: p.sets, objects: p.objects,
    tables: p.tables, prelude: p.prelude,
  }).join("\n");
  const after = canonical(emitted);
  ran++;

  if (!after.ok) {
    bad++;
    stdout.write(`  XX   ${name}: nft refuses what eFeFlow emitted\n`);
    stdout.write(`       ${firstError(after.raw)}\n`);
    continue;
  }
  if (before.text === after.text) { stdout.write(`  ok   ${name}\n`); continue; }

  bad++;
  stdout.write(`  XX   ${name}: the two load to different rulesets\n`);
  const A = before.text.split("\n"), B = after.text.split("\n");
  for (const l of A.filter((x) => !B.includes(x)).slice(0, 5)) stdout.write(`       - ${l.trim()}\n`);
  for (const l of B.filter((x) => !A.includes(x)).slice(0, 5)) stdout.write(`       + ${l.trim()}\n`);
}

rmSync(work, { recursive: true, force: true });
stdout.write(`\n  ${ran} compared, ${skipped} skipped, ${bad} different\n`);

/* Nothing compared is not a pass. It is the same green tick that only means
   nobody looked, which is what --require exists to refuse. */
if (REQUIRE && ran === 0) {
  stdout.write("  nothing was compared, which is not the same as agreeing\n");
  exit(2);
}
exit(bad ? 1 : 0);
