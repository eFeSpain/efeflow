/* test/fixtures/probe.nft, and the three questions worth asking of it.
 *
 * The evaluator has two ways of not understanding something. Where it does not
 * recognise the construct, `unmodelled()` reports it and the verdict is marked
 * as a guess — that path is honest and it works. Where a matcher recognises
 * the shape and then decides wrongly, nothing is left over to report, so the
 * screen shows a confident wrong answer with no net under it.
 *
 * Every bug this file was written to catch was of the second kind, and the
 * fixture is a ruleset built to provoke them rather than one anybody would
 * run. The questions, in the order in which getting them wrong is dangerous:
 *
 *   STRUCTURE  is the model the ruleset that was written? A base chain that
 *              lost its hook is never walked by anything, and a header read
 *              as a rule is a verdict nobody wrote.
 *   VALUES     does each construct decide correctly for a packet whose answer
 *              is known from nftables' own semantics?
 *   HONESTY    where it cannot decide, does it still say so?
 *
 * The last one is not a formality. Every fix here narrows what goes unread,
 * and the temptation each time is to widen a matcher until it swallows
 * something it cannot actually evaluate. */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseNft, verify } from "../src/core/parse.js";
import { MODEL, ruleLine } from "../src/core/model.js";
import { matches, unmodelled } from "../src/core/simulate.js";

const SRC = readFileSync(new URL("fixtures/probe.nft", import.meta.url), "utf8");
const parsed = parseNft(SRC);
const load = () => Object.assign(MODEL, {
  chains: parsed.chains, sets: parsed.sets, objects: parsed.objects,
  tables: parsed.tables, prelude: parsed.prelude,
});
load();

/* ── structure ───────────────────────────────────────────────────────────── */

/* Read out of the source rather than listed here, so a chain added to the
   fixture is covered without anybody remembering to say so. */
const declared = [...SRC.matchAll(/chain\s+(\S+)\s*\{[^}]*?type\s+\w+\s+hook\s+(\w+)/gs)]
  .map((m) => ({ id: m[1], hook: m[2] }));

test("the fixture declares the chains this file is about", () => {
  assert.ok(declared.length >= 10, `only found ${declared.length} base chains`);
});

for (const d of declared)
  test(`${d.id} keeps the hook it was written with`, () => {
    const c = parsed.chains.find((x) => x.id === d.id);
    assert.ok(c, `${d.id} is not in the model at all`);
    assert.equal(c.hook, d.hook,
      "a chain with no hook is never walked, and nothing on any screen says so");
  });

/* `priority filter + 10` is how a chain is ordered against a well-known one.
   The header pattern wanted a bare word, so the line missed it, reached the
   rule parser, and came back as a rule carrying the `drop` out of
   `policy drop;` — a verdict nobody wrote, at the top of a chain that had
   just lost its hook. */
test("no chain header was read as a rule", () => {
  const fabricated = [];
  for (const c of parsed.chains)
    c.rules.forEach((r, i) => {
      if (/^\s*(type|policy)\s/.test(r.expr || ""))
        fabricated.push(`${c.id}:${i + 1} ${JSON.stringify(ruleLine(r))} → ${r.verdict}`);
    });
  assert.deepEqual(fabricated, []);
});

test("a priority offset is computed, and written back as it came", () => {
  const at = (id) => parsed.chains.find((c) => c.id === id);
  assert.equal(at("offset_hook").prio, 10);
  assert.equal(at("offset_hook").prioName, "filter + 10");
  assert.equal(at("offset_negative").prio, -310);
  assert.equal(at("nat_post").prio, 105);
});

test("the whole fixture comes back out as itself", () => {
  const v = verify(SRC);
  assert.equal(v.ok, v.total, `round-trip ${v.ok}/${v.total}: ${JSON.stringify(v.diffs)}`);
  assert.deepEqual(parsed.errors, []);
});

/* ── values ──────────────────────────────────────────────────────────────── */

const BASE = {
  dir: "in", iif: "wan0", oif: "wan0", saddr: "203.0.113.48", daddr: "198.51.100.10",
  sport: 49812, dport: 19000, proto: "tcp", state: "new", tracked: true, nat: true,
  flags: ["syn"],
};
const pkt = (o) => ({ ...BASE, ...o });

/* Each row is what nftables would do, not what this happens to do. A row that
   answers wrongly *and* reported nothing unread is the failure with no net. */
const CASES = [
  ["ip saddr . tcp dport @pairs", { dport: 9038 }, true],
  ["ip saddr . tcp dport @pairs", { dport: 1234 }, false],
  ["ip saddr . tcp dport @pairs", { saddr: "10.0.0.1", dport: 22 }, true],
  ["meta l4proto 6", {}, true],
  ["meta l4proto 17", {}, false],
  ["ip protocol 6", {}, true],
  ["tcp sport $HIGH", { sport: 49812 }, true],
  ["tcp sport $HIGH", { sport: 1024 }, false],
  ["iifname @ifaces", { iif: "veth9" }, true],
  ["iifname @ifaces", { iif: "eth0" }, false],
  ["ip saddr @nets", {}, true],
  ["ip saddr @nets", { saddr: "10.0.0.1" }, false],
  ["tcp dport != { 19015, 19016 }", { dport: 19017 }, true],
  ["tcp dport != { 19015, 19016 }", { dport: 19015 }, false],
  ["iifname $GUEST", { iif: "br-lan" }, true],
  ["iifname $GUEST", { iif: "wan0" }, false],
  ["ct state { new, related }", {}, true],
  ["ct state { established }", {}, false],
  ["ct status dnat", { dnat: true }, true],
  ["ct status dnat", {}, false],
  ["ip6 saddr 2001:db8::1-2001:db8::ff", { saddr: "2001:db8::42", daddr: "2001:db8::1" }, true],
  ["ip6 saddr 2001:db8::1-2001:db8::ff", { saddr: "2001:db8::1ff", daddr: "2001:db8::1" }, false],
];

for (const [expr, over, want] of CASES)
  test(`${want ? "matches" : "misses"}: ${expr}${Object.keys(over).length ? "  " + JSON.stringify(over) : ""}`,
    () => {
      load();
      const unread = unmodelled(expr);
      assert.equal(matches({ expr }, pkt(over)), want,
        unread.length ? `decided while not reading ${JSON.stringify(unread)}` : "and said nothing");
    });

/* ── honesty ─────────────────────────────────────────────────────────────── */

/* Each of these is something the evaluator has no business claiming to have
   evaluated. A verdict map decides the verdict; `fib` asks the routing table;
   `meta mark` and `meta skuid` are state this knows nothing about; and most
   conntrack statuses are bookkeeping it cannot see. */
for (const expr of [
  "meta mark 0x1",
  "fib saddr . iif oif missing",
  "meta skuid 1000",
  "ct status confirmed",
  /* not the verdict maps: those are evaluated now. What stays here is state
     that is nowhere on the packet, which no amount of reading can supply. */
  "meta length 40-1500",
  "numgen random mod 100 < 5",
])
  test(`says it did not read: ${expr}`, () => {
    load();
    assert.deepEqual(unmodelled(expr), [expr]);
  });

/* A concatenation naming a key nothing reads must be reported whole, rather
   than half evaluated on the keys that happen to be recognised. */
test("a concatenation this cannot read is left alone rather than half read", () => {
  load();
  const expr = "meta mark . tcp dport @pairs";
  assert.ok(unmodelled(expr).length, "it claimed to have read a key it does not know");
});
