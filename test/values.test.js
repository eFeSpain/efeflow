/* Every shape nftables can write a value in, against a packet that should or
 * should not match it.
 *
 * This file exists because of how the `$WAN` bug was found and what it implied.
 * The evaluator has two ways of not understanding something. If it does not
 * recognise the construct, `unmodelled()` reports it and the verdict is marked
 * as a guess — that path is honest and it works. But if a matcher *does*
 * recognise the shape and then compares the value wrongly, nothing is left
 * over to report, so the screen shows a confident wrong answer. There is no
 * net under that one.
 *
 * So the question worth asking was not "is there another bug" but "what else
 * does a matcher accept and then compare as text". The answer was four things,
 * and they were all in production rulesets:
 *
 *   udp dport 5060-5070            a port range never matched
 *   ip saddr 10.0.0.1-10.0.0.9     nor an address range
 *   iifname "veth*"                nor a wildcard, on any host running containers
 *   elements = { 1.1.1.1 timeout 30m }   nor a set element the kernel timestamps
 *
 * Sets, braced lists and bare tokens each carried their own half of the
 * comparison and no half knew about any of it. They go through one function
 * now, so a shape learned once is learned everywhere.
 *
 * The negative cases are the point as much as the positive ones: a range that
 * matches everything is not a fix, it is the same bug facing the other way. */
import test from "node:test";
import assert from "node:assert/strict";
import { MODEL } from "../src/core/model.js";
import { matches, unmodelled } from "../src/core/simulate.js";

const PKT = {
  dir: "in", iif: "wan0", oif: "", saddr: "203.0.113.48", daddr: "198.51.100.10",
  sport: 49812, dport: 9038, proto: "tcp", state: "new", tracked: true, nat: true,
  flags: ["syn"],
};

const SETS = [
  { n: "ports", el: ["9000-9100"] },
  { n: "nets", el: ["203.0.113.0/24 timeout 30m", "198.51.100.7"] },
  { n: "ifs", el: ["veth*", "wan0"] },
  { n: "plain", el: ["9038", "22"] },
];

const load = () =>
  Object.assign(MODEL, { chains: [], sets: SETS, objects: [], tables: [], prelude: [] });

/** true/false, and whether anything was left unread while deciding. */
function check(expr, packet = PKT) {
  load();
  return { hit: matches({ expr }, packet), unread: unmodelled(expr) };
}

const hits = (expr, want, packet) =>
  test(`${want ? "matches" : "misses"}: ${expr}`, () => {
    const { hit, unread } = check(expr, packet);
    assert.equal(hit, want,
      unread.length ? `decided while not reading ${JSON.stringify(unread)}` : "wrong answer");
  });

/* ── port ranges ─────────────────────────────────────────────────────────── */

hits("tcp dport 9038", true);
hits("tcp dport 9000-9100", true);
hits("tcp dport { 80, 9000-9100 }", true);
hits("tcp dport 1-65535", true);
hits("tcp dport @ports", true);
hits("tcp dport 9100-9200", false);
hits("tcp dport 9039-9100", false);
hits("tcp dport != 9000-9100", false);
/* the boundaries are inclusive, which is what nft means by a range */
hits("tcp dport 9038-9038", true);
hits("udp dport 9000-9100", false, { ...PKT, proto: "tcp" });

/* ── address ranges ──────────────────────────────────────────────────────── */

hits("ip saddr 203.0.113.1-203.0.113.99", true);
hits("ip saddr 203.0.113.60-203.0.113.99", false);
hits("ip saddr { 1.1.1.1, 203.0.113.1-203.0.113.99 }", true);
/* a range of one family is never a constraint on the other */
hits("ip6 saddr 2001:db8::1-2001:db8::ff", false);
hits("ip6 saddr 2001:db8::1-2001:db8::ff", true,
  { ...PKT, saddr: "2001:db8::42", daddr: "2001:db8::1" });

/* ── interface wildcards ─────────────────────────────────────────────────── */

hits('iifname "wan*"', true);
hits('iifname "w*"', true);
hits('iifname "lan*"', false);
hits('iifname "wan01*"', false);
hits('iifname { "veth*", "wan*" }', true);
hits('iifname { "veth*", "lan0" }', false);
hits('iifname != "veth*"', true);
hits("iifname @ifs", true);
hits("iifname @ifs", true, { ...PKT, iif: "veth7a3f" });
hits("iifname @ifs", false, { ...PKT, iif: "eth0" });

/* A name is not a range. `wan0-guest` is one interface, and reading the dash
   as nftables' range syntax would have made it two things and matched
   neither. */
hits('iifname "wan0-guest"', true, { ...PKT, iif: "wan0-guest" });
hits('iifname "wan0-guest"', false);

/* ── elements the kernel has attached its own bookkeeping to ─────────────── */

/* `elements = { 203.0.113.0/24 timeout 30m }` is what a live host prints back
   for any set with timeouts, and the shape fail2ban writes. Compared whole,
   the element stopped matching the moment the kernel touched it. */
test("a set element carrying a timeout still matches", () => {
  assert.equal(check("ip saddr @nets").hit, true);
  assert.equal(check("ip saddr @nets", { ...PKT, saddr: "10.0.0.1" }).hit, false);
});

/* ── and the honest path is still honest ─────────────────────────────────── */

/* None of the above may come at the cost of the other half of the bargain:
   what the evaluator cannot read, it still says it cannot read. */
test("a construct nothing models is still reported rather than guessed at", () => {
  const { unread } = check("meta mark 0x1 tcp dport 9038");
  assert.deepEqual(unread, ["meta mark 0x1"]);
});

test("a value shape that is understood leaves nothing unread", () => {
  for (const e of ["tcp dport 9000-9100", 'iifname "wan*"', "ip saddr @nets"])
    assert.deepEqual(check(e).unread, [], e);
});

/* ── comparisons that are not equality ───────────────────────────────────── */

/* nftables compares with more than `==`, and `tcp dport >= 1024` is where it
   is usually written: the rule about ephemeral ports. The matcher read the
   operator as the value it was comparing against, so every one of them was a
   certain miss — and a miss is never reported as a guess. */

hits("tcp dport > 1024", true);
hits("tcp dport >= 9038", true);
hits("tcp dport >= 9039", false);
hits("tcp dport < 1024", false);
hits("tcp dport <= 9038", true);
hits("tcp dport > 9038", false);
hits("tcp sport > 1024", true);
hits("tcp sport < 1024", false);
/* the protocol still has to agree */
hits("udp dport > 1024", false);
/* and equality, sets and ranges are untouched by any of it */
hits("tcp dport 9038", true);
hits("tcp dport != 9038", false);
hits("tcp dport { 80, 9038 }", true);
hits("tcp dport 9000-9100", true);

/* A bitwise mask on an address is a prefix test written the long way. Nothing
   here evaluates one, and the address matcher was reading the `&` as the
   address — so it is struck out and named rather than answered. */
test("a bitwise mask on an address is declared, not guessed at", () => {
  for (const expr of ["ip saddr & 255.255.255.0 == 203.0.113.0", "ip daddr & 0xff != 0"]) {
    const { hit, unread } = check(expr);
    assert.equal(hit, true, "a rule this cannot read is taken as matching");
    assert.deepEqual(unread, [expr], "and the whole of it is named");
  }
});

/* ── a key is not just a field ───────────────────────────────────────────── */

/* `tcp dport` is not "the destination port": it is the destination port of a
   TCP packet, and on a UDP one the lookup does not happen at all. The
   standalone matcher had always checked that; the concatenation table did not,
   so a UDP packet matched `ip saddr . tcp dport @pairs`.
 *
 * Found by asking the kernel — a real packet through a real netfilter instance
 * — which is the only reason it was found at all. Every table of cases in this
 * directory is still this project stating what nftables does. */
test("a concatenation on tcp dport says nothing about a udp packet", () => {
  Object.assign(MODEL, {
    chains: [], objects: [], tables: [], prelude: [],
    sets: [{ n: "pairs", el: ["203.0.113.48 . 9038"] }],
  });
  const expr = "ip saddr . tcp dport @pairs";
  assert.equal(matches({ expr }, PKT), true, "the TCP packet it was written for");
  assert.equal(matches({ expr }, { ...PKT, proto: "udp" }), false);
});

test("and a concatenation on ip saddr says nothing about a v6 packet", () => {
  Object.assign(MODEL, {
    chains: [], objects: [], tables: [], prelude: [],
    sets: [{ n: "pairs", el: ["203.0.113.48 . 9038"] }],
  });
  assert.equal(matches({ expr: "ip saddr . tcp dport @pairs" },
    { ...PKT, saddr: "2001:db8::1", daddr: "2001:db8::2" }), false);
});

test("a verdict map is the same: no key, no lookup", async () => {
  const { vmapVerdict } = await import("../src/core/simulate.js");
  Object.assign(MODEL, {
    chains: [], objects: [], tables: [], prelude: [],
    sets: [{ n: "by_port", el: ["9038 : accept"] }],
  });
  assert.equal(vmapVerdict("tcp dport vmap @by_port", PKT), "accept");
  assert.equal(vmapVerdict("tcp dport vmap @by_port", { ...PKT, proto: "udp" }), null,
    "the rule does not fire on a packet the key cannot be read from");
});

test("and so is a NAT target that is a lookup", async () => {
  const { natLookup } = await import("../src/core/simulate.js");
  Object.assign(MODEL, {
    chains: [], objects: [], tables: [], prelude: [],
    sets: [{ n: "fwd", el: ["9038 : 10.0.0.1"] }],
  });
  assert.equal(natLookup("tcp dport map @fwd", PKT).to, "10.0.0.1");
  assert.equal(natLookup("tcp dport map @fwd", { ...PKT, proto: "udp" }).missed, true);
});

/* ── a protocol named as somebody else's value ───────────────────────────── */

/* `meta l4proto != tcp` is a rule that catches everything which is not TCP,
   and the bare-protocol matcher was reading the `tcp` out of the middle of it
   and demanding the packet be TCP — turning the negation into its opposite. An
   ICMP packet missed a rule written precisely to catch it.
 *
 * Found by asking the kernel. No table of cases here would have caught it,
 * because the case would have been written by whoever wrote the bug. */
test("a protocol written as a value belongs to the match that names it", () => {
  Object.assign(MODEL, { chains: [], sets: [], objects: [], tables: [], prelude: [] });
  const icmp = { ...PKT, proto: "icmp" };
  assert.equal(matches({ expr: "meta l4proto != tcp" }, icmp), true);
  assert.equal(matches({ expr: "meta l4proto != tcp" }, PKT), false);
  assert.equal(matches({ expr: "ip protocol != tcp" }, icmp), true);
  assert.equal(matches({ expr: "meta l4proto != { tcp, udp }" }, icmp), true);
});

test("and a protocol named on its own still constrains", () => {
  Object.assign(MODEL, { chains: [], sets: [], objects: [], tables: [], prelude: [] });
  assert.equal(matches({ expr: "tcp dport 9038" }, { ...PKT, proto: "udp" }), false);
  assert.equal(matches({ expr: "icmp type echo-request" }, PKT), false, "the packet is TCP");
  assert.equal(matches({ expr: "meta l4proto tcp" }, PKT), true);
  assert.equal(matches({ expr: "meta l4proto { tcp, udp }" }, PKT), true);
  assert.equal(matches({ expr: "meta l4proto { udp, icmp }" }, PKT), false);
});
