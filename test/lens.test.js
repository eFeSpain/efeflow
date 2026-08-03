/* Three questions the evaluator has to answer the same way twice.
 *
 * The failure family with no net is a matcher that recognises a shape and then
 * decides wrongly: nothing is left unread, so `unmodelled()` has nothing to
 * report and the screen is confidently wrong. Two of them cost a kernel to
 * find — `meta l4proto != tcp` demanding the packet be TCP, and `fib saddr .
 * iif oif missing` comparing the packet's oif against the string "oif" — and
 * both were the same mistake: a regex reading a token that belonged to the
 * match next door.
 *
 * That mistake has a shape, and the shape can be tested without a kernel:
 *
 *   conjunction   `A B` must be `A` and `B`. Nothing else is available to a
 *                 conjunction of two matches on different header fields, so a
 *                 disagreement means one of them read the other's tokens.
 *   order         `A B` must be `B A`. nft accepts either; a matcher anchored
 *                 on what happened to come before it does not.
 *   spelling      one value written bare, braced and as a set is one value.
 *                 Three different code paths used to carry that comparison and
 *                 none of them knew about the others, which is how a port
 *                 range never matched, an address range never matched, and an
 *                 interface wildcard never matched.
 *
 * These are cheap, so the grid is wide: every atom against every other, on six
 * packets that differ in family, protocol, direction and conntrack state.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { MODEL } from "../src/core/model.js";
import { matches, unmodelled } from "../src/core/simulate.js";

Object.assign(MODEL, {
  chains: [], objects: [], tables: [], prelude: [],
  sets: [{ n: "s_port", el: ["9038"] }, { n: "s_addr", el: ["203.0.113.48"] },
         { n: "s_if", el: ["wan0"] }],
});

const PKTS = {
  tcp4: { dir: "in", iif: "wan0", oif: "", saddr: "203.0.113.48", daddr: "198.51.100.10",
          sport: 49812, dport: 9038, proto: "tcp", state: "new", tracked: true, nat: true,
          flags: ["syn"] },
  udp4: { dir: "in", iif: "lan0", oif: "", saddr: "10.10.0.5", daddr: "10.10.0.1",
          sport: 5353, dport: 53, proto: "udp", state: "new", tracked: true, nat: true,
          flags: [] },
  icmp4: { dir: "in", iif: "wan0", oif: "", saddr: "192.0.2.9", daddr: "198.51.100.10",
           sport: 0, dport: 0, proto: "icmp", state: "new", tracked: true, nat: true,
           flags: [] },
  est6: { dir: "in", iif: "wan0", oif: "", saddr: "2001:db8::42", daddr: "2001:db8::1",
          sport: 443, dport: 51234, proto: "tcp", state: "established", tracked: true,
          nat: true, flags: ["ack"] },
  fwd: { dir: "fwd", iif: "lan0", oif: "wan0", saddr: "10.10.0.44", daddr: "93.184.216.34",
         sport: 33333, dport: 443, proto: "tcp", state: "new", tracked: true, nat: true,
         flags: ["syn"] },
  out: { dir: "out", iif: "", oif: "wan0", saddr: "198.51.100.10", daddr: "1.1.1.1",
         sport: 41000, dport: 53, proto: "udp", state: "new", tracked: true, nat: true,
         flags: [] },
};

/* No two of these touch the same header field twice in a way that makes the
   conjunction anything other than the logical and. */
const ATOMS = [
  "tcp dport 9038", "tcp dport != 9038", "tcp dport { 80, 9038 }", "tcp dport 9000-9100",
  "tcp dport @s_port", "tcp dport > 1024", "tcp sport 49812", "udp dport 53", "udp sport 5353",
  "ip saddr 203.0.113.48", "ip saddr != 203.0.113.48", "ip saddr 203.0.113.0/24",
  "ip saddr @s_addr", "ip daddr 198.51.100.10", "ip6 saddr 2001:db8::42",
  "ip6 daddr 2001:db8::1",
  'iif "wan0"', 'iif != "wan0"', 'iifname "wan*"', "iifname @s_if", 'oif "wan0"', 'oifname "w*"',
  "ct state new", "ct state established", "ct state { new, related }", "ct state != invalid",
  "meta l4proto tcp", "meta l4proto != tcp", "meta l4proto { tcp, udp }", "ip protocol tcp",
  "ip protocol icmp", "ip protocol != udp", "meta nfproto ipv4", "meta nfproto ipv6",
  "tcp flags syn", "tcp flags & (fin|syn|rst|ack) == syn", "tcp flags ack",
  "icmp type echo-request", "meta mark 0x1", "ip frag-off & 0x1fff != 0",
];

/* A guess is not a claim: where `unmodelled()` names something, the answer is
   already flagged on screen and holding it to a rule would be testing the
   honesty mechanism rather than the matcher. */
const ask = (e, p) => (unmodelled(e).length ? null : matches({ expr: e }, p));

test("`A B` is `A` and `B`", () => {
  let n = 0;
  for (const [pn, p] of Object.entries(PKTS))
    for (const a of ATOMS) for (const b of ATOMS) {
      if (a === b) continue;
      const A = ask(a, p), B = ask(b, p), joint = ask(`${a} ${b}`, p);
      if (A === null || B === null || joint === null) continue;
      n++;
      assert.equal(joint, A && B,
        `${pn}: "${a}" is ${A} and "${b}" is ${B}, but together they are ${joint}`);
    }
  assert.ok(n > 5000, `only ${n} conjunctions examined`);
});

test("`A B` is `B A`", () => {
  let n = 0;
  for (const [pn, p] of Object.entries(PKTS))
    for (const a of ATOMS) for (const b of ATOMS) {
      if (a >= b) continue;
      const f = ask(`${a} ${b}`, p), r = ask(`${b} ${a}`, p);
      if (f === null || r === null) continue;
      n++;
      assert.equal(f, r, `${pn}: "${a} ${b}" is ${f} but "${b} ${a}" is ${r}`);
    }
  assert.ok(n > 2000, `only ${n} orderings examined`);
});

test("bare, braced and in a set are one value", () => {
  const SPELLINGS = [
    ["tcp dport 9038", "tcp dport { 9038 }", "tcp dport @s_port", "tcp dport 9038-9038"],
    ["ip saddr 203.0.113.48", "ip saddr { 203.0.113.48 }", "ip saddr @s_addr"],
    ['iif "wan0"', 'iif { "wan0" }', "iifname @s_if"],
    ["ct state new", "ct state { new }"],
    ["meta l4proto tcp", "meta l4proto { tcp }"],
  ];
  for (const [pn, p] of Object.entries(PKTS))
    for (const group of SPELLINGS) {
      const answers = group.map((e) => ask(e, p));
      if (answers.some((a) => a === null)) continue;
      assert.equal(new Set(answers).size, 1,
        `${pn}: ${group.map((e, i) => `"${e}"=${answers[i]}`).join("  ")}`);
    }
});

/* A lens that cannot see a defect agrees with everything. These are the cases
   a matcher built out of independent regexes gets wrong, and each of them has
   to come out false. */
test("and the same three questions catch a matcher that reads its neighbour", () => {
  const P = PKTS.tcp4;
  const impossible = [
    /* one field cannot hold two values */
    ["tcp dport 9038 tcp dport 22", "the same field twice"],
    ["tcp dport 22 tcp dport 9038", "and in the other order"],
    /* a negation belongs to the match that wrote it, not to the rule */
    ["ip saddr 203.0.113.48 tcp dport != 9038", "the != is the dport's alone"],
    ["tcp dport != 22 ip saddr 1.2.3.4", "the saddr does not agree"],
    /* a protocol named as somebody else's value is not a protocol match */
    ["meta l4proto != tcp tcp dport 9038", "these two contradict each other"],
  ];
  for (const [expr, why] of impossible)
    assert.equal(matches({ expr }, P), false, `${expr} — ${why}`);
  assert.equal(matches({ expr: 'ip saddr 203.0.113.48 iif "wan0" tcp dport 9038' }, P), true,
    "and three that do agree still match");
});
