/* Two modules that never speak to each other, made to agree.
 *
 * analyse.js decides a rule is shadowed by comparing criteria: it says rule A
 * catches everything rule B could, and offers a button that deletes B.
 * simulate.js decides, packet by packet, whether a rule matches. Neither knows
 * the other exists, and the whole of `subsumes()` is one project's reading of
 * set containment written by hand.
 *
 * So the claim has a consequence the evaluator can be held to: if A subsumes B
 * then no packet matches B without also matching A. One counterexample and the
 * Delete button is offering to remove a rule that fires.
 *
 * That is worth more than the same question asked of a kernel, which is how
 * these findings were checked first. A kernel can only be asked about the
 * findings that happen to be in a handful of rulesets — five, as it turned out,
 * across every sample and fixture here plus a real edge firewall, because real
 * rulesets are not written to trip an analyser. This asks about every pair in
 * a grid built to trip it, and throws several hundred packets at each answer.
 *
 * The grid is deliberately full of the shapes subsumption is easy to get wrong
 * on: a set against a longer set, a prefix against a wider prefix, a range
 * against an overlapping range, `> 1024` against `>= 80`, a negation against
 * anything, and one field's constraint next to another's.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { MODEL } from "../src/core/model.js";
import { subsumes, criteria } from "../src/core/analyse.js";
import { matches, unmodelled } from "../src/core/simulate.js";

const SETS = [
  { n: "g_ports", el: ["22", "80"] },
  { n: "g_nets", el: ["10.0.0.0/24"] },
  { n: "g_ifs", el: ["wan0", "lan0"] },
];
Object.assign(MODEL, { chains: [], objects: [], tables: [], prelude: [], sets: SETS });

const GRID = [];
for (const f of ["dport", "sport"])
  for (const pr of ["tcp", "udp"])
    for (const v of ["22", "80", "443", "1024", "{ 22, 80 }", "{ 22, 80, 443 }", "22-80",
                     "80-443", "1-65535", "@g_ports", "> 1024", ">= 80", "< 1024", "!= 22"])
      GRID.push(`${pr} ${f} ${v}`);
for (const f of ["saddr", "daddr"])
  for (const v of ["10.0.0.1", "10.0.0.0/24", "10.0.0.0/8", "10.0.0.0/16", "0.0.0.0/0",
                   "{ 10.0.0.1, 10.0.0.2 }", "10.0.0.1-10.0.0.9", "@g_nets", "!= 10.0.0.1"])
    GRID.push(`ip ${f} ${v}`);
for (const k of ["iif", "oif", "iifname", "oifname"])
  for (const v of ['"wan0"', '"lan0"', '"wan*"', '{ "wan0", "lan0" }', "@g_ifs"])
    GRID.push(`${k} ${v}`);
for (const v of ["new", "established", "{ new, established }", "{ established, related }",
                 "invalid", "!= invalid"]) GRID.push(`ct state ${v}`);
for (const v of ["tcp", "udp", "{ tcp, udp }", "!= tcp"]) GRID.push(`meta l4proto ${v}`);
/* subsumption over one field is the easy half; these are the other one. The
   base is fixed before the pairs are made, or the loop feeds on its own
   output and never ends. */
const SINGLE = GRID.length;
for (let a = 0; a < SINGLE; a += 7)
  for (let b = 1; b < SINGLE; b += 11)
    if (GRID[a] !== GRID[b]) GRID.push(`${GRID[a]} ${GRID[b]}`);

/* A fixed seed, because a test that fails one run in twenty teaches nobody
   anything. Any counterexample it finds is reproducible from the message. */
let seed = 0x5eed1234;
const rnd = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
const pick = (a) => a[(rnd() * a.length) | 0];

const ADDRS = ["10.0.0.1", "10.0.0.2", "10.0.0.9", "10.0.0.99", "10.0.1.1", "10.1.0.1",
               "9.255.255.255", "11.0.0.1", "192.168.1.1", "203.0.113.9", "0.0.0.0"];
const PORTS = [0, 21, 22, 23, 79, 80, 81, 442, 443, 444, 1023, 1024, 1025, 65535];
const IFS = ["lo", "wan0", "lan0", "wan1", "wanted", "eth0", ""];
const STATES = ["new", "established", "related", "invalid", "untracked"];
const PROTOS = ["tcp", "udp", "icmp", "sctp"];
const FLAGS = [[], ["syn"], ["ack"], ["syn", "ack"], ["fin"], ["rst"]];

const packet = () => ({
  dir: "in", iif: pick(IFS), oif: pick(IFS),
  saddr: pick(ADDRS), daddr: pick(ADDRS), sport: pick(PORTS), dport: pick(PORTS),
  proto: pick(PROTOS), state: pick(STATES), tracked: true, nat: true, flags: pick(FLAGS),
});

test("no rule the analyser calls shadowed is one a packet reaches", () => {
  const crit = new Map(GRID.map((e) => [e, criteria(e)]));
  let claims = 0, shots = 0;
  for (const a of GRID) for (const b of GRID) {
    if (a === b || !subsumes(crit.get(a), crit.get(b))) continue;
    claims++;
    /* the evaluator must not be quoted on what it says it cannot read */
    if (unmodelled(a).length || unmodelled(b).length) continue;
    for (let k = 0; k < 300; k++) {
      const p = packet();
      shots++;
      if (matches({ expr: b }, p) && !matches({ expr: a }, p))
        assert.fail(`"${a}" is said to catch everything of "${b}", but `
          + `${p.proto} ${p.saddr}:${p.sport} -> ${p.daddr}:${p.dport} `
          + `iif=${p.iif || "-"} oif=${p.oif || "-"} ${p.state} [${p.flags}] `
          + `matches the second and not the first`);
    }
  }
  /* a lens that examines nothing agrees with everything */
  assert.ok(claims > 500, `only ${claims} subsumption claims to examine`);
  assert.ok(shots > 100000, `only ${shots} packets thrown`);
});

/* The other half of the bargain. If the fuzzer generated packets no rule
   matched, the test above would pass on a broken `subsumes()`, so the same
   machinery is pointed at pairs that are *not* subsumptions and has to refute
   every one of them. */
test("and the same fuzzer refutes a containment that is not true", () => {
  const NOT = [
    ["tcp dport 22", "tcp dport 80"],
    ["ip saddr 10.0.0.0/24", "ip saddr 10.0.0.0/8"],
    ["ct state new", "ct state established"],
    ["tcp dport { 22, 80 }", "tcp dport { 22, 80, 443 }"],
    ['iif "wan0"', 'iifname "wan*"'],
    ["tcp dport 22-80", "tcp dport 80-443"],
    ["tcp dport > 1024", "tcp dport >= 80"],
    ["meta l4proto tcp", "meta l4proto { tcp, udp }"],
  ];
  for (const [a, b] of NOT) {
    assert.equal(subsumes(criteria(a), criteria(b)), false,
      `"${a}" does not catch everything of "${b}"`);
    let found = false;
    for (let k = 0; k < 4000 && !found; k++) {
      const p = packet();
      found = matches({ expr: b }, p) && !matches({ expr: a }, p);
    }
    assert.ok(found, `the fuzzer never separated "${a}" from "${b}" — it is not looking`);
  }
});
