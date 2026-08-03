/* `define WAN = wan0` above the first table, and `$WAN` in fifty rules below.
 *
 * The parser keeps both, and on purpose: the definitions in `prelude`, the
 * references verbatim in the rules. That is what makes the round-trip exact
 * and what lets a file come back out looking like the file that went in.
 *
 * Nothing resolved them. So the evaluator compared a packet arriving on wan0
 * against the string "$WAN" and missed, and it missed on every rule of the
 * chain, and the packet fell through a port-forwarding table that should have
 * caught it into a catch-all drop three chains later. The screen said DROP
 * with a straight face.
 *
 * That is the failure mode this whole application is built to refuse: not a
 * gap it admits to, but a confident wrong answer, on a ruleset written the way
 * most real ones are written. Found by pointing it at somebody's actual
 * firewall, which is exactly what the README asks people to do.
 *
 * The rules keep their text; only the reasoning sees the expansion. */
import test from "node:test";
import assert from "node:assert/strict";
import { parseNft, verify } from "../src/core/parse.js";
import { MODEL, expand, defines, ruleLine } from "../src/core/model.js";
import { matches, evaluate, setPacket, packet } from "../src/core/simulate.js";
import { criteria, subsumes } from "../src/core/analyse.js";

const load = (src) => {
  const p = parseNft(src);
  Object.assign(MODEL, {
    chains: p.chains, sets: p.sets, objects: p.objects,
    tables: p.tables, prelude: p.prelude,
  });
  return p;
};

const PRELUDE = [
  "define WAN = wan0",
  'define LAN = "br-lan"',
  "define MGMT = 10.10.0.0/24",
  "define PORTS = { 80, 443 }",
  "define EDGE = $WAN",
];

const RULESET = [
  ...PRELUDE,
  "",
  "table inet fw {",
  "\tchain input {",
  "\t\ttype filter hook input priority filter; policy drop;",
  "\t\tiifname $WAN tcp dport 9038 accept",
  "\t\tip saddr $MGMT tcp dport 22 accept",
  "\t\tiifname $LAN accept",
  "\t\ttcp dport $PORTS accept",
  "\t}",
  "}",
].join("\n");

/* ── the expansion itself ────────────────────────────────────────────────── */

test("a define is read whether it was quoted or not", () => {
  load(RULESET);
  const d = defines(MODEL);
  assert.equal(d.get("WAN"), "wan0");
  assert.equal(d.get("LAN"), "br-lan", "the quotes belong to nft, not to the value");
  assert.equal(d.get("MGMT"), "10.10.0.0/24");
});

test("a define that names another define resolves through", () => {
  load(RULESET);
  assert.equal(expand("iifname $EDGE"), "iifname wan0");
});

test("a name with no definition is left exactly as written", () => {
  load(RULESET);
  assert.equal(expand("iifname $NOPE"), "iifname $NOPE",
    "an include could have provided it, and inventing a value is worse than saying nothing");
});

test("a define that names itself stops instead of hanging", () => {
  Object.assign(MODEL, { chains: [], sets: [], objects: [], tables: [],
                         prelude: ["define A = $B", "define B = $A"] });
  const out = expand("iifname $A");
  assert.ok(typeof out === "string", "it returned at all");
});

test("an expression with no dollar sign is handed straight back", () => {
  load(RULESET);
  assert.equal(expand('iifname "lo" accept'), 'iifname "lo" accept');
});

/* ── what the evaluator does with it ─────────────────────────────────────── */

const PKT = {
  dir: "in", iif: "wan0", oif: "", saddr: "203.0.113.48", daddr: "198.51.100.10",
  sport: 49812, dport: 9038, proto: "tcp", state: "new", tracked: true, nat: true,
  flags: ["syn"],
};

test("a rule naming an interface through a define matches the packet on it", () => {
  load(RULESET);
  assert.equal(matches({ expr: "iifname $WAN tcp dport 9038" }, PKT), true);
  assert.equal(matches({ expr: "iifname $LAN" }, PKT), false, "and still misses the wrong one");
});

test("an address and a set reach through a define too", () => {
  load(RULESET);
  assert.equal(matches({ expr: "ip saddr $MGMT" }, { ...PKT, saddr: "10.10.0.9" }), true);
  assert.equal(matches({ expr: "ip saddr $MGMT" }, PKT), false);
  assert.equal(matches({ expr: "tcp dport $PORTS" }, { ...PKT, dport: 443 }), true);
  assert.equal(matches({ expr: "tcp dport $PORTS" }, PKT), false);
});

test("the packet reaches the rule written for it, rather than the drop below", () => {
  load(RULESET);
  setPacket(PKT);
  const r = evaluate(packet);
  assert.equal(r.final.v, "accept");
  assert.equal(r.final.i, 0, "the first rule, which is the one naming $WAN");
});

/* ── and what the analyser does ──────────────────────────────────────────── */

/* The opacity test asks whether anything in the rule went unread. It compared
   the masked expression against the source, which after this change differs
   for every rule carrying a variable — and an opaque rule is one subsumes()
   refuses to reason about, so the analyser would have quietly retired itself
   on exactly the rulesets this was written to fix. */
test("a rule using a define is not mistaken for one nothing could read", () => {
  load(RULESET);
  assert.equal(criteria("iifname $WAN tcp dport 9038")._opaque, false);
  assert.equal(criteria("iifname wan0 tcp dport 9038")._opaque, false);
  assert.equal(criteria("meta mark 0x1")._opaque, true, "and a real one still is");
});

test("the analyser reads a define as the interface it names", () => {
  load(RULESET);
  assert.equal(criteria("iifname $WAN tcp dport 9038").iif, "wan0");
  const broad = criteria("iifname $WAN");
  const narrow = criteria("iifname wan0 tcp dport 9038");
  assert.equal(subsumes(broad, narrow), true,
    "the same interface written two ways is the same interface");
});

/* ── the file still comes back out as itself ─────────────────────────────── */

/* Nothing above may cost the round-trip. The reasoning sees wan0; the rule is
   still `$WAN`, and the export is still the file somebody wrote. */
test("expanding for the evaluator does not rewrite the rule", () => {
  const p = load(RULESET);
  assert.equal(ruleLine(p.chains[0].rules[0]), "iifname $WAN tcp dport 9038 accept");
  const v = verify(RULESET);
  assert.equal(v.ok, v.total, `round-trip ${v.ok}/${v.total}: ${JSON.stringify(v.diffs)}`);
});
