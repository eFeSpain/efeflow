/* The analyser was made ~30× faster. This is the part that says it still says
 * the same things.
 *
 * A stress run showed one gesture costing 891 ms on a thousand-rule ruleset —
 * `analyse()` runs on every model change, so that was the price of toggling a
 * rule off. A profile put the time in address parsing, not in the shadowing
 * logic: `ip saddr @blocked` against a 200-prefix set re-parsed all 200, from
 * the dotted string up, for every pair of rules that named it.
 *
 * Two changes, neither of which may alter a single finding: addresses are
 * parsed once per string, and set membership is remembered for the length of
 * one analyse() and thrown away at the end of it. So the test is not a
 * stopwatch — it is that the answers are identical to the ones a deliberately
 * naive implementation gives. */
import test from "node:test";
import assert from "node:assert/strict";

import { parseNft } from "../src/core/parse.js";
import { analyse, criteria, subsumes } from "../src/core/analyse.js";
import { inSet } from "../src/core/simulate.js";
import { covers as addrCovers } from "../src/core/addr.js";
import { MODEL } from "../src/core/model.js";
import { flawedSource } from "./fixture.js";

/* Enough rules, sets and shapes for the fast paths to matter, small enough to
   stay a unit test. */
function ruleset(n) {
  const L = ["table inet fw {", "\tset blocked {", "\t\ttype ipv4_addr ; flags interval",
    "\t\telements = { " + Array.from({ length: 40 }, (_, i) => `10.${i}.0.0/16`).join(", ") + " }",
    "\t}", "", "\tset ports {", "\t\ttype inet_service",
    "\t\telements = { " + Array.from({ length: 20 }, (_, i) => 3000 + i).join(", ") + " }",
    "\t}", "", "\tchain input {",
    "\t\ttype filter hook input priority 0; policy drop;"];
  for (let i = 0; i < n; i++) {
    const shape = i % 6;
    L.push("\t\t" + [
      `ip saddr @blocked counter drop`,
      `tcp dport ${2000 + (i % 50)} ip saddr 10.${i % 40}.1.0/24 counter accept`,
      `tcp dport @ports counter accept`,
      `ip6 saddr 2001:db8::/32 tcp dport ${4000 + (i % 30)} counter accept`,
      `ip saddr 10.${i % 40}.0.0/16 counter accept`,
      `udp dport ${5000 + (i % 20)} counter accept`,
    ][shape]);
  }
  L.push("\t}", "}");
  return L.join("\n");
}

function load(src) {
  const p = parseNft(src);
  Object.assign(MODEL, {
    chains: p.chains, sets: p.sets, objects: p.objects,
    tables: p.tables, prelude: p.prelude,
  });
  return p;
}

const CRIT_KEYS = ["proto", "l4", "state", "ctst", "iif", "oif", "saddr", "daddr", "sport", "dport"];

/* subsumes(), written the slow obvious way, with nothing remembered between
   calls. If the two ever disagree, the optimisation changed an answer. */
const listOf = (v) => (v.startsWith("{") ? v.slice(1, -1).split(",").map((s) => s.trim()) : [v]);
function naiveCovers(a, b) {
  if (a === b) return true;
  const A = listOf(a), B = listOf(b);
  if (B.every((x) => A.includes(x))) return true;
  if (a.startsWith("@")) return B.every((x) => inSet(x, a.slice(1)));
  return B.every((x) => addrCovers(a, x));
}
function naiveSubsumes(a, b) {
  if (a._limit || a._negate || b._negate) return false;
  if (a._opaque) return false;
  return CRIT_KEYS.every((k) => {
    if (a[k] === undefined) return true;
    if (b[k] === undefined) return false;
    return naiveCovers(a[k], b[k]);
  });
}

test("the fast subsumes answers exactly what the slow one answers", () => {
  load(ruleset(120));
  const rules = MODEL.chains[0].rules.map((r) => criteria(r.expr));
  let pairs = 0, agreed = 0;
  for (const a of rules)
    for (const b of rules) {
      pairs++;
      if (subsumes(a, b) === naiveSubsumes(a, b)) agreed++;
    }
  assert.ok(pairs > 10000, "the comparison has to be wide enough to be worth making");
  assert.equal(agreed, pairs, "the optimisation changed an answer");
});

/* The bitmask says: if A constrains something B leaves open, A cannot cover B.
   That is the first thing the old loop asked, hoisted out of it. */
test("the criteria bitmask agrees with the criteria themselves", () => {
  load(ruleset(60));
  for (const r of MODEL.chains[0].rules) {
    const c = criteria(r.expr);
    CRIT_KEYS.forEach((k, i) => {
      assert.equal(!!(c._bits & (1 << i)), c[k] !== undefined,
        `${k} disagrees with the bit that stands for it in "${r.expr}"`);
    });
  }
});

/* The set memo lives for one analyse() and no longer, because subsumes() and
   overlaps() are exported and a caller may have edited a set since. */
test("editing a set between runs changes the answer", () => {
  load(`table inet fw {
\tset admin {
\t\ttype ipv4_addr ; flags interval
\t\telements = { 10.0.0.0/8 }
\t}

\tchain input {
\t\ttype filter hook input priority 0; policy drop;
\t\tip saddr @admin counter accept
\t\tip saddr 192.168.4.7 counter accept
\t}
}`);
  assert.equal(analyse().filter((f) => f.kind === "shadowed").length, 0,
    "192.168.4.7 is not inside 10.0.0.0/8");

  /* widen the set: now the first rule really does cover the second */
  MODEL.sets[0].el = ["10.0.0.0/8", "192.168.0.0/16"];
  const after = analyse().filter((f) => f.kind === "shadowed");
  assert.equal(after.length, 1, "a set that grew must be read as it is now, not as it was");
  assert.equal(after[0].i, 1);
});

/* The findings of the shipped fixture, whole, so any change to the reasoning
   has to be a deliberate one. */
test("the fixture still reports what it reported", () => {
  load(flawedSource());
  const kinds = analyse().map((f) => `${f.sev}/${f.kind}`).sort();
  assert.deepEqual(kinds, [
    "error/conflict", "hint/merge", "hint/resilience", "hint/unused",
    "warn/hardening", "warn/shadowed",
  ]);
});
