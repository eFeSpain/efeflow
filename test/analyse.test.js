import test from "node:test";
import assert from "node:assert/strict";

import { MODEL, ruleLine } from "../src/core/model.js";
import { analyse, worstCase, subsumes, criteria } from "../src/core/analyse.js";

const kinds = (f) => f.map((x) => x.kind).sort();

test("the demo ruleset yields exactly the defects it contains", () => {
  const f = analyse();
  assert.deepEqual(kinds(f), ["conflict", "hardening", "merge", "resilience", "shadowed", "unused"]);
  assert.equal(f.filter((x) => x.sev === "error").length, 1);
  assert.equal(f[0].kind, "conflict", "errors sort first");
});

test("subsumption is about coverage, not text", () => {
  const broad = criteria("tcp dport { 80, 443 }");
  const narrow = criteria("ip saddr 10.10.0.0/24 tcp dport 443");
  assert.ok(subsumes(broad, narrow), "a wider port set covers the narrower rule");
  assert.ok(!subsumes(narrow, broad), "and not the other way round");
});

test("a rate-limited rule never shadows anything", () => {
  const limited = criteria("limit rate 5/second");
  const anything = criteria("tcp dport 22");
  assert.ok(!subsumes(limited, anything), "non-deterministic rules cannot be reasoned about");
});

test("conntrack criteria do not create false positives", () => {
  const stateful = criteria("ct state established,related");
  const plain = criteria("tcp dport 22 ip saddr @admin_nets");
  assert.ok(!subsumes(stateful, plain), "a state match is narrower, not broader");
});

test("every finding carries a fix, and applying them all converges", () => {
  let guard = 0;
  while (guard++ < 25) {
    const next = analyse().find((f) => f.fix);
    if (!next) break;
    next.fix.run();
  }
  assert.equal(analyse().length, 0, "the analyser should be satisfiable");
  assert.ok(guard < 25, "and converge without thrashing");
});

test("worst case is measured over hooks, not chain names", () => {
  const n = worstCase();
  assert.ok(Number.isInteger(n) && n > 0, `got ${n}`);
  const before = n;
  MODEL.chains.forEach((c) => c.rules.forEach((r) => (r.on = false)));
  assert.ok(worstCase() < before, "disabling every rule must lower the cost");
});
