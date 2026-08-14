/* The ruleset as a graph: what the canvas wires together, and what it calls
 * unreachable. A wire is a path a packet takes, so two families that never
 * share a packet must not be joined, and two chains at one priority must not be
 * put in an order nftables does not promise. */
import test from "node:test";
import assert from "node:assert/strict";
import { UID } from "../src/core/model.js";
import { wirePlan, reachable, classesOf } from "../src/core/topology.js";

const chain = (o) => ({ prio: 0, type: "filter", policy: "accept", rules: [], ...o });
const jump = (to) => ({ verdict: "jump", to, expr: "" });

/* wirePlan returns [from, to, isJump]; solid = packet path, dashed = a call */
const solids = (plan) => plan.filter((e) => !e[2]).map((e) => e[0] + "→" + e[1]);
const has = (plan, a, b) => solids(plan).includes(UID(a) + "→" + UID(b));

test("ip and ip6 chains on the same hook are never wired together", () => {
  const v4 = chain({ table: "ip filter", id: "in4", hook: "input", prio: 0 });
  const v6 = chain({ table: "ip6 filter", id: "in6", hook: "input", prio: 10 });
  const plan = wirePlan([v4, v6]);
  assert.equal(has(plan, v4, v6), false, "a v4 chain was wired to a v6 chain");
  assert.equal(has(plan, v6, v4), false);
  assert.equal(solids(plan).length, 0, "no packet traverses both, so no wire at all");
});

test("inet sits on both the v4 and the v6 path, ip and ip6 on only their own", () => {
  const inet = chain({ table: "inet filter", id: "base", hook: "input", prio: 0 });
  const v4 = chain({ table: "ip filter", id: "in4", hook: "input", prio: 10 });
  const v6 = chain({ table: "ip6 filter", id: "in6", hook: "input", prio: 20 });
  const plan = wirePlan([inet, v4, v6]);
  assert.ok(has(plan, inet, v4), "inet should feed the ip chain for a v4 packet");
  assert.ok(has(plan, inet, v6), "inet should feed the ip6 chain for a v6 packet");
  assert.equal(has(plan, v4, v6), false, "but ip must never feed ip6");
});

test("inet feeds both classes:", () => {
  assert.deepEqual(classesOf({ table: "inet filter" }), ["v4", "v6"]);
  assert.deepEqual(classesOf({ table: "ip nat" }), ["v4"]);
  assert.deepEqual(classesOf({ table: "ip6 filter" }), ["v6"]);
});

test("two chains at the same priority are not put in an invented order", () => {
  const a = chain({ table: "inet filter", id: "a", hook: "input", prio: 0 });
  const b = chain({ table: "inet filter", id: "b", hook: "input", prio: 0 });
  const plan = wirePlan([a, b]);
  assert.equal(has(plan, a, b), false, "a definite order between tied chains is a claim nftables does not make");
  assert.equal(has(plan, b, a), false);
});

test("a predecessor fans out to both chains of a tied pair", () => {
  const first = chain({ table: "inet filter", id: "first", hook: "input", prio: 0 });
  const tieA = chain({ table: "inet filter", id: "ta", hook: "input", prio: 10 });
  const tieB = chain({ table: "inet filter", id: "tb", hook: "input", prio: 10 });
  const plan = wirePlan([first, tieA, tieB]);
  assert.ok(has(plan, first, tieA), "the tie's first member is reached");
  assert.ok(has(plan, first, tieB), "and so is the second — order between them unstated, both reached");
});

test("the packet path runs prerouting → input across hooks", () => {
  const pre = chain({ table: "ip nat", id: "pre", hook: "prerouting", prio: -100 });
  const inp = chain({ table: "ip filter", id: "in", hook: "input", prio: 0 });
  const plan = wirePlan([pre, inp]);
  assert.ok(has(plan, pre, inp), "the last chain of prerouting feeds the first of input");
});

test("a jump is a dashed edge, and a jump to nowhere is no edge", () => {
  const base = chain({ table: "inet filter", id: "input", hook: "input",
    rules: [jump("clean"), jump("ghost")] });
  const clean = chain({ table: "inet filter", id: "clean" });
  const plan = wirePlan([base, clean]);
  const dashed = plan.filter((e) => e[2]).map((e) => e[0] + "→" + e[1]);
  assert.deepEqual(dashed, [UID(base) + "→" + UID(clean)], "only the resolved jump is drawn, dashed");
});

test("a jump across tables does not resolve", () => {
  const base = chain({ table: "inet filter", id: "input", hook: "input", rules: [jump("other")] });
  const other = chain({ table: "ip nat", id: "other" });   /* same name, different table */
  const plan = wirePlan([base, other]);
  assert.equal(plan.filter((e) => e[2]).length, 0, "jumpTarget is table-scoped");
});

/* ── reachability ────────────────────────────────────────────────────── */

test("a base chain is reachable, and so is what it jumps to", () => {
  const base = chain({ table: "inet filter", id: "input", hook: "input", rules: [jump("sub")] });
  const sub = chain({ table: "inet filter", id: "sub" });
  const live = reachable([base, sub]);
  assert.ok(live.has(UID(base)));
  assert.ok(live.has(UID(sub)));
});

test("a regular chain nobody jumps to is unreachable", () => {
  const base = chain({ table: "inet filter", id: "input", hook: "input" });
  const orphan = chain({ table: "inet filter", id: "orphan" });
  const live = reachable([base, orphan]);
  assert.equal(live.has(UID(orphan)), false);
});

test("a disabled jump draws no wire and reaches nothing", () => {
  const base = chain({ table: "inet filter", id: "input", hook: "input",
    rules: [{ verdict: "jump", to: "sub", expr: "", on: false }] });
  const sub = chain({ table: "inet filter", id: "sub" });
  const plan = wirePlan([base, sub]);
  assert.equal(plan.filter((e) => e[2]).length, 0, "a rule that does not run is not a call");
  assert.equal(reachable([base, sub]).has(UID(sub)), false,
    "and a chain only a disabled rule jumps to is unreachable");
});

test("netdev chains on different devices are not wired in sequence", () => {
  const wan = chain({ table: "netdev nd", id: "wan", hook: "ingress", prio: -500, dev: 'device "wan0"' });
  const lan = chain({ table: "netdev nd", id: "lan", hook: "ingress", prio: -400, dev: 'device "lan0"' });
  const plan = wirePlan([wan, lan]);
  assert.equal(has(plan, wan, lan), false, "wan0 ingress and lan0 ingress are parallel, not a path");
  /* two chains on the SAME device do wire, in priority order */
  const a = chain({ table: "netdev nd", id: "a", hook: "ingress", prio: -500, dev: 'device "wan0"' });
  const b = chain({ table: "netdev nd", id: "b", hook: "ingress", prio: -400, dev: 'device "wan0"' });
  assert.ok(has(wirePlan([a, b]), a, b), "same device, same hook: still a sequence");
});

test("reachability is transitive, and does not loop forever on a cycle", () => {
  const base = chain({ table: "inet filter", id: "input", hook: "input", rules: [jump("a")] });
  const a = chain({ table: "inet filter", id: "a", rules: [jump("b")] });
  const b = chain({ table: "inet filter", id: "b", rules: [jump("a")] });   /* a↔b cycle */
  const dead = chain({ table: "inet filter", id: "dead" });
  const live = reachable([base, a, b, dead]);
  assert.ok(live.has(UID(a)) && live.has(UID(b)), "both ends of the cycle are reached from input");
  assert.equal(live.has(UID(dead)), false, "and the one outside it is not");
});
