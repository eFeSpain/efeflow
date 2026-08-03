/* How a packet gets from one rule to the next, and what a NAT verdict does to
 * it on the way.
 *
 * Most of this turned out to be right, which is worth writing down as much as
 * a bug is: `jump` comes back and `goto` does not, a chain that returns leaves
 * the base chain's policy to decide, `accept` ends its chain and not the
 * packet, and chains on one hook run in priority order. None of that was
 * covered by a test before, so all of it was right by luck as far as anything
 * could tell.
 *
 * What was not right was the edges: a cycle took the whole application down,
 * and a NAT target the model could not represent was applied anyway, quietly.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { MODEL, R } from "../src/core/model.js";
import { evaluate, setPacket, packet, natTarget } from "../src/core/simulate.js";

const PKT = {
  dir: "in", iif: "wan0", oif: "", saddr: "1.1.1.1", daddr: "2.2.2.2",
  sport: 1, dport: 80, proto: "tcp", state: "new", tracked: true, nat: true,
  flags: ["syn"],
};
const chain = (id, hook, policy, rules, prio = 0) =>
  ({ id, table: "inet t", hook, prio, type: hook ? "filter" : "regular", policy, rules });

function run(chains, over = {}) {
  Object.assign(MODEL, { sets: [], objects: [], tables: [], prelude: [], chains });
  setPacket({ ...PKT, ...over });
  return evaluate(packet);
}

/* ── jump, goto, return ──────────────────────────────────────────────────── */

test("a jump comes back to the rule after it", () => {
  const r = run([
    chain("input", "input", "drop", [R("tcp dport 80", "jump", { to: "h" }), R("", "accept")]),
    chain("h", null, null, [R("", "return")]),
  ]);
  assert.equal(r.final.v, "accept");
});

test("a goto does not, which is the whole reason nftables has both", () => {
  const r = run([
    chain("input", "input", "drop", [R("tcp dport 80", "goto", { to: "h" }), R("", "accept")]),
    chain("h", null, null, [R("", "return")]),
  ]);
  assert.equal(r.final.v, "drop", "the base chain's policy had the last word");
  assert.equal(r.final.policy, true);
});

test("a jump whose target settles ends the chain that jumped", () => {
  const r = run([
    chain("input", "input", "accept", [R("tcp dport 80", "jump", { to: "h" }), R("", "drop")]),
    chain("h", null, null, [R("", "accept")]),
  ]);
  assert.equal(r.final.v, "accept", "the drop below the jump was never reached");
});

test("jumps nest", () => {
  const r = run([
    chain("input", "input", "drop", [R("", "jump", { to: "a" })]),
    chain("a", null, null, [R("", "jump", { to: "b" })]),
    chain("b", null, null, [R("", "accept")]),
  ]);
  assert.equal(r.final.v, "accept");
});

test("a jump to a chain that is not there decides nothing", () => {
  const r = run([
    chain("input", "input", "drop", [R("", "jump", { to: "gone" }), R("", "accept")]),
  ]);
  assert.equal(r.final.v, "accept");
});

/* ── a cycle ─────────────────────────────────────────────────────────────── */

/* `nft` refuses a loop when the ruleset loads, so this cannot arrive from a
   host. The editor can build one with two clicks, and what came out was
   `RangeError: Maximum call stack size exceeded` from inside a click handler
   — an exception with nowhere to go and a screen that stopped answering. */
test("a jump cycle is refused rather than recursed into", () => {
  const r = run([
    chain("input", "input", "drop", [R("", "jump", { to: "a" })]),
    chain("a", null, null, [R("", "jump", { to: "b" })]),
    chain("b", null, null, [R("", "jump", { to: "a" })]),
  ]);
  assert.equal(r.final.v, "drop", "nothing decided, so the policy did");
  assert.equal(r.sure, false, "a trace that hit a cycle is not a statement");
  assert.ok(r.unsure.some((u) => /jumps back/.test(u)), JSON.stringify(r.unsure));
});

test("a chain that jumps to itself is the same case", () => {
  const r = run([
    chain("input", "input", "drop", [R("", "jump", { to: "a" })]),
    chain("a", null, null, [R("", "jump", { to: "a" }), R("", "accept")]),
  ]);
  assert.equal(r.sure, false);
});

/* ── chains sharing a hook ───────────────────────────────────────────────── */

test("chains on one hook run in priority order", () => {
  const r = run([
    chain("late", "input", "accept", [], 20),
    chain("early", "input", "accept", [], 10),
    chain("raw", "prerouting", "accept", [], -300),
  ]);
  assert.deepEqual(r.steps.map((s) => s.chain.id), ["raw", "early", "late"]);
});

/* accept ends a chain, not the packet: the next base chain on the hook is a
   separate registration and still runs. This is the distinction the README
   opens with, and nothing tested it. */
test("an accept in one chain does not spare the packet from the next", () => {
  const r = run([
    chain("early", "input", "accept", [R("tcp dport 80", "accept")], 10),
    chain("late", "input", "accept", [R("tcp dport 80", "drop")], 20),
  ]);
  assert.equal(r.final.v, "drop");
});

test("and a rule below an accept in the same chain is never reached", () => {
  const r = run([chain("input", "input", "drop", [R("", "accept"), R("", "drop")])]);
  assert.equal(r.final.v, "accept");
});

/* ── what a NAT verdict does to the packet ───────────────────────────────── */

test("a v6 target arrives without the brackets that told it from its port", () => {
  assert.deepEqual(natTarget("[2001:db8::1]:80"), { host: "2001:db8::1", port: 80, assumed: [] });
  assert.deepEqual(natTarget("2001:db8::1"), { host: "2001:db8::1", port: null, assumed: [] });
});

/* Keeping the brackets made the destination a string no address matcher
   recognised, so every rule downstream of a v6 DNAT quietly missed. */
test("and it is an address the rules downstream can still match", () => {
  const r = run([
    chain("pre", "prerouting", "accept",
      [R("tcp dport 80", "dnat", { to: "[2001:db8::1]:8080" })], -100),
    chain("input", "input", "drop", [R("ip6 daddr 2001:db8::1 tcp dport 8080", "accept")]),
  ], { saddr: "2001:db8::9", daddr: "2001:db8::5" });
  assert.equal(r.final.v, "accept");
});

test("a target range picks one, and says which", () => {
  const a = natTarget("10.20.1.1-10.20.1.9");
  assert.equal(a.host, "10.20.1.1");
  assert.equal(a.assumed.length, 1);
  const b = natTarget("10.0.0.12:8000-8010");
  assert.equal(b.port, 8000);
  assert.equal(b.assumed.length, 1);
});

test("and the trace it produced is not called certain", () => {
  const r = run([
    chain("pre", "prerouting", "accept",
      [R("tcp dport 80", "dnat", { to: "10.20.1.1-10.20.1.9" })], -100),
    chain("input", "input", "accept", []),
  ]);
  assert.equal(r.sure, false);
  assert.ok(r.unsure.some((u) => /10\.20\.1\.1/.test(u)), JSON.stringify(r.unsure));
});

test("an ordinary target is not hedged about", () => {
  const r = run([
    chain("pre", "prerouting", "accept",
      [R("tcp dport 80", "dnat", { to: "10.20.1.5:443" })], -100),
    chain("input", "input", "accept", []),
  ]);
  assert.equal(r.sure, true);
  assert.equal(packet.daddr, "10.20.1.5");
  assert.equal(packet.dport, 443);
});
