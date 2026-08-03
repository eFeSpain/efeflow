/* What a rule does to the packet and to the ruleset on its way past.
 *
 * A matched rule is not only a verdict. `notrack` takes the packet out of
 * conntrack, and `add @banned { ip saddr }` puts the packet's own address into
 * a set that a rule below it may then look up. Both were being read as
 * statements with no consequence — correctly, in the sense that neither
 * decides whether the rule applies, and wrongly in every other sense.
 *
 * The `add` one is the shape this application has a finding about: a set
 * filled by traffic, with no size and no timeout, handing a stranger a lever
 * on kernel memory. The rule that does it is the standard tarpit line —
 * `ct state new limit rate over 3/minute add @ratelimit { ip saddr } drop` —
 * and it never fired in any trace at all, because the address matcher was
 * reading the `}` after `ip saddr` as the address the rule compared against.
 * A silent certain miss on the rule the analyser is loudest about. */
import test from "node:test";
import assert from "node:assert/strict";
import { MODEL, R } from "../src/core/model.js";
import { evaluate, matches, unmodelled, inSet } from "../src/core/simulate.js";

const PKT = {
  dir: "in", iif: "wan0", oif: "", saddr: "203.0.113.5", daddr: "198.51.100.1",
  sport: 1, dport: 80, proto: "tcp", state: "new", tracked: true, nat: true,
  flags: ["syn"],
};
const chain = (id, hook, policy, rules, prio = 0) =>
  ({ id, table: "inet f", hook, prio, type: "filter", policy, rules });
/* a rule that only does something: no verdict word at the end of the line */
const does = (expr) => ({ expr, verdict: "continue", implicit: true, on: true, pkts: 0, bytes: 0 });

function run(chains, over = {}, sets = []) {
  Object.assign(MODEL, { sets, objects: [], tables: [], prelude: [], chains });
  return evaluate({ ...PKT, ...over });
}

/* ── notrack ─────────────────────────────────────────────────────────────── */

test("notrack takes the packet out of conntrack", () => {
  const chains = [
    chain("raw", "prerouting", "accept", [does("tcp dport 80 notrack")], -300),
    chain("in", "input", "drop", [R("ct state established", "accept")]),
  ];
  assert.equal(run(chains, { state: "established" }).final.v, "drop",
    "the packet has no conntrack entry for that state to be read from");
});

test("and only the untracked keyword reaches it afterwards", () => {
  const chains = [
    chain("raw", "prerouting", "accept", [does("notrack")], -300),
    chain("in", "input", "drop", [R("ct state untracked", "accept")]),
  ];
  assert.equal(run(chains, { state: "established" }).final.v, "accept");
});

test("without it the packet stays tracked", () => {
  const chains = [
    chain("raw", "prerouting", "accept", [does("tcp dport 80")], -300),
    chain("in", "input", "drop", [R("ct state established", "accept")]),
  ];
  assert.equal(run(chains, { state: "established" }).final.v, "accept");
});

/* ── sets a rule fills ───────────────────────────────────────────────────── */

/* The rule itself first. `add @ratelimit { ip saddr }` names a key, and the
   address matcher read the `}` after it as a value to compare the packet
   against — so the rule was a certain miss, every time. */
test("a rule that fills a set is a rule that matches", () => {
  Object.assign(MODEL, { chains: [], sets: [], objects: [], tables: [], prelude: [] });
  const expr = "ct state new add @ratelimit { ip saddr }";
  assert.equal(matches({ expr }, PKT), true);
  assert.deepEqual(unmodelled(expr), [], "and nothing about it went unread");
});

test("what it puts there is found by a rule below it", () => {
  const chains = [chain("in", "input", "drop", [
    does("add @banned { ip saddr }"),
    R("ip saddr @banned", "drop"),
    R("", "accept"),
  ])];
  assert.equal(run(chains, {}, [{ n: "banned", el: [] }]).final.v, "drop");
});

test("the update form does the same", () => {
  const chains = [chain("in", "input", "drop", [
    does("update @banned { ip saddr timeout 30s }"),
    R("ip saddr @banned", "drop"),
    R("", "accept"),
  ])];
  assert.equal(run(chains, {}, [{ n: "banned", el: [] }]).final.v, "drop",
    "the timeout is bookkeeping, not part of the value");
});

test("a concatenated key is written whole", () => {
  const chains = [chain("in", "input", "drop", [
    does("add @pairs { ip saddr . tcp dport }"),
    R("ip saddr . tcp dport @pairs", "drop"),
    R("", "accept"),
  ])];
  assert.equal(run(chains, {}, [{ n: "pairs", el: [] }]).final.v, "drop");
});

test("a rule above the one that fills it still misses", () => {
  const chains = [chain("in", "input", "drop", [
    R("ip saddr @banned", "drop"),
    does("add @banned { ip saddr }"),
    R("", "accept"),
  ])];
  assert.equal(run(chains, {}, [{ n: "banned", el: [] }]).final.v, "accept",
    "the element was not there yet when the lookup ran");
});

/* ── and it is only true for the length of the walk ──────────────────────── */

/* The ruleset is not edited by being simulated. Every other caller of inSet —
   the analyser most of all — must see the sets the file actually holds. */
test("the set the ruleset holds is not touched", () => {
  const sets = [{ n: "banned", el: [] }];
  run([chain("in", "input", "accept", [does("add @banned { ip saddr }")])], {}, sets);
  assert.deepEqual(sets[0].el, []);
  assert.equal(inSet("203.0.113.5", "banned"), false,
    "an element that only existed during a walk outlived it");
});

test("a key nothing reads is admitted to rather than skipped", () => {
  const r = run([chain("in", "input", "accept", [does("add @banned { meta mark }")])],
    {}, [{ n: "banned", el: [] }]);
  assert.equal(r.sure, false);
  assert.ok(r.unsure.some((u) => /cannot read/.test(u)), JSON.stringify(r.unsure));
});
