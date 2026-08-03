/* Conntrack, and the difference between answering and pretending to.
 *
 * Three gaps of the same family as the value ones, found by asking the same
 * question of a different part of the evaluator: what does a matcher accept
 * and then decide wrongly?
 *
 * `ct state vmap { established : accept, invalid : drop }` is how most modern
 * rulesets open a chain. The state matcher read `vmap` as the name of a state,
 * found the packet was not in it, and made the rule a certain miss — every
 * time, on the busiest rule in the file. And a miss is never reported as a
 * guess, because unmodelled() is only consulted about rules that matched. So
 * nothing on the screen said anything at all.
 *
 * `ct status` was answered by one question — had this packet been DNATed —
 * whatever status was asked about. `ct status snat` came back true for a
 * DNATed packet and `ct status confirmed` came back true for everything.
 *
 * And the braced form of `ct state` went unread, which was merely wasteful:
 * honest, but a trivial shape to support and one nft prints. */
import test from "node:test";
import assert from "node:assert/strict";
import { MODEL } from "../src/core/model.js";
import { matches, unmodelled, evaluate, setPacket, packet } from "../src/core/simulate.js";

const PKT = {
  dir: "in", iif: "wan0", oif: "", saddr: "203.0.113.48", daddr: "198.51.100.10",
  sport: 49812, dport: 9038, proto: "tcp", state: "new", tracked: true, nat: true,
  flags: ["syn"],
};

const blank = () =>
  Object.assign(MODEL, { chains: [], sets: [], objects: [], tables: [], prelude: [] });

const hit = (expr, p = PKT) => { blank(); return matches({ expr }, p); };
const unread = (expr) => { blank(); return unmodelled(expr); };

/* ── ct state, in both spellings ─────────────────────────────────────────── */

test("the comma form and the braced form are the same constraint", () => {
  for (const e of ["ct state new,established", "ct state { new, established }"]) {
    assert.equal(hit(e), true, e);
    assert.deepEqual(unread(e), [], `${e} was matched without being read`);
  }
});

test("and both of them can miss", () => {
  assert.equal(hit("ct state invalid"), false);
  assert.equal(hit("ct state { invalid, related }"), false);
});

test("an untracked packet is only reachable through the untracked keyword", () => {
  const off = { ...PKT, tracked: false };
  assert.equal(hit("ct state { new, established }", off), false);
  assert.equal(hit("ct state untracked", off), true);
});

/* ── ct state vmap ───────────────────────────────────────────────────────── */

/* A verdict map decides the verdict, and the rule carries none of its own.
   This was first fixed by refusing to misread it — the state matcher took
   `vmap` for the name of a state and made the rule a certain miss — and the
   honest answer then was to leave it unread and say so. It is evaluated now,
   which is better, and the shape of the earlier fix is what made that safe:
   nothing else reads a fragment out of it. */
test("a verdict map on ct state decides the verdict", () => {
  Object.assign(MODEL, {
    sets: [], objects: [], tables: [], prelude: [],
    chains: [{
      id: "input", table: "inet fw", hook: "input", prio: 0, type: "filter",
      policy: "drop", rules: [
        { expr: "ct state vmap { established : accept, invalid : drop }",
          verdict: "continue", implicit: true, on: true, pkts: 0, bytes: 0 },
      ],
    }],
  });
  setPacket({ ...PKT, state: "established" });
  assert.equal(evaluate(packet).final.v, "accept");
  setPacket({ ...PKT, state: "invalid" });
  assert.equal(evaluate(packet).final.v, "drop");
});

/* A key the map does not hold means the rule does not fire, the same as a map
   used as a NAT target: the lookup is part of the expression. */
test("a state the map says nothing about falls through to the rule below", () => {
  Object.assign(MODEL, {
    sets: [], objects: [], tables: [], prelude: [],
    chains: [{
      id: "input", table: "inet fw", hook: "input", prio: 0, type: "filter",
      policy: "drop", rules: [
        { expr: "ct state vmap { established : accept, invalid : drop }",
          verdict: "continue", implicit: true, on: true, pkts: 0, bytes: 0 },
        { expr: "tcp dport 9038", verdict: "accept", on: true, pkts: 0, bytes: 0 },
      ],
    }],
  });
  setPacket(PKT);                                  /* state new: not in the map */
  const r = evaluate(packet);
  assert.equal(r.final.v, "accept", "the rule below decided it");
  assert.equal(r.sure, true, "and nothing about that was a guess");
});

/* ── ct status ───────────────────────────────────────────────────────────── */

test("dnat and snat are answered, and answered apart", () => {
  const dnatted = { ...PKT, dnat: true };
  const snatted = { ...PKT, snat: true };
  assert.equal(hit("ct status dnat", dnatted), true);
  assert.equal(hit("ct status snat", dnatted), false, "a DNATed packet is not an SNATed one");
  assert.equal(hit("ct status snat", snatted), true);
  assert.equal(hit("ct status dnat", snatted), false);
  assert.equal(hit("ct status dnat", PKT), false, "and neither, before anything translated it");
});

test("a status nothing models is admitted to rather than invented", () => {
  for (const s of ["confirmed", "assured", "seen-reply", "expected", "dying"]) {
    const e = `ct status ${s}`;
    assert.equal(hit(e, { ...PKT, dnat: true }), true, "taken as matching");
    assert.deepEqual(unread(e), [e], `${e} was decided rather than admitted`);
  }
});

test("an untracked packet has no status at all", () => {
  assert.equal(hit("ct status dnat", { ...PKT, tracked: false, dnat: true }), false);
});

/* The flag exists because a verdict set it, not because the form has a
   checkbox for it: an snat rule earlier in the walk is what makes
   `ct status snat` true later. */
test("an snat verdict is what makes the packet snatted", () => {
  Object.assign(MODEL, {
    sets: [], objects: [], tables: [], prelude: [],
    chains: [
      { id: "postrouting", table: "ip nat", hook: "postrouting", prio: 100, type: "nat",
        policy: "accept", rules: [
          { expr: 'oifname "wan0"', verdict: "snat", to: "198.51.100.10", on: true,
            pkts: 0, bytes: 0 },
        ] },
    ],
  });
  setPacket({ ...PKT, dir: "out", oif: "wan0", snat: false });
  evaluate(packet);
  assert.equal(packet.snat, true);
});
