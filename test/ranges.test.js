/* The analyser's half of the range gap.
 *
 * The evaluator learned to compare a range as a range; subsumption did not,
 * because it has its own comparison and only ever understood prefixes. So a
 * rule sitting under `tcp dport 9000-9100` was never reported as shadowed by
 * it, and two DNAT rules whose ranges overlap never conflicted.
 *
 * This is the safe direction to be wrong in, which is exactly why it outlived
 * the evaluator's version: nothing on the screen was false, there was just
 * less on it than there should have been. Findings this cannot stand behind
 * are the ones worth not making — findings it could make and does not are
 * simply missing. */
import test from "node:test";
import assert from "node:assert/strict";
import { MODEL } from "../src/core/model.js";
import { criteria, subsumes, overlaps } from "../src/core/analyse.js";

const blank = () =>
  Object.assign(MODEL, { chains: [], sets: [], objects: [], tables: [], prelude: [] });

const sub = (a, b) => { blank(); return subsumes(criteria(a), criteria(b)); };
const over = (a, b) => { blank(); return overlaps(criteria(a), criteria(b)); };

/* ── ports ───────────────────────────────────────────────────────────────── */

test("a port range covers a port inside it", () => {
  assert.equal(sub("tcp dport 9000-9100", "tcp dport 9038"), true);
  assert.equal(sub("tcp dport 9000-9100", "tcp dport 9200"), false);
});

test("a wider range covers a narrower one, and not the other way round", () => {
  assert.equal(sub("tcp dport 9000-9100", "tcp dport 9010-9050"), true);
  assert.equal(sub("tcp dport 9010-9050", "tcp dport 9000-9100"), false);
});

test("the bounds are inclusive", () => {
  assert.equal(sub("tcp dport 9000-9100", "tcp dport 9000"), true);
  assert.equal(sub("tcp dport 9000-9100", "tcp dport 9100"), true);
  assert.equal(sub("tcp dport 9000-9100", "tcp dport 8999"), false);
  assert.equal(sub("tcp dport 9000-9100", "tcp dport 9101"), false);
});

test("a range inside a set counts too", () => {
  assert.equal(sub("tcp dport { 80, 9000-9100 }", "tcp dport 9038"), true);
  assert.equal(sub("tcp dport { 80, 9000-9100 }", "tcp dport 8080"), false);
});

/* ── addresses ───────────────────────────────────────────────────────────── */

test("an address range covers an address inside it", () => {
  assert.equal(sub("ip saddr 10.0.0.1-10.0.0.9", "ip saddr 10.0.0.5"), true);
  assert.equal(sub("ip saddr 10.0.0.1-10.0.0.9", "ip saddr 10.0.0.20"), false);
});

test("ranges did not cost prefixes what they already understood", () => {
  assert.equal(sub("ip saddr 10.0.0.0/8", "ip saddr 10.1.2.3"), true);
  assert.equal(sub("ip saddr 10.1.0.0/16", "ip saddr 10.2.0.0/16"), false);
  assert.equal(sub("ip6 saddr 2001:db8::/32", "ip6 saddr 2001:db8:1::1"), true);
});

/* ── what must not become true ───────────────────────────────────────────── */

/* A name is not a range. The evaluator needed this said out loud and so does
   the analyser: reading the dash in an interface name as range syntax would
   have two rules covering each other on the strength of a hyphen. */
test("an interface name with a dash in it is not a range", () => {
  assert.equal(sub('iifname "wan0-guest"', 'iifname "wan0-main"'), false);
  assert.equal(sub('iifname "wan0-guest"', 'iifname "wan0-guest"'), true);
});

test("a range of one family says nothing about the other", () => {
  assert.equal(sub("ip saddr 10.0.0.1-10.0.0.9", "ip6 saddr 2001:db8::1"), false);
});

/* ── and the finding it was there to make ────────────────────────────────── */

test("overlapping ranges overlap, which is what a NAT conflict is built on", () => {
  assert.equal(over("tcp dport 9000-9100", "tcp dport 9050-9200"), true);
  assert.equal(over("tcp dport 9000-9100", "tcp dport 9200-9300"), false);
});

test("a rule under a range is now reported as shadowed by it", async () => {
  const { analyse } = await import("../src/core/analyse.js");
  Object.assign(MODEL, {
    sets: [], objects: [], tables: [], prelude: [],
    chains: [{
      id: "input", table: "inet fw", hook: "input", prio: 0, type: "filter",
      policy: "drop", rules: [
        { expr: "tcp dport 9000-9100", verdict: "accept", on: true, pkts: 0, bytes: 0 },
        { expr: "tcp dport 9038", verdict: "accept", on: true, pkts: 0, bytes: 0 },
      ],
    }],
  });
  const found = analyse().filter((f) => f.kind === "shadowed");
  assert.equal(found.length, 1, "the second rule can never match");
  assert.equal(found[0].i, 1);
  assert.equal(found[0].ref, 0);
});
