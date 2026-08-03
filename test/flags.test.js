/* `tcp flags`, which asks one question in three spellings that do not mean the
 * same thing.
 *
 *   tcp flags syn                    the syn bit is set, whatever else is
 *   tcp flags & (syn|ack) == syn     of those two bits, exactly syn
 *   tcp flags syn / fin,syn,rst,ack  the same, operands the other way round
 *
 * The third was read as if it were the first, so it matched a syn|ack packet
 * that nft would have refused — and the distinction between the first two is
 * the one the README opens the simulator section with. It is also the whole
 * point of the construct: `syn / fin,syn,rst,ack` is how a ruleset says "a
 * connection attempt and not a reply to one".
 *
 * All three come down to the same rule, which is why they can be written once:
 * every bit the mask names is exactly as the value says. The bare form is that
 * with the value as its own mask. */
import test from "node:test";
import assert from "node:assert/strict";
import { MODEL } from "../src/core/model.js";
import { matches } from "../src/core/simulate.js";

const pkt = (flags) => ({
  dir: "in", iif: "wan0", oif: "", saddr: "1.1.1.1", daddr: "2.2.2.2",
  sport: 1, dport: 80, proto: "tcp", state: "new", tracked: true, nat: true, flags,
});

const hit = (expr, flags) => {
  Object.assign(MODEL, { chains: [], sets: [], objects: [], tables: [], prelude: [] });
  return matches({ expr }, pkt(flags));
};

const CASES = [
  /* bare: a subset test */
  ["tcp flags syn", ["syn"], true],
  ["tcp flags syn", ["syn", "ack"], true],
  ["tcp flags syn", ["ack"], false],
  ["tcp flags syn,ack", ["syn", "ack"], true],
  ["tcp flags syn,ack", ["syn"], false],

  /* masked, with the mask first */
  ["tcp flags & (syn|ack) == syn", ["syn"], true],
  ["tcp flags & (syn|ack) == syn", ["syn", "ack"], false],
  ["tcp flags & (syn|ack) == syn", ["syn", "psh"], true, "psh is outside the mask"],
  ["tcp flags & (fin|syn|rst|ack) == syn", ["syn"], true],
  ["tcp flags & (fin|syn|rst|ack) == syn", ["syn", "fin"], false],

  /* masked, with the value first — the one that was being misread */
  ["tcp flags syn / fin,syn,rst,ack", ["syn"], true],
  ["tcp flags syn / fin,syn,rst,ack", ["syn", "ack"], false],
  ["tcp flags syn / fin,syn,rst,ack", ["syn", "psh"], true, "psh is outside the mask"],
  ["tcp flags syn,ack / syn,ack", ["syn", "ack"], true],
  ["tcp flags syn,ack / syn,ack", ["syn"], false],

  /* `== 0` names no bits at all: the null-scan check, and it was being
     compared against a flag called "0" */
  ["tcp flags & (fin|syn|rst|psh|ack|urg) == 0", [], true],
  ["tcp flags & (fin|syn|rst|psh|ack|urg) == 0", ["syn"], false],
  ["tcp flags & (fin|syn|rst|psh|ack|urg) == 0", ["urg"], false],

  /* negated */
  ["tcp flags != syn", ["ack"], true],
  ["tcp flags != syn", ["syn"], false],
  ["tcp flags != syn / fin,syn,rst,ack", ["syn", "ack"], true],
];

for (const [expr, flags, want, why] of CASES)
  test(`${want ? "matches" : "misses"} ${JSON.stringify(flags)}: ${expr}${why ? "  — " + why : ""}`,
    () => assert.equal(hit(expr, flags), want));

/* The distinction the README opens with, stated as one assertion so it cannot
   quietly stop being true. */
test("the bare form and the masked form disagree about syn|ack, on purpose", () => {
  assert.equal(hit("tcp flags syn", ["syn", "ack"]), true);
  assert.equal(hit("tcp flags & (syn|ack) == syn", ["syn", "ack"]), false);
  assert.equal(hit("tcp flags syn / fin,syn,rst,ack", ["syn", "ack"]), false);
});
