/* A verdict map decides the verdict, and the rule carries none of its own.
 *
 * `tcp dport vmap { 80 : accept, 443 : drop }` has no verdict word at the end
 * of the line, so the parser reads it as a rule that falls through — correctly,
 * because that is what the line says. What decides is the lookup, and nothing
 * performed it. Worse, the port matcher read `vmap` as the value it was
 * comparing the packet's port against, so the rule was a certain miss.
 *
 * A miss is never reported as a guess: unmodelled() is only asked about rules
 * that matched. So a packet to port 80 was shown falling straight past an
 * accept written for it, into a policy drop, and the trace said it was certain.
 * `ct state vmap` had already been found doing exactly this at the top of every
 * modern chain; every other key was doing it too.
 *
 * The other half of this file is the opposite problem. `notrack`, `meta mark
 * set` and their kind are statements, not matches — whether a rule applies does
 * not turn on any of them — and every one was being reported as an assumption.
 * The unsure list is only worth reading while it is short. */
import test from "node:test";
import assert from "node:assert/strict";
import { MODEL } from "../src/core/model.js";
import { parseRule } from "../src/core/parse.js";
import { evaluate, setPacket, packet, unmodelled, vmapVerdict } from "../src/core/simulate.js";

const PKT = {
  dir: "in", iif: "wan0", oif: "", saddr: "203.0.113.5", daddr: "198.51.100.10",
  sport: 1, dport: 80, proto: "tcp", state: "new", tracked: true, nat: true,
  flags: ["syn"],
};

/* the rule as written, parsed the way an import would parse it */
function run(lines, over = {}, sets = []) {
  Object.assign(MODEL, {
    sets, objects: [], tables: [], prelude: [],
    chains: [
      { id: "input", table: "inet t", hook: "input", prio: 0, type: "filter",
        policy: "drop", rules: lines.map(parseRule) },
      { id: "lan", table: "inet t", hook: null, prio: 0, type: "regular", policy: null,
        rules: [parseRule("accept")] },
    ],
  });
  setPacket({ ...PKT, ...over });
  return evaluate(packet);
}

/* ── the lookup decides ──────────────────────────────────────────────────── */

test("a port map picks the verdict for the port", () => {
  const line = "tcp dport vmap { 80 : accept, 443 : drop }";
  assert.equal(run([line], { dport: 80 }).final.v, "accept");
  assert.equal(run([line], { dport: 443 }).final.v, "drop");
});

test("and none of that is hedged about", () => {
  const r = run(["tcp dport vmap { 80 : accept, 443 : drop }"], { dport: 80 });
  assert.equal(r.sure, true);
  assert.deepEqual(r.unsure, []);
});

test("a key the map does not hold means the rule does not fire", () => {
  const r = run(["tcp dport vmap { 80 : accept, 443 : drop }", "tcp dport 22 accept"],
    { dport: 22 });
  assert.equal(r.final.v, "accept", "the rule below decided it");
  assert.equal(r.sure, true);
});

test("a map can send the packet to a chain", () => {
  assert.equal(run(['iifname vmap { "wan0" : jump lan }'], { iif: "wan0" }).final.v, "accept");
  assert.equal(run(['iifname vmap { "wan0" : jump lan }'], { iif: "eth9" }).final.v, "drop");
});

test("the keys are the same ones a concatenation uses", () => {
  assert.equal(run(["ct state vmap { new : accept }"]).final.v, "accept");
  assert.equal(run(["meta l4proto vmap { tcp : accept, udp : drop }"]).final.v, "accept");
  assert.equal(run(["ip saddr vmap { 203.0.113.0/24 : accept }"]).final.v, "accept");
});

test("a map held in a named set works the same way", () => {
  const sets = [{ n: "by_port", el: ["80 : accept", "443 : drop"] }];
  assert.equal(run(["tcp dport vmap @by_port"], { dport: 80 }, sets).final.v, "accept");
  assert.equal(run(["tcp dport vmap @by_port"], { dport: 443 }, sets).final.v, "drop");
});

test("a concatenated key is read as one", () => {
  const sets = [{ n: "pairs", el: ["203.0.113.5 . 80 : accept"] }];
  assert.equal(run(["ip saddr . tcp dport vmap @pairs"], { dport: 80 }, sets).final.v, "accept");
  assert.equal(run(["ip saddr . tcp dport vmap @pairs"], { dport: 81 }, sets).final.v, "drop");
});

test("a map on a key nothing reads is admitted to rather than answered", () => {
  const line = "meta mark vmap { 0x1 : accept }";
  assert.equal(vmapVerdict(line, PKT), undefined);
  assert.ok(unmodelled(line).length, "and it says so");
});

/* ── what is not a match ─────────────────────────────────────────────────── */

test("a statement is not an assumption", () => {
  for (const e of ["meta mark set 0x1", "notrack", "nftrace set 1", "ct mark set 0x1",
                   "queue num 0", "flow add @ft", "add @banned { ip saddr }",
                   "dup to 10.0.0.1", "tproxy to :3129", "meta priority set 1:10"])
    assert.deepEqual(unmodelled(e), [], e);
});

/* A rate limit really does decide whether the rule fires, out of a history no
   single packet carries. Saying so is the honest answer rather than a
   nuisance, and it is the reason this list is worth keeping short. */
test("a rate limit still is one", () => {
  assert.deepEqual(unmodelled("limit rate 5/second"), ["limit rate 5/second"]);
});

/* ── and what one packet cannot answer ───────────────────────────────────── */

/* `jhash ip saddr mod 2 == 0` was worse than unanswered: the address matcher
   read the `ip saddr` out of the middle of it and compared the packet against
   the word `mod`, which made it a certain miss with nothing reported. */
test("a hash or a random draw is reported whole", () => {
  for (const e of ["jhash ip saddr mod 2 == 0", "numgen random mod 100 < 5",
                   "symhash mod 4 == 1"])
    assert.deepEqual(unmodelled(e), [e], e);
});
