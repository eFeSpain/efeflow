/* Control flow between chains, which is where a simulator earns its keep.
 *
 * `jump` comes back and `goto` does not; `return` ends the chain it is in.
 * Getting those wrong does not produce a slightly different trace — it
 * produces a different verdict, and the whole claim of this screen is that the
 * verdict is the one the exported ruleset gives you. */
import test from "node:test";
import assert from "node:assert/strict";

import { MODEL, R } from "../src/core/model.js";
import { evaluate, PRESETS } from "../src/core/simulate.js";

const base = (id, hook, policy, rules, type = "filter") =>
  ({ id, table: "inet filter", hook, prio: 0, type, policy, rules });
const regular = (id, rules) =>
  ({ id, table: "inet filter", hook: null, prio: 0, type: "filter", policy: null, rules });

const load = (chains) => { MODEL.chains = chains; MODEL.sets = []; };
const packet = (over = {}) => ({ ...PRESETS.ssh, flags: ["syn"], ...over });

test("jump comes back to the rule after it", () => {
  load([
    base("input", "input", "drop", [R("tcp dport 22", "jump", { to: "ssh" }), R("", "accept")]),
    regular("ssh", [R("ip saddr 10.9.9.9", "drop")]),
  ]);
  assert.equal(evaluate(packet()).final.v, "accept",
    "ssh decided nothing, so input carries on at its next rule");
});

/* Returning from a jump is not the same as having decided something. A chain
   whose rules all miss after the jump falls to its policy — which used to be
   skipped for any chain containing a jump at all, so a default-deny firewall
   quietly accepted the packet instead. */
test("a chain that only jumps still falls to its own policy", () => {
  load([
    base("input", "input", "drop", [R("tcp dport 22", "jump", { to: "ssh" })]),
    regular("ssh", [R("ip saddr 10.9.9.9", "drop")]),
  ]);
  assert.equal(evaluate(packet()).final.v, "drop");
});

/* The difference between the two is the whole reason `goto` exists. A packet
   sent with `goto` never returns: if the target chain settles nothing, the
   base chain's policy applies, not the rules below the goto. Treating goto as
   a no-op meant the rules below it ran, and they are exactly the rules the
   author wrote goto to skip. */
test("goto does not come back, and the base policy has the last word", () => {
  load([
    base("input", "input", "drop", [R("tcp dport 22", "goto", { to: "ssh" }), R("", "accept")]),
    regular("ssh", [R("ip saddr 10.9.9.9", "drop")]),
  ]);
  assert.equal(evaluate(packet()).final.v, "drop",
    "the accept below the goto must never be reached");
});

test("goto still carries a verdict its target reaches", () => {
  load([
    base("input", "input", "drop", [R("tcp dport 22", "goto", { to: "ssh" })]),
    regular("ssh", [R("", "accept")]),
  ]);
  assert.equal(evaluate(packet()).final.v, "accept");
});

test("return ends the chain it is in", () => {
  load([
    base("input", "input", "drop", [R("", "jump", { to: "sub" })]),
    regular("sub", [R("tcp dport 22", "return"), R("", "accept")]),
  ]);
  assert.equal(evaluate(packet()).final.v, "drop",
    "the return leaves sub before its accept, and input then falls to its policy");
});

test("return in a base chain hands over to the policy", () => {
  load([base("input", "input", "drop", [R("tcp dport 22", "return"), R("", "accept")])]);
  assert.equal(evaluate(packet()).final.v, "drop");
});

/* `redirect to :8080` is a DNAT to this machine on another port. The packet
   that walks on to the input chain is the translated one, so a rule matching
   dport 8080 must see it. */
test("redirect translates the port and marks the packet", () => {
  load([
    base("prerouting", "prerouting", "accept", [R("tcp dport 80", "redirect", { to: ":8080" })], "nat"),
    base("input", "input", "drop", [R("tcp dport 8080", "accept")]),
  ]);
  const p = packet({ dport: 80 });
  assert.equal(evaluate(p).final.v, "accept");
  assert.equal(p.dport, 8080);
  assert.equal(p.dnat, true);
});

/* `dnat to 10.0.0.5` moves the packet to another host on the port it already
   had. Splitting the target on ":" unconditionally set the port to NaN, and a
   packet with no port matches no port rule anywhere downstream. */
test("a dnat with no port leaves the port alone", () => {
  load([
    base("prerouting", "prerouting", "accept", [R("tcp dport 443", "dnat", { to: "10.0.0.5" })], "nat"),
    base("input", "input", "drop", [R("tcp dport 443", "accept")]),
  ]);
  const p = packet({ dport: 443 });
  assert.equal(evaluate(p).final.v, "accept");
  assert.equal(p.daddr, "10.0.0.5");
  assert.equal(p.dport, 443, "the port was not part of the translation");
});

test("a dnat to an address and a port applies both", () => {
  load([
    base("prerouting", "prerouting", "accept", [R("tcp dport 8443", "dnat", { to: "10.0.0.5:443" })], "nat"),
    base("input", "input", "drop", [R("tcp dport 443 ip daddr 10.0.0.5", "accept")]),
  ]);
  const p = packet({ dport: 8443 });
  assert.equal(evaluate(p).final.v, "accept");
  assert.equal(p.daddr, "10.0.0.5");
  assert.equal(p.dport, 443);
});
