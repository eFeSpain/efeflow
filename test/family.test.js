/* Which packets reach a table's chains at all, and what a walk leaves behind.
 *
 * A table's family is not decoration: `table ip nat` never sees an IPv6 packet
 * and `table ip6 filter` never sees an IPv4 one. Nothing was checking it, so
 * on a dual-stack ruleset — which is most of them — half of every trace was
 * chains the packet does not enter. An `ip` table's DNAT translated IPv6
 * traffic; an `ip6` table's drop killed IPv4.
 *
 * It is the same failure as the netdev one and the opposite of it: there, a
 * chain that should have been walked was invisible; here, chains that should
 * have been invisible were walked. Both come from the same place — the list of
 * what a packet passes through was built from the hook alone.
 *
 * The second half of this file is the other thing a walk was doing: editing
 * the packet it was handed. A DNAT rewrote its destination in place, so
 * running the same simulation twice gave two different answers, the second
 * starting from where the first had left off. */
import test from "node:test";
import assert from "node:assert/strict";
import { MODEL, R } from "../src/core/model.js";
import { evaluate } from "../src/core/simulate.js";

const V4 = {
  dir: "in", iif: "wan0", oif: "", saddr: "203.0.113.5", daddr: "198.51.100.1",
  sport: 1, dport: 80, proto: "tcp", state: "new", tracked: true, nat: true,
  flags: ["syn"],
};
const V6 = { ...V4, saddr: "2001:db8::1", daddr: "2001:db8::2" };

const chain = (id, table, hook, policy, rules = [], prio = 0) =>
  ({ id, table, hook, prio, type: hook ? "filter" : "regular", policy, rules });

function run(chains, p) {
  Object.assign(MODEL, { sets: [], objects: [], tables: [], prelude: [], chains });
  return evaluate(p);
}

/* ── the family decides who is walked ────────────────────────────────────── */

test("an ip table says nothing about an IPv6 packet", () => {
  const chains = [chain("in4", "ip filter", "input", "accept", [R("", "drop")])];
  assert.equal(run(chains, V4).final.v, "drop");
  assert.equal(run(chains, V6).final.v, "accept", "the ip table caught IPv6");
});

test("an ip6 table says nothing about an IPv4 packet", () => {
  const chains = [chain("in6", "ip6 filter", "input", "accept", [R("", "drop")])];
  assert.equal(run(chains, V6).final.v, "drop");
  assert.equal(run(chains, V4).final.v, "accept", "the ip6 table caught IPv4");
});

test("an inet table sees both, which is the whole reason it exists", () => {
  const chains = [chain("in", "inet filter", "input", "accept", [R("", "drop")])];
  assert.equal(run(chains, V4).final.v, "drop");
  assert.equal(run(chains, V6).final.v, "drop");
});

test("and the trace only holds chains the packet actually enters", () => {
  const chains = [
    chain("in4", "ip filter", "input", "accept"),
    chain("in6", "ip6 filter", "input", "accept"),
    chain("both", "inet filter", "input", "accept"),
  ];
  assert.deepEqual(run(chains, V4).steps.map((s) => s.chain.id), ["in4", "both"]);
  assert.deepEqual(run(chains, V6).steps.map((s) => s.chain.id), ["in6", "both"]);
});

/* A NAT table of the wrong family translating the packet is the worst of it:
   not a verdict that reads oddly, but a destination nothing downstream can
   match, produced by a rule that never runs. */
test("an ip nat table does not translate an IPv6 packet", () => {
  const chains = [
    chain("pre", "ip nat", "prerouting", "accept",
      [R("tcp dport 80", "dnat", { to: "10.20.0.5" })], -100),
    chain("in", "inet filter", "input", "accept"),
  ];
  assert.equal(run(chains, V6).packet.daddr, V6.daddr);
  assert.equal(run(chains, V4).packet.daddr, "10.20.0.5");
});

/* A packet described here always carries an IP address, so it is never one an
   arp table would see. netdev and bridge are not decided by the family. */
test("an arp table is not on any path an IP packet takes", () => {
  const chains = [
    chain("a", "arp filter", "input", "accept", [R("", "drop")]),
    chain("in", "inet filter", "input", "accept"),
  ];
  assert.equal(run(chains, V4).final.v, "accept");
});

test("a bridge table is not filtered out by the address family", () => {
  const chains = [chain("br", "bridge filter", "input", "accept", [R("", "drop")])];
  assert.equal(run(chains, V4).final.v, "drop");
  assert.equal(run(chains, V6).final.v, "drop");
});

/* ── evaluating is not editing ───────────────────────────────────────────── */

/* A DNAT used to rewrite the destination of the packet it was given, so the
   same simulation run twice gave two answers: the second started from where
   the first left the packet, with the rule that moved it no longer matching.
   The interface copies before calling and was never affected, which is exactly
   why it survived — the trap was waiting for every other caller. */
test("the packet handed over comes back unchanged", () => {
  const before = { ...V4 };
  const chains = [
    chain("pre", "ip nat", "prerouting", "accept",
      [R("tcp dport 80", "dnat", { to: "10.20.0.5:8080" })], -100),
    chain("in", "inet filter", "input", "accept"),
  ];
  const p = { ...V4 };
  run(chains, p);
  assert.deepEqual(p, before);
});

test("and the same simulation twice gives the same answer", () => {
  const chains = [
    chain("pre", "ip nat", "prerouting", "accept",
      [R("tcp dport 80", "dnat", { to: "10.20.0.5:8080" })], -100),
    chain("in", "inet filter", "input", "drop",
      [R("ip daddr 10.20.0.5 tcp dport 8080", "accept")]),
  ];
  const p = { ...V4 };
  const first = run(chains, p);
  const second = run(chains, p);
  assert.equal(first.final.v, "accept");
  assert.equal(second.final.v, first.final.v);
  assert.equal(second.packet.daddr, first.packet.daddr);
});

test("what the walk did to it comes back in the result", () => {
  const chains = [
    chain("pre", "ip nat", "prerouting", "accept",
      [R("tcp dport 80", "dnat", { to: "10.20.0.5:8080" })], -100),
    chain("in", "inet filter", "input", "accept"),
  ];
  const r = run(chains, { ...V4 });
  assert.equal(r.packet.daddr, "10.20.0.5");
  assert.equal(r.packet.dport, 8080);
  assert.equal(r.packet.dnat, true);
});

/* The flags array was shared by a shallow copy, so a walk that touched it
   would have reached back into the caller's packet through it. */
test("the flags come back as their own array", () => {
  const p = { ...V4, flags: ["syn"] };
  const r = run([chain("in", "inet filter", "input", "accept")], p);
  assert.notEqual(r.packet.flags, p.flags);
  assert.deepEqual(r.packet.flags, p.flags);
});
