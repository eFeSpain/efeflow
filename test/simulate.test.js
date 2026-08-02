import test from "node:test";
import assert from "node:assert/strict";

import { evaluate, matches, PRESETS } from "../src/core/simulate.js";
import { loadFlawed } from "./fixture.js";

loadFlawed();

const run = (over = {}) => {
  const p = { ...PRESETS.ssh, ...over };
  p.flags = [...(over.flags || p.flags)];
  const r = evaluate(p);
  return {
    v: r.final.v,
    chains: [...new Set(r.steps.map((s) => s.chain.id))],
    evals: r.steps.reduce((a, s) => a + s.evs.length, 0),
  };
};

test("direction chooses the path the kernel would take", () => {
  assert.deepEqual(run({ dir: "in" }).chains, ["raw_pre", "nat_pre", "input"]);
  assert.deepEqual(run(PRESETS.fwd).chains, ["raw_pre", "nat_pre", "forward", "nat_post"]);
  assert.deepEqual(run(PRESETS.egress).chains, ["output", "nat_post"]);
});

test("accept ends the chain, not the packet", () => {
  // wireguard is accepted in the nat chain, but must still traverse input
  const r = run({ proto: "udp", dport: 51820 });
  assert.ok(r.chains.includes("input"), "packet continues past the nat hook");
  assert.equal(r.v, "accept");
});

test("skipping NAT changes the verdict, not just the view", () => {
  assert.equal(run({ ...PRESETS.dnat, nat: true }).v, "accept");
  assert.equal(run({ ...PRESETS.dnat, nat: false }).v, "drop");
});

test("an untracked packet cannot use the conntrack fast path", () => {
  assert.equal(run({ state: "established", tracked: true }).v, "accept");
  assert.equal(run({ state: "established", tracked: false }).v, "drop");
});

test("tcp flag matching distinguishes presence from exclusivity", () => {
  const presence = { expr: "tcp flags syn", verdict: "drop", on: true };
  const exclusive = { expr: "tcp flags & (syn|ack) == syn", verdict: "accept", on: true };
  const pkt = (flags) => ({ proto: "tcp", flags, tracked: true });

  assert.ok(matches(presence, pkt(["syn"])));
  assert.ok(matches(presence, pkt(["syn", "ack"])), "presence test also matches syn|ack");
  assert.ok(!matches(presence, pkt(["ack"])));

  assert.ok(matches(exclusive, pkt(["syn"])));
  assert.ok(!matches(exclusive, pkt(["syn", "ack"])), "masked test rejects syn|ack");
});

test("unquoted iif/oif interface names are honoured", () => {
  const loOut = { expr: "oif lo", verdict: "accept", on: true };
  assert.ok(matches(loOut, { oif: "lo", tracked: true }));
  assert.ok(!matches(loOut, { oif: "wan0", tracked: true }), "must not match every interface");
});

/* `iif "lo"` is what nft prints, so it is what every imported ruleset contains.
   It used to match every packet: the bare form was special-cased for lo only,
   and the quoted form was only recognised after `iifname`. A packet arriving on
   wan0 walked into the loopback rule and was accepted there. */
test("an interface constraint holds however it is spelled", () => {
  const r = (expr) => ({ expr, verdict: "accept", on: true });
  const on = (iif) => ({ iif, tracked: true });

  for (const expr of ['iif "lo"', "iif lo", 'iifname "lo"', "iifname lo"]) {
    assert.ok(matches(r(expr), on("lo")), `${expr} should match lo`);
    assert.ok(!matches(r(expr), on("wan0")),
      `${expr} matched a packet from wan0 — the constraint was dropped`);
  }
});

test("interface names other than lo are honoured too", () => {
  const r = { expr: 'iif "eth0"', verdict: "accept", on: true };
  assert.ok(matches(r, { iif: "eth0", tracked: true }));
  assert.ok(!matches(r, { iif: "eth1", tracked: true }));
  assert.ok(!matches(r, { iif: "", tracked: true }), "no interface is not every interface");
});

test("a negated or listed interface behaves", () => {
  const neg = { expr: 'iifname != "wan0"', verdict: "accept", on: true };
  assert.ok(matches(neg, { iif: "br-lan", tracked: true }));
  assert.ok(!matches(neg, { iif: "wan0", tracked: true }));

  const list = { expr: 'iifname { "br-lan", "wg0" }', verdict: "accept", on: true };
  assert.ok(matches(list, { iif: "wg0", tracked: true }));
  assert.ok(!matches(list, { iif: "wan0", tracked: true }));
});

/* the exact report: the sample ruleset's third input rule is `iif "lo"` */
test("a packet from wan0 does not stop at the loopback rule", () => {
  const lo = { expr: 'iif "lo"', verdict: "accept", on: true };
  assert.ok(!matches(lo, { ...PRESETS.ssh }), "ssh arrives on wan0, not on lo");
});
