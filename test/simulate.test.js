import test from "node:test";
import assert from "node:assert/strict";

import { evaluate, matches, PRESETS } from "../src/core/simulate.js";

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
