/* The hooks that were not on the map, and the NAT target that was a lookup.
 *
 * `PATHS` listed prerouting, input, forward, output and postrouting. netdev's
 * `ingress` runs before the first of those and `egress` after the last, and
 * neither was there — so a netdev chain was never walked by anything. It is
 * not an exotic corner: filtering rogue DHCP on a bridge is one of the
 * scenarios this ships as a sample, and on that sample the real firewall
 * dropped the packet while the trace said accept and looked certain.
 *
 * And `dnat to tcp dport map @port_fwd`, which is how port forwarding is
 * written once there is more than one of it. The whole expression was applied
 * to the packet as its destination — a string no address matcher recognises —
 * so every rule below a forwarding map missed. It is the first rule of the NAT
 * chain in the ruleset that turned this up. */
import test from "node:test";
import assert from "node:assert/strict";
import { MODEL, R } from "../src/core/model.js";
import { evaluate, setPacket, packet, natLookup, chainDevices } from "../src/core/simulate.js";

const PKT = {
  dir: "in", iif: "wan0", oif: "lan0", saddr: "203.0.113.5", daddr: "198.51.100.10",
  sport: 49812, dport: 80, proto: "tcp", state: "new", tracked: true, nat: true,
  flags: ["syn"],
};
const chain = (o) => ({ table: "t", prio: 0, type: "filter", policy: "accept", rules: [], ...o });

function run(chains, over = {}, sets = []) {
  Object.assign(MODEL, { sets, objects: [], tables: [], prelude: [], chains });
  setPacket({ ...PKT, ...over });
  return evaluate(packet);
}

/* ── netdev is on the path now ───────────────────────────────────────────── */

test("an ingress chain is walked, and before prerouting", () => {
  const r = run([
    chain({ id: "pre", hook: "prerouting", prio: -300 }),
    chain({ id: "ing", hook: "ingress", dev: 'device "wan0"', prio: -500 }),
    chain({ id: "input", hook: "input" }),
  ]);
  assert.deepEqual(r.steps.map((s) => s.chain.id), ["ing", "pre", "input"]);
});

test("an egress chain is walked, and after postrouting", () => {
  const r = run([
    chain({ id: "eg", hook: "egress", dev: 'device "wan0"' }),
    chain({ id: "post", hook: "postrouting" }),
    chain({ id: "out", hook: "output" }),
  ], { dir: "out", oif: "wan0" });
  assert.deepEqual(r.steps.map((s) => s.chain.id), ["out", "post", "eg"]);
});

test("and it can decide the packet, which is the whole point", () => {
  const chains = [
    chain({ id: "ing", hook: "ingress", dev: 'device "wan0"', prio: -500,
            rules: [R("ip saddr 203.0.113.5", "drop")] }),
    chain({ id: "input", hook: "input" }),
  ];
  assert.equal(run(chains).final.v, "drop");
});

/* ── but only for packets on its device ──────────────────────────────────── */

test("a chain on wan0 says nothing about traffic arriving on br-lan", () => {
  const chains = [
    chain({ id: "ing", hook: "ingress", dev: 'device "wan0"', prio: -500,
            rules: [R("", "drop")] }),
    chain({ id: "input", hook: "input" }),
  ];
  assert.equal(run(chains, { iif: "wan0" }).final.v, "drop");
  assert.equal(run(chains, { iif: "br-lan" }).final.v, "accept");
});

test("an egress chain reads the outgoing device, not the incoming one", () => {
  const chains = [
    chain({ id: "eg", hook: "egress", dev: 'device "wan0"', rules: [R("", "drop")] }),
    chain({ id: "out", hook: "output" }),
  ];
  assert.equal(run(chains, { dir: "out", oif: "wan0" }).final.v, "drop");
  assert.equal(run(chains, { dir: "out", oif: "lan0" }).final.v, "accept");
});

test("the device list is read in both spellings, wildcards included", () => {
  assert.deepEqual(chainDevices({ dev: 'device "wan0"' }), ["wan0"]);
  assert.deepEqual(chainDevices({ dev: "devices = { eth0, br0 }" }), ["eth0", "br0"]);
  assert.deepEqual(chainDevices({ dev: null }), []);
  const chains = [
    chain({ id: "ing", hook: "ingress", dev: 'device "veth*"', prio: -500,
            rules: [R("", "drop")] }),
    chain({ id: "input", hook: "input" }),
  ];
  assert.equal(run(chains, { iif: "veth9a1" }).final.v, "drop");
  assert.equal(run(chains, { iif: "eth0" }).final.v, "accept");
});

/* ── a NAT target that is a lookup ───────────────────────────────────────── */

const FWD = [{ n: "port_fwd", el: ["8443 : 10.20.0.31:443", "25 : 10.20.0.40", "80 : 10.20.0.10:8080"] }];

test("the key is read off the packet and the map says where it goes", () => {
  /* natLookup reads the set out of the model, like everything else here */
  Object.assign(MODEL, { chains: [], sets: FWD, objects: [], tables: [], prelude: [] });
  assert.deepEqual(natLookup("tcp dport map @port_fwd", { ...PKT, dport: 8443 }),
    { to: "10.20.0.31:443", missed: false, assumed: [] });
  assert.deepEqual(natLookup("tcp dport map @port_fwd", { ...PKT, dport: 9999 }),
    { to: null, missed: true, assumed: [] });
});

test("a value with no port leaves the port alone", () => {
  Object.assign(MODEL, { chains: [], sets: FWD, objects: [], tables: [], prelude: [] });
  const r = run([
    chain({ id: "pre", hook: "prerouting", prio: -100, type: "nat",
            rules: [R("", "dnat", { to: "tcp dport map @port_fwd" })] }),
    chain({ id: "input", hook: "input" }),
  ], { dport: 25 }, FWD);
  assert.equal(r.packet.daddr, "10.20.0.40");
  assert.equal(r.packet.dport, 25, "the map named a host and not a port");
  assert.equal(r.sure, true);
});

/* The map is part of the expression, so a key it does not hold means the rule
   does not fire — not that the packet is translated to nowhere. */
test("a key the map does not hold means the rule does not fire", () => {
  const r = run([
    chain({ id: "pre", hook: "prerouting", prio: -100, type: "nat",
            rules: [R("", "dnat", { to: "tcp dport map @port_fwd" }),
                    R("", "dnat", { to: "10.99.0.1" })] }),
    chain({ id: "input", hook: "input" }),
  ], { dport: 9999 }, FWD);
  assert.equal(r.packet.daddr, "10.99.0.1", "it walked on to the rule below");
  assert.equal(r.sure, true);
});

test("and the destination it produces is one the rules below can match", () => {
  const r = run([
    chain({ id: "pre", hook: "prerouting", prio: -100, type: "nat",
            rules: [R("", "dnat", { to: "tcp dport map @port_fwd" })] }),
    chain({ id: "input", hook: "input", policy: "drop",
            rules: [R("ip daddr 10.20.0.31 tcp dport 443", "accept")] }),
  ], { dport: 8443 }, FWD);
  assert.equal(r.final.v, "accept");
});

test("a map on a key nothing reads is admitted to rather than applied", () => {
  const before = { ...PKT };
  const r = run([
    chain({ id: "pre", hook: "prerouting", prio: -100, type: "nat",
            rules: [R("", "dnat", { to: "meta mark map @port_fwd" })] }),
    chain({ id: "input", hook: "input" }),
  ], {}, FWD);
  assert.equal(r.packet.daddr, before.daddr, "nothing was invented for the destination");
  assert.equal(r.sure, false);
  assert.ok(r.unsure.some((u) => /cannot read/.test(u)), JSON.stringify(r.unsure));
});
