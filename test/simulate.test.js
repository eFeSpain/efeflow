import test from "node:test";
import assert from "node:assert/strict";

import { evaluate, matches, unmodelled, PRESETS } from "../src/core/simulate.js";
import { MODEL } from "../src/core/model.js";
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

/* `ip6 saddr` was not recognised as an address match at all, so it constrained
   nothing: a v6 prefix drop applied to every packet that reached it, IPv4
   included. Same shape as `iif "lo"` matching every interface. */
test("an IPv6 rule constrains IPv6, and only that", () => {
  const r = { expr: "ip6 saddr 2001:db8::/32", verdict: "drop", on: true };
  assert.ok(matches(r, { saddr: "2001:db8:1::5", tracked: true }));
  assert.ok(!matches(r, { saddr: "2001:db9::5", tracked: true }), "outside the prefix");
  assert.ok(!matches(r, { saddr: "8.8.8.8", tracked: true }),
    "a v6 prefix matched an IPv4 packet — the rule did far more than it said");
});

test("an IPv4 rule never reaches an IPv6 packet", () => {
  const r = { expr: "ip saddr 0.0.0.0/0", verdict: "drop", on: true };
  assert.ok(matches(r, { saddr: "8.8.8.8", tracked: true }));
  assert.ok(!matches(r, { saddr: "2001:db8::1", tracked: true }));
});

test("both families work in sets, lists and negations", (t) => {
  const sets = MODEL.sets;
  t.after(() => { MODEL.sets = sets; });

  const set = { expr: "ip6 saddr @v6trusted", verdict: "accept", on: true };
  MODEL.sets = [{ n: "v6trusted", t: "ipv6_addr", f: "interval", el: ["2001:db8::/32"] }];
  assert.ok(matches(set, { saddr: "2001:db8::9", tracked: true }));
  assert.ok(!matches(set, { saddr: "2001:dbe::9", tracked: true }));

  const list = { expr: "ip6 daddr { 2001:db8::1, ::1 }", verdict: "accept", on: true };
  assert.ok(matches(list, { daddr: "::1", tracked: true }));
  assert.ok(matches(list, { daddr: "2001:0db8:0000::0001", tracked: true }), "however it is spelled");
  assert.ok(!matches(list, { daddr: "2001:db8::2", tracked: true }));

  const neg = { expr: "ip6 saddr != 2001:db8::/32", verdict: "drop", on: true };
  assert.ok(matches(neg, { saddr: "2001:dbe::1", tracked: true }));
  assert.ok(!matches(neg, { saddr: "2001:db8::1", tracked: true }));
});

/* Three more of the same family, all found by asking the evaluator to account
   for what it had read: it stopped at the first occurrence of each kind of
   match, it never read `ip protocol` at all, and it read the `oif` out of the
   middle of a fib lookup as though it were an interface constraint. */
test("a second match of the same kind is not skipped", () => {
  const r = { expr: "udp sport 67 udp dport 68", verdict: "drop", on: true };
  assert.ok(matches(r, { proto: "udp", sport: 67, dport: 68, tracked: true }));
  assert.ok(!matches(r, { proto: "udp", sport: 67, dport: 9999, tracked: true }),
    "the second port match was never checked, so the rule took any port");
});

test("ip protocol constrains the protocol", () => {
  const r = { expr: "ip protocol icmp", verdict: "drop", on: true };
  assert.ok(matches(r, { saddr: "8.8.8.8", proto: "icmp", tracked: true }));
  assert.ok(!matches(r, { saddr: "8.8.8.8", proto: "tcp", tracked: true }));
});

/* `fib saddr . iif oif missing` is the standard anti-spoofing rule. Reading
   the oif out of it compared the packet's output interface against the string
   "missing", so the rule never fired and was not flagged either — a miss for a
   reason that was not a reason. */
test("a fib lookup is not mistaken for an interface constraint", () => {
  const r = { expr: "fib saddr . iif oif missing", verdict: "drop", on: true };
  assert.ok(matches(r, { saddr: "8.8.8.8", oif: "wan0", tracked: true }),
    "nothing here can be evaluated, so the useful guess is that it matches");
  assert.deepEqual(unmodelled(r.expr), ["fib saddr . iif oif missing"]);
});

test("meta is allowed in front of an interface match, as nft allows it", () => {
  const r = { expr: 'meta iifname "wan0"', verdict: "drop", on: true };
  assert.ok(matches(r, { iif: "wan0", tracked: true }));
  assert.ok(!matches(r, { iif: "lan0", tracked: true }));
  assert.deepEqual(unmodelled(r.expr), []);
});

/* the exact report: the sample ruleset's third input rule is `iif "lo"` */
test("a packet from wan0 does not stop at the loopback rule", () => {
  const lo = { expr: 'iif "lo"', verdict: "accept", on: true };
  assert.ok(!matches(lo, { ...PRESETS.ssh }), "ssh arrives on wan0, not on lo");
});
