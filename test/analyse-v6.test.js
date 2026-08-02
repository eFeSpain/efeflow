/* The analyser reasons about coverage, and only knew one family's addresses.
 *
 * The containment test was gated behind a regex that only IPv4 could pass, so
 * a v6 rule shadowed by a broader v6 rule went unreported. It failed in the
 * safe direction — a finding missed, never one invented — but the simulator
 * understands both families now, and an analyser that only understands one is
 * an inconsistency you would eventually trip over rather than a caveat. */
import test from "node:test";
import assert from "node:assert/strict";

import { MODEL } from "../src/core/model.js";
import { criteria, subsumes, overlaps, analyse } from "../src/core/analyse.js";

const c = (e) => criteria(e);

test("a wider IPv4 prefix covers a narrower one, as it always did", () => {
  assert.ok(subsumes(c("ip saddr 10.0.0.0/8"), c("ip saddr 10.1.0.0/16")));
  assert.ok(!subsumes(c("ip saddr 10.1.0.0/16"), c("ip saddr 10.0.0.0/8")));
});

test("a wider IPv6 prefix covers a narrower one too", () => {
  assert.ok(subsumes(c("ip6 saddr 2001:db8::/32"), c("ip6 saddr 2001:db8:1::/48")));
  assert.ok(!subsumes(c("ip6 saddr 2001:db8:1::/48"), c("ip6 saddr 2001:db8::/32")));
  assert.ok(subsumes(c("ip6 saddr ::/0"), c("ip6 saddr 2001:db8::/32")), "the whole of v6");
  assert.ok(subsumes(c("ip6 saddr 2001:db8::/32"), c("ip6 saddr 2001:db8::5")), "a bare address");
});

test("an address outside the prefix is not covered by it", () => {
  assert.ok(!subsumes(c("ip6 saddr 2001:db8::/32"), c("ip6 saddr 2001:dbe::/32")));
  assert.ok(!subsumes(c("ip saddr 10.0.0.0/8"), c("ip saddr 192.168.0.0/16")));
});

/* An inet table spells out both because they do not overlap. Nothing in one
   family may ever be reported as covering anything in the other. */
test("neither family covers the other, in either direction", () => {
  assert.ok(!subsumes(c("ip saddr 0.0.0.0/0"), c("ip6 saddr 2001:db8::/32")));
  assert.ok(!subsumes(c("ip6 saddr ::/0"), c("ip saddr 10.0.0.0/8")));
  assert.ok(!overlaps(c("ip saddr 10.0.0.0/8"), c("ip6 saddr 2001:db8::/32")));
});

/* A prefix written unnormalised still says how many bits it fixes. */
test("coverage follows the prefix length, not just the network address", () => {
  assert.ok(!subsumes(c("ip saddr 10.1.0.0/16"), c("ip saddr 10.1.0.0/8")),
    "a /8 is broader than the /16 it happens to start inside");
  assert.ok(!subsumes(c("ip6 saddr 2001:db8::/48"), c("ip6 saddr 2001:db8::/32")));
});

test("a shadowed IPv6 rule is reported like a shadowed IPv4 one", (t) => {
  const saved = { chains: MODEL.chains, sets: MODEL.sets };
  t.after(() => { MODEL.chains = saved.chains; MODEL.sets = saved.sets; });

  MODEL.sets = [];
  MODEL.chains = [{
    id: "input", table: "inet filter", hook: "input", prio: 0, type: "filter",
    policy: "drop", rules: [
      { expr: "ip6 saddr 2001:db8::/32", verdict: "drop", on: true, pkts: 0, bytes: 0 },
      { expr: "ip6 saddr 2001:db8:1::/48", verdict: "drop", on: true, pkts: 0, bytes: 0 },
    ],
  }];

  const shadowed = analyse().filter((f) => f.kind === "shadowed");
  assert.equal(shadowed.length, 1, "the second rule can never match");
  assert.equal(shadowed[0].i, 1);
});

test("two IPv6 rules that do not overlap are left alone", (t) => {
  const saved = { chains: MODEL.chains, sets: MODEL.sets };
  t.after(() => { MODEL.chains = saved.chains; MODEL.sets = saved.sets; });

  MODEL.sets = [];
  MODEL.chains = [{
    id: "input", table: "inet filter", hook: "input", prio: 0, type: "filter",
    policy: "drop", rules: [
      { expr: "ip6 saddr 2001:db8::/32", verdict: "drop", on: true, pkts: 0, bytes: 0 },
      { expr: "ip6 saddr 2001:dbe::/32", verdict: "drop", on: true, pkts: 0, bytes: 0 },
    ],
  }];

  assert.deepEqual(analyse().filter((f) => f.kind === "shadowed"), []);
});
