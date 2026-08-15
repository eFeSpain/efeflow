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

/* An address set in braces is a criterion like any other. The saddr/daddr
   pattern read only the first token — the `{` — so a rule matching a braced set
   was opaque, comparable to nothing, and every such rule stood outside the
   analysis. sport/dport already read the brace; addresses do now too. */
test("a braced address set is read, not swallowed as an opaque `{`", () => {
  assert.equal(c("ip6 saddr { 2001:db8::1, 2001:db8::2 } tcp dport 53").saddr,
    "{ 2001:db8::1, 2001:db8::2 }");
  assert.equal(c("ip saddr { 10.0.0.1, 10.0.0.2 } tcp dport 22")._opaque, false,
    "reading the set means nothing is left unread");
  /* and it covers correctly: the set covers each of its members, not the reverse */
  assert.ok(subsumes(c("ip saddr { 10.0.0.1, 10.0.0.2 }"), c("ip saddr 10.0.0.1")));
  assert.ok(!subsumes(c("ip saddr 10.0.0.1"), c("ip saddr { 10.0.0.1, 10.0.0.2 }")),
    "one address does not cover a set that includes another");
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

/* The families part company even when no address is written.
 *
 * `ip protocol ospf` and `ip6 nexthdr ospf` name the same transport, so they
 * read as the same l4 criterion — and in an inet chain that is true about the
 * protocol and false about the packet: the first matches only IPv4, the second
 * only IPv6, and no packet is both. Three corpus rulesets carried this pair
 * and the analyser called the v6 rule shadowed by the v4 one, with a Delete
 * offered above it — a button that would have taken OSPFv3 off a live router.
 *
 * The corpus analyse pass found it: the packet built from the dead rule's own
 * criteria matched the rule but not the one said to cover it. `meta l4proto`
 * stays family-neutral, which is the whole point of writing it that way. */
test("one family's protocol match does not cover the other's", () => {
  assert.ok(!subsumes(c("ip protocol ospf"), c("ip6 nexthdr ospf")),
    "an IPv4-only rule cannot cover the IPv6 packets that never reach it");
  assert.ok(!subsumes(c("ip6 nexthdr ospf"), c("ip protocol ospf")));
  assert.ok(!overlaps(c("ip protocol ospf"), c("ip6 nexthdr ospf")),
    "no packet is both IPv4 and IPv6");
  /* the neutral spelling still covers, because it really does match both */
  assert.ok(subsumes(c("meta l4proto ospf"), c("ip6 nexthdr ospf")));
});

test("a v6-pinned rule is not shadowed by a v4-pinned one, end to end", (t) => {
  Object.assign(MODEL, {
    chains: [{ table: "inet f", id: "input", hook: "input", type: "filter",
      prio: 0, policy: "drop", rules: [
        { expr: "ip protocol ospf", verdict: "accept", on: true },
        { expr: "ip6 nexthdr ospf", verdict: "accept", on: true },
      ] }],
    sets: [], objects: [], tables: [{ name: "inet f", extra: [] }], prelude: [], preludeAt: [],
  });
  const dead = analyse().filter((f) => f.kind === "shadowed");
  assert.equal(dead.length, 0, JSON.stringify(dead.map((f) => f.title?.[0])));
});
