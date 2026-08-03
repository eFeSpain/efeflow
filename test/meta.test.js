/* Three matches whose answer the packet already contains, and which were
 * being assumed instead.
 *
 * The honest default — a construct nothing reads is taken as matching, and
 * named under the verdict — is right for `meta mark` and `meta skuid`, which
 * describe state this knows nothing about. It is the wrong answer for
 * something the packet on screen already says.
 *
 *   meta nfproto ipv4      the addresses say which family it is
 *   icmp type echo-request two claims, and one of them is just "it is ICMP"
 *   ip frag-off & 0x1fff   a packet described with ports and flags is a whole
 *                          packet, so its fragment offset is zero
 *
 * The last one is why this file exists. `ip frag-off & 0x1fff != 0 counter
 * drop` is the usual first line of an ingress chain — it was in the first line
 * of the first real one this ever walked — and taken as matching it swallowed
 * every packet before any rule below it was reached. The chain had just become
 * visible and immediately became a black hole. */
import test from "node:test";
import assert from "node:assert/strict";
import { MODEL } from "../src/core/model.js";
import { matches, unmodelled } from "../src/core/simulate.js";

const PKT = {
  dir: "in", iif: "wan0", oif: "", saddr: "203.0.113.5", daddr: "198.51.100.10",
  sport: 1, dport: 80, proto: "tcp", state: "new", tracked: true, nat: true,
  flags: ["syn"],
};
const V6 = { ...PKT, saddr: "2001:db8::1", daddr: "2001:db8::2" };

const hit = (expr, p = PKT) => {
  Object.assign(MODEL, { chains: [], sets: [], objects: [], tables: [], prelude: [] });
  return matches({ expr }, p);
};

/* ── meta nfproto ────────────────────────────────────────────────────────── */

test("the family is read off the addresses", () => {
  assert.equal(hit("meta nfproto ipv4"), true);
  assert.equal(hit("meta nfproto ipv6"), false);
  assert.equal(hit("meta nfproto ipv4", V6), false);
  assert.equal(hit("meta nfproto ipv6", V6), true);
  assert.equal(hit("meta nfproto { ipv4, ipv6 }"), true);
  assert.equal(hit("meta nfproto != ipv6"), true);
});

/* ── icmp ────────────────────────────────────────────────────────────────── */

/* Which ICMP message it is stays beyond this — there is no field on the packet
   for it. That it is ICMP at all is not, and masking the keyword along with
   the type threw that away too, so the rule matched a TCP packet and admitted
   only that it had not read something. */
test("an icmp rule does not match a packet that is not icmp", () => {
  assert.equal(hit("icmp type echo-request", { ...PKT, proto: "icmp" }), true);
  assert.equal(hit("icmp type echo-request"), false);
  assert.equal(hit("icmpv6 type nd-neighbor-solicit"), false);
  assert.equal(hit("icmpv6 type nd-neighbor-solicit", { ...V6, proto: "icmpv6" }), true);
});

test("and the type is still declared unread rather than answered", () => {
  assert.deepEqual(unmodelled("icmp type echo-request"), ["type echo-request"]);
});

/* ── fragments ───────────────────────────────────────────────────────────── */

test("a packet described here is a whole one, so it is not a later fragment", () => {
  assert.equal(hit("ip frag-off & 0x1fff != 0"), false);
  assert.equal(hit("ip frag-off & 0x1fff == 0"), true);
  assert.equal(hit("ip frag-off 0"), true);
});

test("and a frag-off this cannot read a number out of is left alone", () => {
  const expr = "ip frag-off & 0x1fff != $SOMETHING";
  assert.equal(hit(expr), true, "taken as matching");
  assert.ok(unmodelled(expr).length === 0 || hit(expr), "it did not invent an answer");
});

/* ── and what must stay assumed ──────────────────────────────────────────── */

/* Every fix above narrows what goes unread, and the temptation each time is to
   widen a matcher until it swallows something it cannot evaluate. These
   describe state that is nowhere on the packet, and they must keep saying so. */
test("what the packet does not carry is still admitted to", () => {
  for (const expr of ["meta mark 0x64", "meta skuid 1000", "meta length 40-1500",
                      "meta iifgroup 2", "ether saddr 00:11:22:33:44:55"])
    assert.deepEqual(unmodelled(expr), [expr], expr);
});
