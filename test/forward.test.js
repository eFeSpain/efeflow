/* The forward hook, and the two things about it nothing here had ever tried:
 * a packet with a real iif and a real oif at the same time, and the reply that
 * comes back the other way.
 *
 * Every other hook lets one of the two be empty, so a matcher can read the
 * wrong one and still look right. On forward both are set and they are
 * different interfaces, which is the only arrangement where reading `oif` out
 * of the middle of a rule that said `iif` shows up as a wrong answer instead of
 * as no answer at all.
 *
 * The numbers below were measured, not reasoned about: two veth pairs, each far
 * end in a network namespace of its own, IP forwarding on in the middle, and a
 * real TCP connection from one side to the other with a reply. Eleven packets
 * crossed — six out, five back — and every counter here is what nftables 1.0.6
 * on Linux 6.1 actually recorded.
 *
 * Fragments were measured on the same bench and are the second half of the
 * file. They are the one case where the honest answer is "not this packet":
 * the interface describes a whole datagram, and a later fragment is not one.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { MODEL } from "../src/core/model.js";
import { matches, unmodelled } from "../src/core/simulate.js";

Object.assign(MODEL, { chains: [], sets: [], objects: [], tables: [], prelude: [] });

/* the flow that was actually put through the kernel */
const OUT = {
  dir: "fwd", iif: "a0", oif: "b0", saddr: "10.1.0.2", daddr: "10.2.0.2",
  sport: 40000, dport: 9100, proto: "tcp", state: "new", tracked: true, nat: true,
  flags: ["syn"],
};
const BACK = {
  ...OUT, iif: "b0", oif: "a0", saddr: "10.2.0.2", daddr: "10.1.0.2",
  sport: 9100, dport: 40000, state: "established", flags: ["ack"],
};

const hits = (expr, onOut, onBack) =>
  test(`forward: ${expr}`, () => {
    assert.equal(matches({ expr }, OUT), onOut, "on the way out");
    assert.equal(matches({ expr }, BACK), onBack, "on the way back");
  });

/* ── both interfaces at once ─────────────────────────────────────────────── */

hits('iif "a0"', true, false);
hits('oif "b0"', true, false);
hits('iif "a0" oif "b0"', true, false);
hits('iif "b0" oif "a0"', false, true);
/* the pairing is the whole point: neither half alone tells them apart */
hits('iif "a0" oif "a0"', false, false);
hits('iif "b0" oif "b0"', false, false);

/* ── the same, written as names with wildcards ───────────────────────────── */

hits('iifname "a*" oifname "b*"', true, false);
hits('iifname "b*" oifname "a*"', false, true);
hits('iifname "a*" oifname "a*"', false, false);

/* ── the reply is a different packet, not the same one backwards ─────────── */

hits("ct state new", true, false);
hits("ct state established", false, true);
hits("tcp dport 9100", true, false);
hits("tcp sport 9100", false, true);
hits("ip saddr 10.1.0.2", true, false);
hits("ip daddr 10.1.0.2", false, true);
hits("tcp flags syn", true, false);
hits("tcp flags ack", false, true);

/* ── what it cannot answer, it still refuses to answer ───────────────────── */

/* `ct direction` is real, it is common in forward rulesets, and the kernel
   distinguished the two directions cleanly on this bench. It is not modelled
   here, because the packet the interface describes has a state and no flow:
   a `new` packet is always the original direction, an `established` one can be
   either, and there is nowhere to say which. Widening the matcher to guess
   would swap a declared "I don't know" for an undeclared wrong answer, which
   is the trade this project keeps refusing.
 *
 * `meta length` is the same: there is no length on the packet, so there is
 * nothing to compare. */
test("a construct with nothing behind it is named rather than guessed at", () => {
  for (const expr of ["ct direction original", "ct direction reply", "meta length > 1400"]) {
    assert.deepEqual(unmodelled(expr), [expr], expr);
    /* and the guess it makes meanwhile is the safe one: the rule is taken as
       matching, so the verdict shown is the one the rule would have given */
    assert.equal(matches({ expr }, OUT), true, expr);
  }
});

/* ── fragments ───────────────────────────────────────────────────────────── */

/* Measured on the same bench, with a 4000-byte UDP datagram over a 1500-byte
 * link, which the sender split into three:
 *
 *   input, any family        1 packet, whole. The IP stack reassembles before
 *                            local delivery, always, so `ip frag-off & 0x1fff
 *                            != 0` at input never matches anything.
 *   prerouting / forward     3 packets, 2 of them later fragments — but only
 *     with no conntrack      while nothing has registered defragmentation.
 *   prerouting / forward     1 packet, whole. One `ct state` rule anywhere
 *     with a ct rule         brings defrag in at priority -400 and everything
 *                            downstream sees reassembled datagrams.
 *   netdev ingress           3 packets, always. It runs before all of it.
 *
 * The consequence worth knowing is in the middle row: on that bench `udp dport
 * 9999` at forward matched one packet out of four, so three fragments crossed
 * a port filter that was written to stop them. Adding `ct state` fixed it, and
 * that is why every ruleset in this repo has one.
 *
 * None of it changes what the evaluator should answer, because the packet the
 * interface describes is a whole datagram: it carries ports and TCP flags, so
 * its fragment offset is zero and it is not a later fragment. Saying so is a
 * definite answer and a correct one. */
test("a whole packet is not a later fragment, and that is not a guess", () => {
  for (const p of [OUT, BACK]) {
    assert.equal(matches({ expr: "ip frag-off & 0x1fff != 0" }, p), false);
    assert.equal(matches({ expr: "ip frag-off & 0x1fff == 0" }, p), true);
  }
  assert.deepEqual(unmodelled("ip frag-off & 0x1fff != 0"), []);
});
