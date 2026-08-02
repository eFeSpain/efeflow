/* What the evaluator does with a match it does not understand.
 *
 * It ignored it. Not "approximated it" — ignored it, so the rule matched every
 * packet: `meta mark 0x1 drop` dropped everything in the trace. That is the
 * same failure as `ip6 saddr` matching every packet and `iif "lo"` matching
 * every interface, and it is the one this screen can least afford, because its
 * whole claim is that the verdict here is the verdict your ruleset gives you.
 *
 * There is no fixing it by modelling more of nftables — the language is larger
 * than any model of it, and the free-text rule editor means anything in it can
 * now be written. What can be fixed is the silence. */
import test from "node:test";
import assert from "node:assert/strict";

import { MODEL, R } from "../src/core/model.js";
import { matches, unmodelled, evaluate, PRESETS } from "../src/core/simulate.js";

const PKT = { saddr: "8.8.8.8", daddr: "10.0.0.1", proto: "tcp", dport: 443,
              sport: 5000, iif: "wan0", oif: "", tracked: true, state: "new", flags: ["syn"] };

test("a rule made only of things it reads is understood whole", () => {
  for (const e of [
    "ct state established,related",
    'iifname "wan0" tcp dport 443',
    "ip saddr 10.0.0.0/8 ip daddr 10.0.0.1",
    "ip6 saddr 2001:db8::/32",
    "tcp flags & (syn|ack) == syn",
    "meta l4proto { tcp, udp }",
    "",
  ])
    assert.deepEqual(unmodelled(e), [], e);
});

test("statements that do not decide whether a rule matches are not held against it", () => {
  assert.deepEqual(unmodelled('tcp dport 22 log prefix "ssh " level info'), []);
  assert.deepEqual(unmodelled("counter"), []);
});

/* Every one of these is nftables, all of them are now writable in the rule
   editor, and none of them is something the evaluator reads. */
test("a match it cannot read is reported, not ignored", () => {
  assert.deepEqual(unmodelled("meta mark 0x1"), ["meta mark 0x1"]);
  assert.deepEqual(unmodelled("ct mark 0x9"), ["ct mark 0x9"]);
  assert.deepEqual(unmodelled("vlan id 30"), ["vlan id 30"]);
  assert.deepEqual(unmodelled("fib saddr . iif oif missing"), ["fib saddr . iif oif missing"]);
  assert.deepEqual(unmodelled("tcp dport 22 meta skuid 1000"), ["meta skuid 1000"],
    "only the part it could not read");
});

/* A rate limit depends on traffic the simulator has not got, so a rule that
   carries one is not a rule it can be certain about either. The analyser has
   always refused to reason about them; this says the same out loud. */
test("a rate limit is a thing it cannot know", () => {
  assert.deepEqual(unmodelled("limit rate 5/second burst 10 packets"),
    ["limit rate 5/second burst 10 packets"]);
});

/* The optimism itself is not the bug and is not being changed: assuming the
   unknown part matches is the only useful guess. Claiming to be sure is. */
test("an unreadable rule is still taken as matching, and said to be a guess", () => {
  const r = { expr: "meta mark 0x1", verdict: "drop", on: true };
  assert.equal(matches(r, PKT), true, "the optimistic guess is still the useful one");
});

test("a verdict reached through a rule it could not read is not reported as certain", () => {
  MODEL.chains = [{
    id: "input", table: "inet filter", hook: "input", prio: 0, type: "filter",
    policy: "accept", rules: [R("meta mark 0x1", "drop"), R("tcp dport 443", "accept")],
  }];
  MODEL.sets = [];

  const res = evaluate({ ...PKT, dir: "in", nat: true });
  assert.equal(res.final.v, "drop");
  assert.equal(res.sure, false, "the drop rests on a match nothing evaluated");
  assert.deepEqual(res.unsure, ["meta mark 0x1"]);
});

test("a verdict reached only through rules it read is certain", () => {
  MODEL.chains = [{
    id: "input", table: "inet filter", hook: "input", prio: 0, type: "filter",
    policy: "drop", rules: [R("tcp dport 443", "accept")],
  }];
  MODEL.sets = [];

  const res = evaluate({ ...PKT, dir: "in", nat: true });
  assert.equal(res.final.v, "accept");
  assert.equal(res.sure, true);
  assert.deepEqual(res.unsure, []);
});

/* A rule that misses on something the evaluator did read is a certain miss,
   whatever else it carries — the unreadable part never came into it. */
test("a rule that misses for a reason it understood does not make the trace a guess", () => {
  MODEL.chains = [{
    id: "input", table: "inet filter", hook: "input", prio: 0, type: "filter",
    policy: "drop", rules: [R("meta mark 0x1 tcp dport 22", "accept")],
  }];
  MODEL.sets = [];

  const res = evaluate({ ...PKT, dir: "in", nat: true });
  assert.equal(res.final.v, "drop", "dport 443 is not 22, mark or no mark");
  assert.equal(res.sure, true);
});

test("the rules it guessed at are marked in the trace, not only in the total", () => {
  MODEL.chains = [{
    id: "input", table: "inet filter", hook: "input", prio: 0, type: "filter",
    policy: "accept", rules: [R("meta mark 0x1", "drop")],
  }];
  MODEL.sets = [];

  const ev = evaluate({ ...PKT, dir: "in", nat: true }).steps[0].evs[0];
  assert.equal(ev.st, "match");
  assert.deepEqual(ev.unsure, ["meta mark 0x1"]);
});
