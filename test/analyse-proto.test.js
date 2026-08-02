/* `ip protocol icmp` is a constraint, and the analyser could not see it.
 *
 * criteria() knew `meta l4proto` and nothing else, so a rule reading
 * `ip protocol icmp counter drop` came back with no criteria at all — which is
 * how the analyser spells "matches every packet". Everything below it was
 * therefore shadowed by it, and the shipped public-server sample reported
 * seven rules as dead that are all reachable and all doing their job.
 *
 * This is the direction that matters: not a finding missed, a finding invented
 * — and every one of them carrying a one-click Delete rule, with an Apply all
 * above them offering to take the lot. */
import test from "node:test";
import assert from "node:assert/strict";

import { MODEL } from "../src/core/model.js";
import { criteria, subsumes, analyse } from "../src/core/analyse.js";
import { parseNft } from "../src/core/parse.js";
import { sampleById } from "../src/core/samples.js";

test("a protocol match is read however nftables spells it", () => {
  for (const e of ["meta l4proto icmp", "ip protocol icmp", "ip6 nexthdr icmpv6"])
    assert.ok(criteria(e).l4, `${e} constrains the protocol and was read as constraining nothing`);
});

test("a rule that names a protocol does not cover one that names none", () => {
  assert.ok(!subsumes(criteria("ip protocol icmp"), criteria("tcp dport 22 ip saddr 10.0.0.1")),
    "an icmp rule cannot shadow a tcp one");
  assert.ok(!subsumes(criteria("ip protocol icmp"), criteria("")),
    "nor a rule with no matches at all");
});

test("it still covers what it genuinely covers", () => {
  assert.ok(subsumes(criteria("ip protocol icmp"), criteria("ip protocol icmp ip saddr 10.0.0.1")),
    "the same protocol, narrowed by a source, is genuinely covered");
});

/* The sample is the point: it is one of the eight the product offers to load,
   and it was being told seven of its rules were dead. */
test("the public-server sample has no shadowed rules, because it has none", (t) => {
  const saved = { chains: MODEL.chains, sets: MODEL.sets };
  t.after(() => { MODEL.chains = saved.chains; MODEL.sets = saved.sets; });

  const p = parseNft(sampleById("public-server").nft);
  MODEL.chains = p.chains;
  MODEL.sets = p.sets;

  const shadowed = analyse().filter((f) => f.kind === "shadowed");
  assert.deepEqual(
    shadowed.map((f) => f.i + 1), [],
    "rules reported dead that a packet reaches every day",
  );
});

/* Nothing that ships should offer to delete a rule that is not dead. */
test("no shipped sample is told to delete a rule it needs", async (t) => {
  const saved = { chains: MODEL.chains, sets: MODEL.sets };
  t.after(() => { MODEL.chains = saved.chains; MODEL.sets = saved.sets; });

  const { SAMPLES } = await import("../src/core/samples.js");
  for (const s of SAMPLES) {
    const p = parseNft(s.nft);
    MODEL.chains = p.chains;
    MODEL.sets = p.sets;
    const dead = analyse().filter((f) => f.kind === "shadowed");
    assert.deepEqual(dead.map((f) => `${f.chain.id}:${f.i + 1}`), [],
      `${s.id} is offered a fix that deletes a working rule`);
  }
});
