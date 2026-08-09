import test from "node:test";
import assert from "node:assert/strict";

import { parseNft, roundTrip, verify } from "../src/core/parse.js";
import { SAMPLES, sampleById } from "../src/core/samples.js";

/* Anything the product offers to load has to clear the same bar it holds the
   user's own ruleset to. A sample that lost a rule on the way in would make
   the honest round-trip percentage a liar on the very rulesets a new user
   reaches for first. Every one of them, not just the first. */

test("there are samples, each identified once", () => {
  assert.ok(SAMPLES.length >= 5, "a single example is not a library of scenarios");
  const ids = SAMPLES.map((s) => s.id);
  assert.equal(new Set(ids).size, ids.length, "two samples share an id");
  for (const id of ids) assert.equal(sampleById(id).id, id);
  assert.equal(sampleById("no-such-sample"), null);
});

test("every sample is described in both languages", () => {
  for (const s of SAMPLES) {
    for (const field of ["title", "blurb"]) {
      assert.ok(s[field].en?.trim(), `${s.id}: no English ${field}`);
      assert.ok(s[field].es?.trim(), `${s.id}: no Spanish ${field}`);
      assert.notEqual(s[field].en, s[field].es, `${s.id}: the ${field} was never translated`);
    }
  }
});

for (const s of SAMPLES) {
  test(`${s.id} parses without errors`, () => {
    const p = parseNft(s.nft);
    assert.deepEqual(p.errors, [], `unparsed lines in ${s.id}`);
  });

  test(`${s.id} re-emits every rule identically`, () => {
    const p = parseNft(s.nft);
    const rt = roundTrip(s.nft, p);
    assert.equal(rt.diffs.length, 0, `${s.id}\n` + JSON.stringify(rt.diffs, null, 2));
    assert.equal(rt.ok, rt.total);
  });

  /* The stronger claim, and the one the import dialog now makes: not "every
     rule came back" but "this is the same ruleset". */
  test(`${s.id} survives the whole-file check, not just its rules`, () => {
    const v = verify(s.nft);
    assert.deepEqual(v.diffs, [], `${s.id}\n` + JSON.stringify(v.diffs, null, 2));
  });

  test(`${s.id} is a ruleset worth showing`, () => {
    const p = parseNft(s.nft);
    assert.ok(p.chains.length >= 2, `${s.id}: one chain does not illustrate a path`);
    const rules = p.chains.reduce((a, c) => a + c.rules.length, 0);
    assert.ok(rules >= 4, `${s.id}: too thin to read as a scenario`);
    assert.ok(p.chains.some((c) => c.hook), `${s.id}: nothing is attached to a hook`);
  });

  /* What ships in a public repository must not describe a real network. */
  test(`${s.id} addresses nobody's real network`, () => {
    const addrs = [...s.nft.matchAll(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/g)].map((m) => m[1]);
    const documentation = (a) =>
      /^10\./.test(a) ||
      /^192\.168\./.test(a) ||
      /^172\.(1[6-9]|2\d|3[01])\./.test(a) ||
      /^192\.0\.2\./.test(a) ||
      /^198\.51\.100\./.test(a) ||
      /^203\.0\.113\./.test(a);
    for (const a of addrs)
      assert.ok(documentation(a), `${s.id}: ${a} is neither RFC 1918 nor RFC 5737 documentation space`);
  });

  /* A sample is read on the reader's own machine, and the first thing they are
   * likely to press is "Check with nft -c". So it has to be a ruleset nft will
   * accept anywhere, and three things quietly are not:
   *
   *   flowtable ft { devices = { "wan0" } }   No such file or directory
   *   chain c { type filter hook ingress device "wan0" ... }   the same
   *   synproxy s { mss 1460 }                 needs nft_synproxy loaded
   *
   * All three resolve against the running kernel rather than being parsed, so
   * they fail on any machine that does not have that exact interface or that
   * module — which is every machine except the one the sample describes. Found
   * by checking two new samples against nft 1.1.6 before shipping them, which
   * is also how `quota over 50 gbytes` was caught: nft takes bytes, kbytes and
   * mbytes and nothing larger.
   *
   * `iifname "wan0"` is fine and is what the samples use: it compares a string
   * and asks the kernel nothing. */
  test(`${s.id} loads on a machine that is not the one it describes`, () => {
    assert.doesNotMatch(s.nft, /hook\s+ingress\s+device/,
      `${s.id}: a netdev chain names a device that has to exist`);
    assert.doesNotMatch(s.nft, /devices\s*=\s*\{\s*"/,
      `${s.id}: a flowtable names a device that has to exist`);
    assert.doesNotMatch(s.nft, /^\s*synproxy\s+\w+\s*\{/m,
      `${s.id}: synproxy needs a kernel module the reader may not have`);
    assert.doesNotMatch(s.nft, /\b(over|until)\s+\d+\s*(gbytes|tbytes)\b/,
      `${s.id}: nft takes bytes, kbytes or mbytes — it refuses anything larger`);
  });
}
