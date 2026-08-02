import test from "node:test";
import assert from "node:assert/strict";

import { parseNft, roundTrip } from "../src/core/parse.js";
import { SAMPLE_NFT } from "../src/core/samples.js";

/* Anything the product offers to load has to clear the same bar it holds the
   user's own ruleset to. A sample that lost a rule on the way in would make
   the honest round-trip percentage a liar on the one ruleset every new user
   sees first. */

test("the sample parses without errors", () => {
  const p = parseNft(SAMPLE_NFT);
  assert.deepEqual(p.errors, [], "unparsed lines in the shipped sample");
});

test("the sample re-emits every rule identically", () => {
  const p = parseNft(SAMPLE_NFT);
  const rt = roundTrip(SAMPLE_NFT, p);
  assert.equal(rt.diffs.length, 0, JSON.stringify(rt.diffs, null, 2));
  assert.equal(rt.ok, rt.total);
});

/* What ships in a public repository must not describe a real network. */
test("the sample addresses nobody's real network", () => {
  const addrs = [...SAMPLE_NFT.matchAll(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/g)].map((m) => m[1]);
  assert.ok(addrs.length, "there should be addresses to check");
  const documentation = (a) =>
    /^10\./.test(a) ||
    /^192\.168\./.test(a) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(a) ||
    /^192\.0\.2\./.test(a) ||
    /^198\.51\.100\./.test(a) ||
    /^203\.0\.113\./.test(a);
  for (const a of addrs)
    assert.ok(documentation(a), `${a} is neither RFC 1918 nor RFC 5737 documentation space`);
});
