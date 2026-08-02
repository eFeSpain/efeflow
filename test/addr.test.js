import test from "node:test";
import assert from "node:assert/strict";

import { family, v4, v6, inCidr, looksLikeAddr } from "../src/core/addr.js";

test("a colon is what tells the two families apart", () => {
  assert.equal(family("10.0.0.1"), 4);
  assert.equal(family("2001:db8::1"), 6);
  assert.equal(family("::1"), 6);
});

test("IPv4 parses, and refuses what is not one", () => {
  assert.equal(v4("0.0.0.0"), 0n);
  assert.equal(v4("255.255.255.255"), 0xffffffffn);
  assert.equal(v4("10.0.0.1"), 0x0a000001n);
  for (const bad of ["10.0.0.256", "10.0.0", "10.0.0.1.2", "", "hello"])
    assert.equal(v4(bad), null, bad);
});

/* The compressed forms are the ones people write, and `nft list ruleset`
   prints them compressed too. */
test("IPv6 parses in every form it is written in", () => {
  assert.equal(v6("::"), 0n);
  assert.equal(v6("::1"), 1n);
  assert.equal(v6("2001:db8::1"), v6("2001:0db8:0000:0000:0000:0000:0000:0001"));
  assert.equal(v6("fe80::1%0"), null, "a zone index is not part of the address");
  assert.equal(v6("[2001:db8::1]"), v6("2001:db8::1"), "brackets are punctuation");
  assert.equal(v6("::ffff:192.0.2.1"), v6("::ffff:c000:201"), "an embedded IPv4 tail");
  for (const bad of ["2001:db8::1::2", "gggg::1", "10.0.0.1", ""])
    assert.equal(v6(bad), null, bad);
});

test("a prefix contains what is inside it", () => {
  assert.ok(inCidr("10.10.0.5", "10.10.0.0/24"));
  assert.ok(!inCidr("10.11.0.5", "10.10.0.0/24"));
  assert.ok(inCidr("1.2.3.4", "0.0.0.0/0"), "the whole of v4");
  assert.ok(inCidr("10.0.0.1", "10.0.0.1/32"));

  assert.ok(inCidr("2001:db8:1::5", "2001:db8::/32"));
  assert.ok(!inCidr("2001:db9::5", "2001:db8::/32"));
  assert.ok(inCidr("fe80::1", "::/0"), "the whole of v6");
  assert.ok(inCidr("2001:db8::1", "2001:db8::1/128"));
});

/* An inet table spells out `ip saddr` and `ip6 saddr` precisely because the
   two do not overlap. A v4 address is not inside ::/0. */
test("the families never contain each other", () => {
  assert.ok(!inCidr("10.0.0.1", "::/0"));
  assert.ok(!inCidr("2001:db8::1", "0.0.0.0/0"));
  assert.ok(!inCidr("2001:db8::1", "10.0.0.0/8"));
});

test("an address with no prefix is an equality, however it is spelled", () => {
  assert.ok(inCidr("2001:0db8:0000::0001", "2001:db8::1"));
  assert.ok(inCidr("10.0.0.1", "10.0.0.1"));
  assert.ok(!inCidr("10.0.0.2", "10.0.0.1"));
  assert.ok(inCidr("lo", "lo"), "anything else falls back to being the same text");
});

test("nonsense is not silently inside everything", () => {
  assert.ok(!inCidr("10.0.0.1", "10.0.0.0/33"));
  assert.ok(!inCidr("not-an-address", "10.0.0.0/8"));
});

test("what is an address is answerable, because set elements are a mixture", () => {
  assert.ok(looksLikeAddr("10.0.0.0/8"));
  assert.ok(looksLikeAddr("2001:db8::1"));
  assert.ok(!looksLikeAddr("443"));
  assert.ok(!looksLikeAddr("wan0"));
});
