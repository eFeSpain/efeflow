/* Every verdict nftables has, through the parser and back out again.
 *
 * The round-trip proof compares a rule's source line to the line we re-emit,
 * so a verdict the model cannot spell is not a cosmetic problem: it is a
 * ruleset that does not load. `goto` was exactly that — parsed with its target
 * and emitted without it, which is a syntax error wherever it lands. */
import test from "node:test";
import assert from "node:assert/strict";

import { ruleLine, VNAME, VCOLOR } from "../src/core/model.js";
import { parseRule, normalise } from "../src/core/parse.js";

const trip = (line) => {
  const r = parseRule(line);
  assert.ok(r, `should parse: ${line}`);
  return normalise(ruleLine(r) + (r.cmt ? ` comment "${r.cmt}"` : ""));
};

test("every verdict form survives being written back out", () => {
  const lines = [
    "tcp dport 22 accept",
    "ct state invalid drop",
    "ct state invalid reject",
    "tcp dport 25 reject with tcp reset",
    "ip protocol icmp reject with icmp type admin-prohibited",
    "ip saddr 10.0.0.0/8 jump lan",
    "tcp dport 22 goto ssh_hardening",
    'iifname "wan0" counter goto zone_wan',
    "return",
    "counter",
    "ip saddr 1.2.3.4 dnat to 10.0.0.5",
    "tcp dport 8443 dnat to 10.0.0.5:443",
    'oifname "wan0" snat to 198.51.100.1',
    'oifname "wan0" masquerade',
    "tcp dport 80 redirect to :8080",
    "udp dport 53 redirect",
    'log prefix "audit " level info',
  ];
  for (const line of lines) assert.equal(trip(line), normalise(line), line);
});

/* `redirect` is a DNAT to the machine the rule runs on, and it is the only way
   to say that. Rewriting it as `dnat to :8080` changes what the rule does and
   emits something nft rejects — the destination is not optional in a dnat. */
test("redirect is a verdict of its own, not a dnat in disguise", () => {
  const r = parseRule("tcp dport 80 redirect to :8080");
  assert.equal(r.verdict, "redirect");
  assert.equal(r.to, ":8080");

  const bare = parseRule("udp dport 53 redirect");
  assert.equal(bare.verdict, "redirect");
  assert.equal(ruleLine(bare), "udp dport 53 redirect");
});

test("goto keeps the chain it goes to", () => {
  const r = parseRule("tcp dport 22 goto ssh_hardening");
  assert.equal(r.verdict, "goto");
  assert.equal(r.to, "ssh_hardening");
  assert.equal(ruleLine(r), "tcp dport 22 goto ssh_hardening");
});

/* The canvas paints a pill per rule from these two tables. A verdict missing
   from them renders the string "undefined" in a pill with no colour, which is
   what every falls-through rule looked like — and those are common: any rule
   that only logs or only counts has no terminal verdict at all. */
test("every verdict the parser can produce has a name and a colour", () => {
  const produced = [
    "accept", "drop", "reject", "jump", "goto",
    "dnat", "snat", "redirect", "return", "continue", "log",
  ];
  for (const v of produced) {
    assert.ok(VNAME[v], `VNAME is missing ${v}`);
    assert.ok(VCOLOR[v], `VCOLOR is missing ${v}`);
  }
});
