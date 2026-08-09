/* Rules that nft will refuse to load.
 *
 * The analyser answers "is this ruleset sensible". Nothing answered the
 * question underneath it — "is this ruleset loadable" — and that one only got
 * asked when somebody ran nft -c, which needs a Linux host to hand. These are
 * the mistakes that make `nft -f` exit non-zero, all of them findable from the
 * text alone. */
import test from "node:test";
import assert from "node:assert/strict";

import { lintRule } from "../src/core/lint.js";

const codes = (line, ctx) => lintRule(line, ctx).map((f) => f.code);
const clean = (line, ctx) => assert.deepEqual(lintRule(line, ctx), [], line);

test("a rule that loads reports nothing", () => {
  for (const line of [
    "ct state established,related counter accept",
    'iifname "wan0" tcp dport { 80, 443 } accept',
    'ip saddr 10.0.0.0/8 log prefix "lan " level info limit rate 5/second burst 10 packets drop',
    "tcp dport 22 goto ssh_hardening",
    "udp dport 53 redirect",
    "meta l4proto { tcp, udp } flow add @ft",
    "tcp flags & (syn|ack) == syn accept",
    "counter",
  ])
    clean(line, { chains: ["ssh_hardening"], sets: ["ft"] });
});

/* nft parses to the end of the line; an unterminated string swallows it. */
test("an unbalanced quote or brace is caught", () => {
  assert.deepEqual(codes('log prefix "ssh drop'), ["unbalanced"]);
  assert.deepEqual(codes("tcp dport { 80, 443 accept"), ["unbalanced"]);
  assert.deepEqual(codes("tcp flags & (syn|ack == syn accept"), ["unbalanced"]);
});

/* Everything after `log` belongs to it. Deleting the keyword and leaving the
   arguments is what the properties panel used to do. */
test("log arguments without the log keyword are caught", () => {
  assert.deepEqual(codes('ip saddr 1.2.3.4 prefix "drop " accept'), ["orphan-log"]);
  assert.deepEqual(codes("ip saddr 1.2.3.4 level warn accept"), ["orphan-log"]);
  clean('ip saddr 1.2.3.4 log prefix "drop " accept');
});

test("a burst with no rate is caught", () => {
  assert.deepEqual(codes("burst 10 packets accept"), ["orphan-burst"]);
  clean("limit rate 5/second burst 10 packets accept");
});

/* nftables has no protocol-less port match: `dport 22` on its own is a syntax
   error, and it is the single easiest rule to write by hand and get wrong. */
test("a port with no transport is caught", () => {
  assert.deepEqual(codes("dport 22 accept"), ["port-no-proto"]);
  assert.deepEqual(codes("ip saddr 10.0.0.1 sport 1024 drop"), ["port-no-proto"]);
  clean("tcp dport 22 accept");
  clean("meta l4proto tcp th dport 22 accept");
});

test("a verdict that needs a target and has none is caught", () => {
  assert.deepEqual(codes("tcp dport 22 jump"), ["no-target"]);
  assert.deepEqual(codes("tcp dport 22 goto"), ["no-target"]);
  assert.deepEqual(codes("tcp dport 80 dnat to"), ["no-target"]);
});

/* A jump to a chain that is not in this table, or a lookup in a set that does
   not exist, loads on nobody's kernel. */
test("a target that is not in the ruleset is caught", () => {
  assert.deepEqual(codes("tcp dport 22 jump nowhere", { chains: ["ssh"] }), ["unknown-chain"]);
  assert.deepEqual(codes("ip saddr @nobody drop", { sets: ["admins"] }), ["unknown-set"]);
  clean("tcp dport 22 jump ssh", { chains: ["ssh"] });
  clean("ip saddr @admins drop", { sets: ["admins"] });
});

/* A verdict map is how anybody writes several jumps at once, and it was the
   one shape this could not read. `\S+` took the punctuation with the name, so
   a chain that was right there came back as `No chain called zone_lan,` — and
   without /g only the first target was ever looked at, so the other two could
   name nothing at all and pass. Found by writing a router sample that
   dispatches three zones through one map. */
test("every jump on the line is checked, and only the name of it", () => {
  const zones = { chains: ["zone_lan", "zone_dmz", "zone_guest"] };
  clean('iifname vmap { "lan0" : jump zone_lan, "dmz0" : jump zone_dmz }', zones);

  assert.deepEqual(
    codes('iifname vmap { "lan0" : jump zone_lan, "x" : jump nowhere }', zones),
    ["unknown-chain"], "a real chain listed first hid a missing one after it");

  assert.deepEqual(
    codes('iifname vmap { "a" : jump ghost1, "b" : jump ghost2 }', zones),
    ["unknown-chain", "unknown-chain"], "only the first target was ever reported");

  /* and it stays quiet about the same name twice */
  assert.deepEqual(
    codes('iifname vmap { "a" : jump ghost1, "b" : jump ghost1 }', zones),
    ["unknown-chain"]);
});

/* `@` does not only mean a set: a flowtable is reached with `flow add @ft`.
   Checked against the sets alone, every offload rule in every router ruleset
   came back naming a set that does not exist. */
test("a flowtable is a thing an @ can name", () => {
  const ctx = { sets: ["admins"], flowtables: ["ft"], objects: [] };
  clean("ip protocol { tcp, udp } flow add @ft", ctx);
  assert.deepEqual(codes("flow add @nope", ctx), ["unknown-set"]);
});

/* The objects named in a statement rather than with an @ were not checked at
   all, which is the same gap seen from the other side. */
test("an object named in a statement has to exist too", () => {
  const objects = [
    { kind: "counter", name: "hits" },
    { kind: "ct helper", name: "ftp-standard" },
  ];
  const ctx = { sets: [], objects };
  clean('tcp dport 80 counter name "hits" accept', ctx);
  clean('tcp dport 21 ct helper set "ftp-standard" accept', ctx);
  assert.deepEqual(codes('tcp dport 80 counter name "nope" accept', ctx), ["unknown-object"]);
  assert.deepEqual(codes('tcp dport 21 ct helper set "nope" accept', ctx), ["unknown-object"]);
});

/* Without the ruleset to check against there is nothing to be sure of, so an
   unresolvable name is not reported rather than reported wrongly. */
test("names are only checked when there is something to check them against", () => {
  clean("tcp dport 22 jump anywhere");
  clean("ip saddr @anything drop");
});

test("a verdict in the middle of a rule is caught", () => {
  assert.deepEqual(codes("tcp dport 22 accept ip saddr 10.0.0.1"), ["verdict-not-last"]);
  clean("tcp dport 22 ip saddr 10.0.0.1 accept");
});

/* Two verdicts carry an argument, and a verdict map spells verdicts inside
   braces where they are values rather than the end of the rule. */
test("a verdict is allowed what that verdict takes", () => {
  clean("ct state invalid reject with icmpx admin-prohibited");
  clean("tcp dport 25 reject with tcp reset");
  clean('oifname "wan0" masquerade to :1024-65535');
  clean('oifname "wan0" masquerade persistent');
  clean("tcp dport vmap { 22 : accept, 80 : drop }");
  clean("ip saddr vmap { 10.0.0.0/8 : accept, 0.0.0.0/0 : drop } comment");
});

test("a rule reports every problem it has, not only the first", () => {
  const found = codes('dport 22 prefix "x " jump');
  assert.ok(found.includes("port-no-proto"));
  assert.ok(found.includes("orphan-log"));
  assert.ok(found.includes("no-target"));
});

test("every finding says what is wrong in both languages", () => {
  for (const f of lintRule('dport 22 prefix "x " jump')) {
    assert.ok(f.title[0]?.trim(), `${f.code}: no English title`);
    assert.ok(f.title[1]?.trim(), `${f.code}: no Spanish title`);
    assert.notEqual(f.title[0], f.title[1], `${f.code}: the title was never translated`);
  }
});
