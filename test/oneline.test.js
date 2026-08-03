/* A block written on one line is still a block.
 *
 * nft never prints one, so for a long time nothing here had to read one. But
 * this reads files people write as well as files nft prints, and `chain empty
 * { }` — or a whole base chain on a single line — is legal in both. Every one
 * of those fell through into the table's keep-as-text bucket: the text came
 * back out untouched, so the round-trip check reported 100% while a chain
 * carrying `hook input` and `policy drop` was not in the model at all.
 *
 * That is the one shape of bug this application cannot have. The number is the
 * whole of its argument for being trusted, and here it was compatible with
 * having silently dropped a base chain: absent from the canvas, unanalysed,
 * not walked by the simulator, and reported as missing by anything jumping to
 * it. A file that parses to nothing must never parse to 100%.
 *
 * The controls matter as much as the cases. A `{` in nftables is far more
 * often a value than a block — anonymous sets, verdict maps, `elements =` —
 * and reading one of those as a declaration would be the same class of
 * mistake pointing the other way. */
import test from "node:test";
import assert from "node:assert/strict";
import { parseNft, verify, logicalLines } from "../src/core/parse.js";

const wrap = (body) => `table inet t {\n${body}\n}`;
const chains = (p) => p.chains.map((c) => c.id);
const rulesOf = (p, id) => p.chains.find((c) => c.id === id)?.rules ?? [];

/* Parsed, and reproduced. Both halves, every time: the failure being guarded
   against is precisely a file that reproduces perfectly and models nothing. */
function read(src) {
  const p = parseNft(src);
  const v = verify(src);
  assert.equal(v.ok, v.total, `round-trip ${v.ok}/${v.total}: ${JSON.stringify(v.diffs)}`);
  return p;
}

test("an empty chain on one line is a chain", () => {
  const p = read(wrap("\tchain c { }"));
  assert.deepEqual(chains(p), ["c"]);
  assert.equal(rulesOf(p, "c").length, 0);
});

test("a base chain on one line keeps its hook, its priority and its policy", () => {
  const p = read(wrap("\tchain c { type filter hook input priority 0; policy drop; tcp dport 22 accept }"));
  const c = p.chains[0];
  assert.equal(c.id, "c");
  assert.equal(c.hook, "input");
  assert.equal(c.type, "filter");
  assert.equal(c.prio, 0);
  assert.equal(c.policy, "drop", "the policy is the difference between a firewall and a sieve");
  assert.equal(c.rules.length, 1);
  assert.equal(c.rules[0].verdict, "accept");
});

test("a regular chain on one line keeps its rules", () => {
  const p = read(wrap("\tchain c { tcp dport 22 accept ; tcp dport 80 drop }"));
  const rs = rulesOf(p, "c");
  assert.equal(rs.length, 2);
  assert.deepEqual(rs.map((r) => r.verdict), ["accept", "drop"]);
});

test("a set on one line is a set, with its type and its elements", () => {
  const p = read(wrap("\tset s { type ipv4_addr; elements = { 1.1.1.1, 2.2.2.2 } }"));
  assert.equal(p.sets.length, 1);
  assert.equal(p.sets[0].n, "s");
  assert.equal(p.sets[0].t, "ipv4_addr");
  assert.deepEqual(p.sets[0].el, ["1.1.1.1", "2.2.2.2"]);
});

test("a whole table on one line is a table", () => {
  const p = read("table inet t { chain c { tcp dport 22 accept } }");
  assert.deepEqual(chains(p), ["c"]);
  assert.equal(p.chains[0].table, "inet t");
  assert.equal(rulesOf(p, "c").length, 1);
});

/* The closing brace sharing a line with the last rule is the other half of the
   same gap: the rule used to be read as `tcp dport 22 accept }`, which carries
   no verdict this file recognises, and the chain never closed. */
test("a closing brace on the same line as the last rule closes the chain", () => {
  const p = read(wrap("\tchain c {\n\t\ttcp dport 22 accept }"));
  const rs = rulesOf(p, "c");
  assert.equal(rs.length, 1);
  assert.equal(rs[0].verdict, "accept");
  assert.equal(rs[0].expr, "tcp dport 22", "the brace is not part of the expression");
});

test("a chain opened with a rule already on the line keeps both", () => {
  const p = read(wrap("\tchain c { tcp dport 22 accept\n\t\ttcp dport 80 accept\n\t}"));
  assert.equal(rulesOf(p, "c").length, 2);
});

/* ── the other direction: a value brace is not a declaration ── */

test("an anonymous set in a rule stays in the rule", () => {
  const p = read(wrap('\tchain c {\n\t\tiifname { "eth0", "eth1" } accept\n\t}'));
  const rs = rulesOf(p, "c");
  assert.equal(rs.length, 1);
  assert.equal(rs[0].expr, 'iifname { "eth0", "eth1" }');
});

test("a verdict map in a rule stays in the rule", () => {
  const p = read(wrap("\tchain c {\n\t\tct state vmap { established : accept, invalid : drop }\n\t}"));
  assert.equal(rulesOf(p, "c").length, 1);
  assert.equal(p.chains[0].rules[0].expr, "ct state vmap { established : accept, invalid : drop }");
});

/* `counter` names an object and also opens a rule. Which one it is depends on
   what follows it, and getting that wrong would read a rule's anonymous set as
   the body of a named counter.

   No round-trip assertion here, and not because of the braces: `counter` is
   lifted out of the expression and written back in the one place this file
   writes it, so a rule that arrived with it in front comes back with it in the
   middle. nft normalises the same statement the same way. It is a move, not a
   loss, and it is older than anything on this page. */
test("a rule beginning with counter is not a named counter", () => {
  const p = parseNft(wrap("\tchain c {\n\t\tcounter ip saddr { 1.1.1.1, 2.2.2.2 } drop\n\t}"));
  assert.equal(p.objects.length, 0, "no object was declared here");
  assert.equal(rulesOf(p, "c").length, 1);
  assert.equal(p.chains[0].rules[0].ctr, true);
  assert.equal(p.chains[0].rules[0].expr, "ip saddr { 1.1.1.1, 2.2.2.2 }");
});

test("a named counter written the way nft prints it is still an object", () => {
  const p = read(wrap("\tcounter http_hits {\n\t\tpackets 0 bytes 0\n\t}"));
  assert.equal(p.objects.length, 1);
  assert.equal(p.objects[0].kind, "counter");
  assert.equal(p.objects[0].name, "http_hits");
});

/* Preserve by default is the governing rule, and it has to survive this. An
   object kind this list has never heard of must still keep its body. */
test("a block kind nobody modelled still keeps its body", () => {
  const p = read(wrap("\tmeter m {\n\t\tsomething odd\n\t}"));
  assert.equal(p.objects.length, 1);
  assert.equal(p.objects[0].kind, "meter");
  assert.deepEqual(p.objects[0].body, ["something odd"]);
});

/* The reason logicalLines exists at all: nft wraps a long element list, and
   reading it a line at a time is how a blocklist imported with nothing in it.
   The splitter runs before that and must not disturb it. */
test("a wrapped element list is still one logical line", () => {
  const p = read(wrap("\tset s {\n\t\ttype ipv4_addr\n\t\telements = { 1.1.1.1,\n\t\t\t2.2.2.2,\n\t\t\t3.3.3.3 }\n\t}"));
  assert.deepEqual(p.sets[0].el, ["1.1.1.1", "2.2.2.2", "3.3.3.3"]);
});

/* A chain header and its policy share a line in everything nft prints. The
   expansion splits statements apart, so it has to put that one back — or every
   ordinary ruleset would report the split as a change it did not make. */
test("splitting a one-line body puts the chain header back together", () => {
  const lines = logicalLines("table inet t { chain c { type filter hook input priority filter; policy drop; } }")
    .map((l) => l.text);
  assert.ok(lines.includes("type filter hook input priority filter; policy drop;"),
    `header was split apart: ${JSON.stringify(lines)}`);
});

test("an ordinary multi-line ruleset is untouched by the splitter", () => {
  const src = [
    "table inet t {",
    "\tchain c {",
    "\t\ttype filter hook input priority filter; policy drop;",
    '\t\tiifname "lo" accept',
    "\t}",
    "}",
  ].join("\n");
  assert.deepEqual(logicalLines(src).map((l) => l.text), [
    "table inet t {",
    "chain c {",
    "type filter hook input priority filter; policy drop;",
    'iifname "lo" accept',
    "}",
    "}",
  ]);
});

/* ── the backstop ──
   Everything above is the parser being taught to read these. This is what
   happens if some shape still gets past it: kept, so nothing is lost on
   export, but reported, so the round-trip number is never the only thing
   standing between a user and a chain that quietly is not there. */
test("a declaration that reaches the keep-as-text bucket is reported", () => {
  const p = parseNft("table inet t {\n\tchain\n}");
  assert.equal(p.errors.length, 1, "a bare `chain` is not a table attribute");
  assert.equal(p.tables[0].extra.includes("chain"), true, "and it is still kept");
});

test("a real table attribute is not reported", () => {
  const p = parseNft("table inet t {\n\tflags dormant\n\tcomment \"parked\"\n}");
  assert.equal(p.errors.length, 0);
});
