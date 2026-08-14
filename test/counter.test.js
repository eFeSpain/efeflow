/* Where the counter sits, and why it is not a matter of taste.
 *
 * nftables evaluates a rule left to right and the first expression that does
 * not match abandons it. So `counter ip saddr 10.0.0.1 drop` counts every
 * packet that reaches the rule, and `ip saddr 10.0.0.1 counter drop` counts
 * only the ones from that address. Same verdict, different measurement, and
 * the second is the one people write by accident.
 *
 * The parser lifted `counter` out of the expression and generate.js wrote it
 * back in one fixed place — just before the verdict — so a rule that arrived
 * with the counter in front came back out with it in the middle. Nobody's
 * firewall changed what it blocked; what changed was what it was counting,
 * which on this tool matters twice over, because the cold-rule finding reads
 * those counters back and says which rules have matched nothing.
 *
 * It was never invisible: the round-trip check reported it as a line that came
 * back different, on every ruleset carrying one. That was the check doing
 * exactly its job while being read as noise. */
import test from "node:test";
import assert from "node:assert/strict";
import { parseRule, normalise, verify } from "../src/core/parse.js";
import { ruleLine, cmtEsc } from "../src/core/model.js";

/** parse it, write it back, and insist on getting the same rule. */
const trip = (src) => ruleLine(parseRule(src));

/* A comment is held as plain text and turned into a loadable comment body on the
   way out. Measured on nft 1.1.3: a backslash is doubled and survives, but a
   double quote cannot live in an nft comment at all (`\"` is a syntax error, not
   an escape), so it is dropped rather than emitted as nft the preflight rejects. */
test("a backslash comment round-trips; a quote is dropped, not escaped", () => {
  for (const src of [
    'ip saddr 1.1.1.1 drop comment "path C:\\\\tmp"',
    'accept comment "plain"',
  ]) {
    const r = parseRule(src);
    assert.equal(ruleLine(r) + (r.cmt ? ` comment "${cmtEsc(r.cmt)}"` : ""), src, src);
  }
  assert.equal(cmtEsc('he said "hi"'), "he said hi", "nft cannot hold a quote in a comment");
  assert.equal(cmtEsc("path C:\\tmp"), "path C:\\\\tmp", "a backslash is doubled");
  /* the parser still reads what it is handed, unescaping a backslash-quote */
  assert.equal(parseRule('accept comment "a\\"b"').cmt, 'a"b');
});

/* ── the counter goes back where it came from ───────────────────────────── */

const SAME = [
  "counter ip saddr 1.1.1.1 drop",
  "counter tcp dport 22 accept",
  /* the word `counter` inside a log prefix is not a counter statement */
  "log prefix \"packet counter: \" ip saddr 1.1.1.1 drop",
  "ip saddr 1.1.1.1 log prefix \"drop counter\" drop",
  "counter ip saddr 10.0.0.0/8 tcp dport { 80, 443 } accept",
  "counter log prefix \"in: \" ip saddr 1.1.1.1 drop",
  /* the ordinary shape, and the one nft prints: nothing to remember */
  "tcp dport 22 counter accept",
  "ip saddr 1.1.1.1 counter drop",
  "iifname \"lo\" counter accept",
  /* a rule that is nothing but a counter */
  "counter accept",
  "counter drop",
  "counter",
  /* and one in the middle, which is neither of the two easy cases */
  "tcp dport 22 counter ip saddr 1.1.1.1 drop",
  "ct state new counter ip saddr 10.0.0.0/8 tcp dport 22 accept",
];

for (const src of SAME)
  test(`re-emits as itself: ${src}`, () => assert.equal(trip(src), src));

/* ── what it records, and when it bothers ───────────────────────────────── */

test("a counter in front of the matches is remembered", () => {
  const r = parseRule("counter ip saddr 1.1.1.1 drop");
  assert.equal(r.ctr, true);
  assert.equal(r.ctrAt, 0);
  assert.equal(r.expr, "ip saddr 1.1.1.1", "the counter is not part of the match");
});

test("a counter in the middle is remembered by the word it went in front of", () => {
  const r = parseRule("tcp dport 22 counter ip saddr 1.1.1.1 drop");
  assert.equal(r.ctrAt, 3, "after `tcp dport 22`");
});

/* A field nobody needs is a field in every saved project and every undo
   snapshot. The position is only worth recording when it is not the one
   ruleLine() writes by default — which is where nft prints it, and where
   every rule built in the editor puts it. */
test("the ordinary position is not recorded at all", () => {
  for (const src of ["tcp dport 22 counter accept", "counter accept", "counter drop", "counter"])
    assert.equal(parseRule(src).ctrAt, undefined, src);
});

test("a rule with no counter records nothing either", () => {
  const r = parseRule("tcp dport 22 accept");
  assert.equal(r.ctr, false);
  assert.equal(r.ctrAt, undefined);
});

/* ── the statistics are not part of the rule ────────────────────────────── */

/* `counter packets 12 bytes 900` is the statement plus what it has counted so
   far. ruleLine() writes the statement; the round-trip check takes the figures
   off the source side before comparing, which is what makes the two agree. */
test("the packet and byte figures come off, and the placement still holds", () => {
  for (const src of ["counter packets 12 bytes 900 ip daddr 8.8.8.8 accept",
                     "ip saddr 1.1.1.1 counter packets 5 bytes 40 drop"]) {
    const r = parseRule(src);
    assert.equal(normalise(trip(src)), normalise(src), src);
    assert.ok(r.pkts > 0, "the figures were read");
  }
  assert.equal(trip("counter packets 12 bytes 900 ip daddr 8.8.8.8 accept"),
    "counter ip daddr 8.8.8.8 accept", "and the statement is written bare");
});

/* ── it survives the whole file, which is the claim that matters ─────────── */

test("a ruleset mixing every placement round-trips whole", () => {
  const src = [
    "table inet t {",
    "\tchain c {",
    "\t\ttype filter hook input priority filter; policy drop;",
    "\t\tcounter ip saddr 1.1.1.1 drop",
    "\t\tip saddr 2.2.2.2 counter drop",
    "\t\ttcp dport 22 counter accept",
    "\t\tcounter log prefix \"in: \" tcp dport 80 accept",
    "\t\ttcp dport 443 counter ip saddr 10.0.0.0/8 accept",
    "\t\tcounter",
    "\t}",
    "}",
  ].join("\n");
  const v = verify(src);
  assert.equal(v.ok, v.total, `round-trip ${v.ok}/${v.total}: ${JSON.stringify(v.diffs)}`);
});

/* ── and does not break when the rule is edited underneath it ───────────── */

/* The position is a word index, so an expression that has since got shorter
   can leave it pointing past the end. Falling back to the ordinary placement
   is right: an approximate answer about where a counter goes is worth having,
   an exception in the middle of drawing the canvas is not. */
test("an expression edited shorter falls back rather than throwing", () => {
  const r = parseRule("tcp dport 22 counter ip saddr 1.1.1.1 drop");
  r.expr = "tcp";
  assert.equal(ruleLine(r), "tcp counter drop");
});

test("an expression edited longer keeps the counter where it was", () => {
  const r = parseRule("counter tcp dport 22 accept");
  r.expr = "tcp dport 22 ct state new";
  assert.equal(ruleLine(r), "counter tcp dport 22 ct state new accept");
});

/* Splitting on the separators rather than through them, so a rule carrying a
   quoted string keeps its own spacing instead of being tidied into a
   different rule. */
test("odd spacing inside a quoted string is left alone", () => {
  const r = parseRule("counter log prefix \"two  spaces\" accept");
  assert.equal(ruleLine(r), "counter log prefix \"two  spaces\" accept");
});
