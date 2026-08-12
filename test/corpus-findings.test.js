/* What 268 real rulesets said about this parser.
 *
 * Every fixture in this repository was written beside the code it tests, which
 * is a corpus with a bias the size of a house in it: it holds the syntax
 * somebody thought of, and that is exactly the syntax that works. So
 * `scripts/corpus.mjs` fetches what people committed to public repositories,
 * keeps only the files nft itself accepts — two of every four turned out to be
 * templates full of `$VARIABLES` and Jinja — and asks whether we can read them
 * and write them back.
 *
 * These are the findings that mattered, each reduced to the smallest case that
 * shows it. The corpus itself is not committed: it is other people's code, and
 * a test that needs a download is a test that fails on a train.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { parseNft, verify } from "../src/core/parse.js";
import { generate } from "../src/core/generate.js";

const chain = (header, body = "\t\tct state established,related accept") =>
  `table inet filter {\n\tchain input {\n\t\t${header}\n${body}\n\t}\n}`;

/* ── the one that mattered ───────────────────────────────────────────────
 *
 * nft prints a chain header with a semicolon and accepts one without. A
 * hand-written config very often has none, and it was one of the commonest
 * shapes in the corpus. Without it the line matched no branch at all: `hook`
 * stayed null and `type` fell back to "regular", so a base chain quietly
 * became an ordinary one.
 *
 * That is not a formatting loss. A chain with no hook is attached to nothing:
 * netfilter never calls it, the simulator never walks it, the canvas never
 * puts it on the packet's path — and the ruleset that comes back out has an
 * input chain that is not an input chain, which nft will load without a word
 * of complaint. The policy went with it, so `policy drop` came back as the
 * `accept` nft applies when nothing says otherwise.
 */
test("a chain header is a chain header without its semicolon", () => {
  for (const header of [
    "type filter hook input priority filter;",
    "type filter hook input priority filter",
    "type filter hook input priority 0",
    "type filter hook input priority filter + 10",
  ]) {
    const ch = parseNft(chain(header)).chains[0];
    assert.equal(ch.hook, "input", `${header}: the chain is not attached to a hook`);
    assert.equal(ch.type, "filter", `${header}: it stopped being a base chain`);
  }
});

test("and a policy on its own line reaches the ruleset that comes out", () => {
  const m = parseNft(chain("type filter hook input priority filter\n\t\tpolicy drop"));
  assert.equal(m.chains[0].policy, "drop", "the policy was read");
  const header = generate(m).find((l) => /hook input/.test(l));
  assert.match(header, /policy drop/,
    "a firewall that drops by default came back out accepting by default");
});

test("a netdev chain keeps its device without one too", () => {
  const ch = parseNft(chain('type filter hook ingress device "eth0" priority -500')).chains[0];
  assert.equal(ch.hook, "ingress");
  assert.equal(ch.dev, 'device "eth0"');
});

/* ── and what the round-trip was calling a loss ──────────────────────────
 *
 * The check compares what a file says against what we would write. nft prints
 * `type … priority …; policy …;` on one line; people write two, and leave the
 * policy out because accept is the default. Both load and both mean the same
 * thing, and this was counted as two losses per chain — then a third and a
 * fourth as the line-by-line comparison slipped a row and reported the
 * neighbours. Across the corpus it accounted for roughly four hundred of five
 * hundred and forty-six reported losses: files that had been understood
 * perfectly, telling their authors they had not been.
 */
test("a chain header split across lines is not a line we lost", () => {
  const split = verify(chain("type filter hook input priority filter\n\t\tpolicy drop"));
  assert.deepEqual(split.diffs, [], JSON.stringify(split.diffs));

  const bare = verify(chain("type filter hook input priority filter"));
  assert.deepEqual(bare.diffs, [], "a header with no policy at all is nft's default, not a loss");
});

test("but a policy we got wrong is still a difference", () => {
  /* the fold may not become a way of not noticing */
  const m = parseNft(chain("type filter hook input priority filter\n\t\tpolicy drop"));
  m.chains[0].policy = "accept";
  const out = generate(m).find((l) => /hook input/.test(l));
  assert.match(out, /policy accept/);
  assert.doesNotMatch(out, /policy drop/,
    "the check must still see a policy that changed under it");
});

/* ── a rule continued onto the next line ─────────────────────────────────
 *
 * A trailing backslash continues a line, and nft reads the pair as one rule.
 * Seventy-one of the five hundred and thirty-four rulesets fetched wrote at
 * least one that way — four hundred and ten lines between them — usually to
 * put the comment on a line of its own:
 *
 *     iifname lo accept \
 *     comment "Accept any localhost traffic"
 *
 * Read as two, the rule lost its comment and the comment became a line that
 * parsed as nothing, and everything after it in the chain shifted. It was why
 * the worst file in the corpus came back at 71%.
 */
test("a backslash at the end of a line continues it", () => {
  const text = [
    "table inet filter {",
    "\tchain input {",
    "\t\ttype filter hook input priority 0; policy drop;",
    "\t\tiifname lo accept \\",
    '\t\tcomment "Accept any localhost traffic"',
    "\t\ttcp dport { 80, 443 } \\",
    "\t\t\tcounter accept",
    "\t}",
    "}",
  ].join("\n");

  const m = parseNft(text);
  const rules = m.chains[0].rules;
  assert.equal(rules.length, 2, "the continuations were read as rules of their own");
  assert.equal(rules[0].expr, "iifname lo");
  assert.equal(rules[0].verdict, "accept");
  assert.equal(rules[0].cmt, "Accept any localhost traffic",
    "the comment was on the next line, and belongs to the rule above it");
  assert.equal(rules[1].expr, "tcp dport { 80, 443 }");
  assert.equal(rules[1].ctr, true, "the counter was on the continued half");
  assert.deepEqual(m.errors, [], "a continuation line parses as nothing on its own");
});

/* ── the four the kernel found ────────────────────────────────────────────
 *
 * Comparing text can only say a file came back written differently. Loading
 * both into an empty netfilter instance and listing them back asks whether it
 * came back *meaning* differently, which is the question. `npm run corpus
 * kernel` does that; these are what it found, and all four produced either a
 * file nft refuses or a firewall that is not the one in the file.
 */

/* A braced list wrapped across lines was read as a block, so the rule's entire
   match went with it and the rule became a bare `accept` — which accepts
   everything. The braces then came back out at table level, where nft refuses
   them. A firewall opened silently, in a file that would not load. */
test("a value list wrapped across lines stays part of its rule", () => {
  const m = parseNft([
    "table inet filter {",
    "\tchain input {",
    "\t\ttype filter hook input priority filter; policy drop;",
    "\t\ticmp type {",
    "\t\t\techo-request,",
    "\t\t\tdestination-unreachable",
    "\t\t} accept",
    "\t}",
    "}",
  ].join("\n"));

  assert.equal(m.chains.length, 1, "the braces were read as a chain of their own");
  const r = m.chains[0].rules;
  assert.equal(r.length, 1);
  assert.match(r[0].expr, /icmp type \{ echo-request, destination-unreachable \}/,
    "the rule lost its match and became a bare verdict");
  assert.equal(r[0].verdict, "accept");
  assert.deepEqual(parseNft(generate(m).join("\n")).chains[0].rules[0].expr, r[0].expr,
    "and it survives being written out and read again");
});

/* `flush table inet x` fails on a table that does not exist, and takes the
   whole file with it. The idiom is to declare it empty first; the declaration
   lived above the flush and everything in the prelude is emitted before any
   table, so the flush was left with nothing to flush. */
test("a flush of a table is preceded by something that creates it", () => {
  const src = [
    "table inet x {",
    "}",
    "flush table inet x",
    "table inet x {",
    "\tchain input {",
    "\t\ttype filter hook input priority filter; policy accept;",
    "\t\ttcp dport 22 accept",
    "\t}",
    "}",
  ].join("\n");
  const out = generate(parseNft(src)).join("\n");
  const flush = out.indexOf("flush table inet x");
  const decl = out.indexOf("table inet x\n");
  assert.ok(flush > 0, "somebody's flush was dropped");
  assert.ok(decl >= 0 && decl < flush,
    "nothing creates the table the flush is about, so nft refuses the file");
});

/* A chain declared twice is one chain, which is how a long ruleset gets split
   across blocks or files. Read as two, we emitted the name twice — the second
   time with a hook — and nft refused it. */
test("a chain declared twice is one chain", () => {
  const m = parseNft([
    "table inet filter {",
    "\tchain input {",
    "\t\ttcp dport 22 accept",
    "\t}",
    "}",
    "table inet filter {",
    "\tchain input {",
    "\t\ttype filter hook input priority filter; policy drop;",
    "\t\ttcp dport 443 accept",
    "\t}",
    "}",
  ].join("\n"));

  const inputs = m.chains.filter((c) => c.id === "input" && c.table === "inet filter");
  assert.equal(inputs.length, 1, "two chains of one name is a file nft will not load");
  assert.equal(inputs[0].hook, "input", "the header from the second block reached it");
  assert.equal(inputs[0].policy, "drop");
  assert.deepEqual(inputs[0].rules.map((r) => r.expr), ["tcp dport 22", "tcp dport 443"],
    "and both blocks' rules are there, in the order the file gives them");
});

/* `flush ruleset` in the middle of a file is not decoration: everything above
   it is gone by the time the kernel reaches it. One ruleset in the corpus was
   two firewalls pasted together, and reading them as a union produced five
   rules the kernel would never have loaded. Drawing a firewall nobody is
   running is the worst thing this application can do. */
test("a flush in the middle of a file discards what came before it", () => {
  const m = parseNft([
    "table inet old {",
    "\tchain input {",
    "\t\ttype filter hook input priority filter; policy accept;",
    "\t\ttcp dport 23 accept",
    "\t}",
    "}",
    "",
    "flush ruleset",
    "",
    "table inet new {",
    "\tchain input {",
    "\t\ttype filter hook input priority filter; policy drop;",
    "\t\ttcp dport 22 accept",
    "\t}",
    "}",
  ].join("\n"));

  assert.deepEqual(m.chains.map((c) => c.table), ["inet new"],
    "the table above the flush is not running on that machine");
  assert.equal(m.chains[0].policy, "drop");
});

/* …but it does not reach what was never in the kernel. A `define` is nft's own
   textual substitution and an `include` is a file it reads; neither is state a
   flush can clear, and the rules below still need them. */
test("and it does not discard the defines above it", () => {
  const m = parseNft([
    'define wan = "eth0"',
    'include "/etc/nftables.d/*.nft"',
    "flush ruleset",
    "table inet filter {",
    "\tchain input {",
    "\t\ttype filter hook input priority filter; policy drop;",
    "\t\tiifname $wan accept",
    "\t}",
    "}",
  ].join("\n"));
  assert.deepEqual(m.prelude, ['define wan = "eth0"', 'include "/etc/nftables.d/*.nft"']);
});
