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
