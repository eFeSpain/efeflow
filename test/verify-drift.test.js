/* One line that does not come back must cost one line.
 *
 * The check lined the two files up by index, so a source line that produced no
 * output shifted every line after it: each one then compared against its
 * neighbour and reported as changed. A set with an empty `elements = { }` —
 * one line, nothing else wrong — came out as 4/10 with six diffs, not one of
 * which named the line actually lost.
 *
 * That number is what the import dialog presents as evidence. Being wrong
 * about it in the alarming direction is not a small thing: it tells you to
 * distrust an import that was fine apart from one line. */
import test from "node:test";
import assert from "node:assert/strict";

import { verify, roundTrip, parseNft } from "../src/core/parse.js";

/* `elements = { }` is emitted for no elements, so nothing comes back for it */
const LOSES_A_LINE = `table inet filter {
	set blocked {
		type ipv4_addr
		elements = { }
	}

	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		iif lo accept
		tcp dport 22 accept
		tcp dport 443 accept
	}
}`;

const CLEAN = LOSES_A_LINE.replace("\t\telements = { }\n", "");

test("a clean ruleset still verifies whole", () => {
  const v = verify(CLEAN);
  assert.deepEqual(v.diffs, []);
  assert.equal(v.ok, v.total);
});

test("one line that does not come back costs one line", () => {
  const v = verify(LOSES_A_LINE);
  assert.equal(v.diffs.length, 1, JSON.stringify(v.diffs, null, 2));
  assert.equal(v.ok, v.total - 1, `${v.ok}/${v.total} — the rest of the file was fine`);
});

test("the diff names the line that went missing, not the ones that moved", () => {
  const [d] = verify(LOSES_A_LINE).diffs;
  assert.match(d.src, /elements/);
  assert.equal(d.out, "—", "nothing came back for it, and that is the whole story");
});

/* A stray brace closes the chain early, so the rules under it really are lost —
   several lines, honestly several diffs. What must not happen is the other
   thing: pairing each survivor with an unrelated neighbour and calling them all
   changed, which is what an index comparison did and how it hid which line
   actually went. */
test("lines genuinely lost are named, and nothing else is dragged in with them", () => {
  const v = verify(CLEAN.replace("\t\tiif lo accept", "\t\t}\n\t\tiif lo accept"));
  assert.ok(v.diffs.length > 0, "a truncated file is not a clean one");
  for (const d of v.diffs)
    assert.ok(d.src === "—" || d.out === "—",
      `paired two unrelated lines: ${JSON.stringify(d)}`);
});

/* A line that comes back different is a different problem from one that does
   not come back, and each has to be reported as itself: one diff naming both
   sides, not a loss followed by an arrival that nobody can connect to it.
 *
 * This used to be shown with `table filter {` against `table ip filter {`,
 * which no longer differs — writing the family nft assumes is nft's spelling,
 * not a line we failed to reproduce. That is the right answer and it made a
 * poor fixture, so the drift here is a port number: whatever else we learn to
 * normalise, 8443 is never going to be 443. */
test("a line that changes is reported as a change, not as a loss", () => {
  const rt = roundTrip(CLEAN.replace("tcp dport 443", "tcp dport 8443"), parseNft(CLEAN));
  assert.equal(rt.diffs.length, 1, JSON.stringify(rt.diffs));
  assert.equal(rt.diffs[0].src, "tcp dport 8443 accept");
  assert.equal(rt.diffs[0].out, "tcp dport 443 accept");
  assert.equal(rt.ok, rt.total - 1);
});

test("the rule-level check drifts no more than the whole-file one", () => {
  const src = CLEAN.replace("\t\tiif lo accept\n", "");
  const withExtra = CLEAN;
  const rt = roundTrip(withExtra, parseNft(src));
  assert.equal(rt.diffs.length, 1, JSON.stringify(rt.diffs, null, 2));
});

/* The percentage exists to survive the thing it is for: a ruleset that is
   mostly readable reading as mostly readable. */
test("a mostly readable file reads as mostly readable", () => {
  const many = ["table inet filter {", "\tset blocked {", "\t\ttype ipv4_addr",
                "\t\telements = { }", "\t}", "\tchain input {",
                "\t\ttype filter hook input priority filter; policy drop;"];
  for (let i = 0; i < 40; i++) many.push(`\t\ttcp dport ${1000 + i} accept`);
  many.push("\t}", "}");

  const v = verify(many.join("\n"));
  const pct = Math.round((v.ok / v.total) * 100);
  assert.ok(pct >= 97, `reported ${pct}% for one lost line in forty-odd`);
});
