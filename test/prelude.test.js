/* What a ruleset says before its first table.
 *
 * `define wan = "eth0"` and `include "/etc/nftables.d/*.nft"` were dropped —
 * and the rules using `$wan` were not, so importing a real script and
 * exporting it gave you a file referencing a variable nothing defined. The
 * round-trip check counted the lines as lost, which is honest, and said
 * nothing about the export no longer loading. */
import test from "node:test";
import assert from "node:assert/strict";

import { parseNft, verify } from "../src/core/parse.js";
import { generate } from "../src/core/generate.js";

const model = (p) => ({ chains: p.chains, sets: p.sets, objects: p.objects,
                        tables: p.tables, prelude: p.prelude, preludeAt: p.preludeAt });

const SRC = `define wan = "eth0"
define admins = { 10.0.0.1, 10.0.0.2 }
include "/etc/nftables.d/*.nft"

flush ruleset

table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		iifname $wan ip saddr $admins tcp dport 22 accept
	}
}`;

test("what comes before the first table is kept, in order", () => {
  assert.deepEqual(parseNft(SRC).prelude, [
    'define wan = "eth0"',
    "define admins = { 10.0.0.1, 10.0.0.2 }",
    'include "/etc/nftables.d/*.nft"',
  ]);
});

test("it is written back, so the rules that use it still resolve", () => {
  const out = generate(model(parseNft(SRC))).join("\n");
  assert.match(out, /^define wan = "eth0"$/m);
  assert.match(out, /^include "\/etc\/nftables\.d\/\*\.nft"$/m);
  assert.ok(out.indexOf('define wan') < out.indexOf("table inet filter"),
    "a definition after its use is not a definition");
});

test("the whole file survives now, where three lines used to go missing", () => {
  const v = verify(SRC);
  assert.deepEqual(v.diffs, [], JSON.stringify(v.diffs, null, 2));
  assert.equal(v.ok, v.total);
});

/* Re-importing eFeFlow's own output must not treat its preamble as somebody's
   prelude and stack another copy on every round. */
test("our own preamble is not mistaken for a prelude", () => {
  for (const scope of ["ruleset", "tables"]) {
    let out = generate(model(parseNft(SRC)), { scope });
    for (let i = 0; i < 3; i++) out = generate(model(parseNft(out.join("\n"))), { scope });
    const text = out.join("\n");
    assert.equal((text.match(/^define wan/gm) || []).length, 1, scope);
    assert.equal((text.match(/^flush ruleset$/gm) || []).length, scope === "ruleset" ? 1 : 0, scope);
    assert.equal((text.match(/^delete table /gm) || []).length, scope === "tables" ? 1 : 0, scope);
  }
});

test("a ruleset with nothing before its first table gains nothing", () => {
  const plain = `table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		tcp dport 22 accept
	}
}`;
  assert.deepEqual(parseNft(plain).prelude, []);
  assert.deepEqual(verify(plain).diffs, []);
});

/* ── and what it says after its first table ──────────────────────────────
 *
 * Everything outside a table was hoisted above every table, which is right for
 * a `define` — a definition after its use is not a definition — and wrong for
 * an `include`, which is nft reading another file *at that point*. What people
 * put in the included file is
 *
 *     add rule ip filter input tcp dport 8080 accept
 *
 * and that needs the table to exist. Asked of nft 1.1.6: the file loads as
 * written, and the same file with the include moved to the top is refused —
 * "Could not process rule: No such file or directory". So exporting one of these
 * projects produced a file that would not load.
 *
 * Seventy-six of the three thousand corpus rulesets write an include after a
 * table, and 2,042 top-level `add` lines, 401 `delete`s and 192 `flush`es follow
 * one too.
 */
const LATE = `table ip filter {
	chain input {
		type filter hook input priority filter; policy drop;
		tcp dport 22 accept
	}
}

include "/etc/nftables.d/extra.nft"`;

test("a line written after a table is written back after it", () => {
  const p = parseNft(LATE);
  assert.deepEqual(p.prelude, ['include "/etc/nftables.d/extra.nft"']);
  assert.deepEqual(p.preludeAt, [1], "one table finished above it");

  const out = generate(model(p)).join("\n");
  assert.ok(out.indexOf("table ip filter {") < out.indexOf("include"),
    "the include has to come after the table its file adds rules to");
});

test("and one written before a table still comes before it", () => {
  const p = parseNft(`include "/etc/nftables.d/first.nft"\n${LATE}`);
  assert.deepEqual(p.preludeAt, [0, 1]);
  const out = generate(model(p)).join("\n");
  assert.ok(out.indexOf("first.nft") < out.indexOf("table ip filter {"));
  assert.ok(out.indexOf("table ip filter {") < out.indexOf("extra.nft"));
});

/* A table declared twice is one table and comes out once, so a line between the
   two declarations cannot follow "the table above it" — the table is also
   below. The idiom this protects is the one that makes a flush safe:
   declare empty, flush, then define. Written after the table, the flush would
   throw away everything the file had just put into it. */
test("a line between two declarations of one table stays above it", () => {
  const p = parseNft([
    "table inet x { }",
    "flush table inet x",
    "table inet x {",
    "\tchain input {",
    "\t\ttype filter hook input priority filter; policy accept;",
    "\t\ttcp dport 22 accept",
    "\t}",
    "}",
  ].join("\n"));
  assert.deepEqual(p.preludeAt, [0], "the table below it is the same table");
  const out = generate(model(p)).join("\n");
  assert.ok(out.indexOf("flush table inet x") < out.indexOf("table inet x {"),
    "the flush would have emptied the table it was meant to make room for");
});

/* Position survives being saved and opened again. It is a separate array from
   `prelude` precisely so that a project written before it existed still reads,
   and a project written now has to keep it. */
test("the prelude and its positions survive a save and an open", async () => {
  const { MODEL } = await import("../src/core/model.js");
  const project = await import("../src/core/project.js");
  const p = parseNft(`define wan = "eth0"\n${LATE}`);
  Object.assign(MODEL, model(p));

  const saved = JSON.parse(project.serialise());
  assert.deepEqual(saved.prelude, ['define wan = "eth0"', 'include "/etc/nftables.d/extra.nft"'],
    "a project that lost its defines exports a ruleset that does not load");
  assert.deepEqual(saved.preludeAt, [0, 1]);

  const back = project.deserialise(JSON.stringify(saved));
  assert.deepEqual(back.prelude, saved.prelude);
  assert.deepEqual(back.preludeAt, saved.preludeAt);
});

/* An older project has no positions at all, and that has to mean what it used
   to mean rather than throwing or dropping the lines. */
test("a project saved before positions existed still opens", async () => {
  const project = await import("../src/core/project.js");
  const back = project.deserialise(JSON.stringify({
    app: "eFeFlow", v: 1, name: "old", chains: [], sets: [], objects: [], tables: [],
    prelude: ['define wan = "eth0"'],
  }));
  assert.deepEqual(back.prelude, ['define wan = "eth0"']);
  assert.deepEqual(back.preludeAt, []);
  const out = generate({ ...back, chains: [] }).join("\n");
  assert.match(out, /^define wan = "eth0"$/m);
});
