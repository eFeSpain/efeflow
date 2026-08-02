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
                        tables: p.tables, prelude: p.prelude });

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
