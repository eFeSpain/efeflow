/* nft will not read a file whose last line has no newline after it.
 *
 * A ruleset ending in
 *
 *     include "/etc/nftables.d/extra.nft"
 *
 * came back from nft 1.1.6 as
 *
 *     syntax error, unexpected end of file, expecting newline or semicolon
 *
 * which is a complaint about the missing newline that reads like a complaint
 * about the include. The file export has always written one. The check and the
 * apply built their text with join("\n") and did not, so a project whose last
 * line was an include could be neither checked nor applied, and what it said
 * about why was untrue.
 *
 * Every ruleset reaches nft through nftCheck or nftApply — local helper or ssh,
 * whole ruleset or scoped — so the newline is added there, at the one door, and
 * this file holds it to that.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { complete } from "../src/native.js";
import { parseNft } from "../src/core/parse.js";
import { generate } from "../src/core/generate.js";

test("a ruleset gets the newline nft wants, and only if it needs one", () => {
  assert.equal(complete("table inet x { }"), "table inet x { }\n");
  assert.equal(complete("table inet x { }\n"), "table inet x { }\n",
    "one that already ends properly is left exactly as it is");
  assert.equal(complete(""), "\n");
});

/* The two calls that hand a ruleset to nft. A future third one is the reason
   this reads the source rather than trusting that it was remembered. */
test("both doors to nft go through it", () => {
  const src = readFileSync(new URL("../src/native.js", import.meta.url), "utf8")
    .replace(/\/\*[\s\S]*?\*\//g, "");
  for (const cmd of ["nft_check", "nft_apply"]) {
    const call = src.match(new RegExp(`invoke\\("${cmd}",[^)]*\\)`));
    assert.ok(call, `${cmd} is no longer invoked from here — move this check`);
    assert.match(call[0], /ruleset: complete\(ruleset\)/,
      `${cmd} sends a ruleset that may have no newline at the end of it`);
  }
});

/* And the shape that found it: our own output, for the ruleset that broke. */
test("the export ends in a newline even when its last line is an include", () => {
  const p = parseNft(`table ip filter {
	chain input {
		type filter hook input priority filter; policy drop;
		tcp dport 22 accept
	}
}

include "/etc/nftables.d/extra.nft"`);
  const lines = generate({ ...p });
  assert.equal(lines.at(-1), 'include "/etc/nftables.d/extra.nft"',
    "the include belongs at the end, after the table its file adds rules to");
  assert.equal(complete(lines.join("\n")).at(-1), "\n");
});
