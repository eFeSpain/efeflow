/* The README makes claims. This checks the ones that can be checked.
 *
 * The opening argument is a ruleset with a rule that can never fire. On a tool
 * whose whole pitch is that it reads nftables correctly, an example that nft
 * would refuse — or that turns out not to have the defect it is introduced as
 * having — is the first thing a reader of the right kind will notice. */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";

import { parseNft } from "../src/core/parse.js";
import { analyse } from "../src/core/analyse.js";
import { MODEL } from "../src/core/model.js";

const READMES = [["README.md", "en"], ["README.es.md", "es"]];
const read = (p) => readFileSync(new URL("../" + p, import.meta.url), "utf8");

const firstNft = (md) => md.match(/```nft\n([\s\S]*?)```/)?.[1];

for (const [file, lang] of READMES) {
  const md = read(file);

  test(`${file}: the ruleset it opens with is one nft would load`, () => {
    const src = firstNft(md);
    assert.ok(src, "the opening example has to be a ```nft block");
    const p = parseNft(src);
    assert.deepEqual(p.errors, [], "the example does not parse");
    assert.equal(p.chains.length, 1);
    assert.equal(p.chains[0].rules.length, 3);
  });

  test(`${file}: and the rule it calls dead really is dead`, () => {
    const p = parseNft(firstNft(md));
    Object.assign(MODEL, {
      chains: p.chains, sets: p.sets, objects: p.objects, tables: p.tables,
    });
    const shadowed = analyse().filter((f) => f.kind === "shadowed");
    assert.equal(shadowed.length, 1, "the opening argument is that one rule is shadowed");
    assert.equal(shadowed[0].i, 2, "and it is the last one");
    assert.equal(shadowed[0].ref, 1, "shadowed by the one above it");
  });

  test(`${file}: every image it points at exists`, () => {
    const srcs = [...md.matchAll(/<img src="([^"]+)"/g)].map((m) => m[1]);
    assert.ok(srcs.length >= 3, "a README with no images is not the one we wrote");
    for (const s of srcs)
      assert.ok(existsSync(new URL("../" + s, import.meta.url)), `${s} is missing`);
    /* the GIFs are per-language: an English page illustrated with a Spanish
       interface reads as nobody having looked */
    const gifs = srcs.filter((s) => s.endsWith(".gif"));
    assert.ok(gifs.length >= 2, "the moving parts are what a screenshot cannot show");
    for (const g of gifs)
      assert.equal(/\.es\.gif$/.test(g), lang === "es", `${g} is the wrong language for ${file}`);
  });

  test(`${file}: every anchor it links to is defined`, () => {
    const targets = new Set([...md.matchAll(/<a name="([\w-]+)">/g)].map((m) => m[1]));
    for (const [, href] of md.matchAll(/\]\(#([\w-]+)\)/g))
      assert.ok(targets.has(href), `#${href} is linked and never defined`);
  });
}

/* Two files, one product. They drifted once already. */
test("both READMEs claim the same test count", () => {
  const n = (md) => md.match(/npm test\s+#\s*(\d+)/)[1];
  assert.equal(n(read("README.md")), n(read("README.es.md")));
});
