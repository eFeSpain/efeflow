/* The order the members of a table come back out in.
 *
 * Emission was sets, then objects, then chains. nft prints named objects
 * *first* — counter, quota, set, chain — so any ruleset carrying a named
 * counter or a flowtable came back reordered, and the round-trip check read
 * the move as loss: 85% on a file nothing had been dropped from. That number
 * is the one thing this application asks people to trust.
 *
 * The order below is not an opinion. It is what nft 1.1.6 printed when handed
 * a table with all four kinds in a deliberately jumbled order:
 *
 *     table inet fw {
 *         counter hits { ... }
 *         quota q { ... }
 *         set admin { ... }
 *         chain input { ... }
 *     }
 *
 * Declaration order does not matter to nft itself — a chain may name a set
 * declared below it, also checked — so preserving what arrived is safe. */
import test from "node:test";
import assert from "node:assert/strict";

import { parseNft, verify } from "../src/core/parse.js";
import { generate } from "../src/core/generate.js";
import { MODEL } from "../src/core/model.js";

const load = (src) => {
  const p = parseNft(src);
  Object.assign(MODEL, {
    chains: p.chains, sets: p.sets, objects: p.objects,
    tables: p.tables, prelude: p.prelude,
  });
  return p;
};
/* the member declarations, in the order they are emitted */
const order = () =>
  generate(MODEL).join("\n").split("\n")
    .filter((l) => /^\t(chain|set|map|counter|quota|flowtable|ct helper) /.test(l))
    .map((l) => l.trim().replace(/\s*\{$/, ""));

const CANONICAL = `table inet fw {
	counter hits {
		packets 0 bytes 0
	}

	quota q {
		over 1 mbytes
	}

	set admin {
		type ipv4_addr
		elements = { 10.0.0.1 }
	}

	chain input {
		type filter hook input priority filter; policy drop;
		ip saddr @admin counter name "hits" accept
	}
}`;

/* What `nft list ruleset` hands you, which is what people paste. */
test("a ruleset in nft's own order comes back in nft's own order", () => {
  load(CANONICAL);
  assert.deepEqual(order(), ["counter hits", "quota q", "set admin", "chain input"]);
  assert.deepEqual(verify(CANONICAL).diffs, [], "and reproduces whole");
});

/* What a person writes by hand, which nft accepts and which used to be
   reported as 85% with the objects listed as lost. */
test("a hand-written order is kept, not corrected", () => {
  const hand = `table inet fw {
	chain input {
		type filter hook input priority filter; policy drop;
		ip saddr @admin accept
	}

	set admin {
		type ipv4_addr
		elements = { 10.0.0.1 }
	}

	counter hits {
		packets 0 bytes 0
	}
}`;
  load(hand);
  assert.deepEqual(order(), ["chain input", "set admin", "counter hits"]);
  const v = verify(hand);
  assert.deepEqual(v.diffs, [], "nothing was lost, so nothing may be reported as lost");
  assert.equal(v.ok, v.total);
});

/* Nothing was ever actually dropped — the check was reading a move as a loss.
   This is the assertion that would have caught it either way. */
test("whatever the order, every member is still there", () => {
  for (const src of [CANONICAL, CANONICAL.split("\n").reverse().join("\n")]) {
    const p = parseNft(src);
    Object.assign(MODEL, { chains: p.chains, sets: p.sets, objects: p.objects,
                           tables: p.tables, prelude: p.prelude });
    const out = generate(MODEL).join("\n");
    for (const want of ["counter hits", "quota q", "set admin", "chain input"])
      assert.match(out, new RegExp(want.replace(" ", "\\s+")), `${want} went missing`);
  }
});

/* Made in the editor rather than read from a file: no recorded position, so it
   follows what was imported, in the order nft would print it. */
test("what you add afterwards follows, in nft's order", () => {
  load(CANONICAL);
  MODEL.chains.push({ id: "output", table: "inet fw", hook: null, prio: null,
                      type: "regular", policy: null, rules: [], extra: [] });
  MODEL.sets.push({ n: "fresh", t: "ipv4_addr", f: "", el: [], body: [],
                    kind: "set", table: "inet fw" });
  MODEL.objects.push({ table: "inet fw", kind: "counter", name: "new_hits",
                       body: ["packets 0 bytes 0"] });

  assert.deepEqual(order(), [
    "counter hits", "quota q", "set admin", "chain input",   /* as imported */
    "counter new_hits", "set fresh", "chain output",         /* then nft's order */
  ]);
});

/* A round trip through the editor must not shuffle anything either. */
test("re-importing what was emitted changes nothing", () => {
  load(CANONICAL);
  const once = generate(MODEL).join("\n");
  load(once);
  assert.equal(generate(MODEL).join("\n"), once, "emission has to be a fixed point");
});
