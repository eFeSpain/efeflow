/* A chain called `log` does not load, and nothing said so.
 *
 * This is the export path's copy of the failure this project keeps turning up:
 * not a construct nobody could read, but one everybody read and nobody
 * questioned. `parseNft` takes the chain, `verify()` calls the round trip
 * exact, the generated file carries `round-trip safe` in its own header — and
 * `nft -f` answers `syntax error, unexpected log, expecting string` and applies
 * none of it. The failure is at a declaration, so it takes the whole block with
 * it, and the ruleset the user was looking at was never wrong on screen.
 *
 * Measured against nft 1.0.6: every name below was offered to it as a chain, a
 * set and a table, and these are the ones it refused. Quoting was tried too —
 * `chain "log"` is refused as well, which is why this has to be a warning and
 * cannot be a fix in the generator.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { MODEL } from "../src/core/model.js";
import { parseNft } from "../src/core/parse.js";
import { analyse } from "../src/core/analyse.js";
import { RESERVED, reservedName, lintNames } from "../src/core/lint.js";

const load = (src) => {
  const p = parseNft(src);
  Object.assign(MODEL, { chains: p.chains, sets: p.sets, objects: p.objects,
                         tables: p.tables, prelude: p.prelude });
  return p;
};

/* ── the words nft refuses ───────────────────────────────────────────────── */

test("a chain named after a keyword is reported", () => {
  load(`table ip fw {
\tchain log {
\t\ttype filter hook input priority 0; policy drop;
\t\ttcp dport 22 accept
\t}
}`);
  const f = lintNames(MODEL);
  assert.equal(f.length, 1);
  assert.equal(f[0].kind, "chain");
  assert.equal(f[0].name, "log");
  assert.match(f[0].title[0], /"log"/);
});

test("so is a set, and so is a table", () => {
  load(`table ip ct {
\tset map {
\t\ttype ipv4_addr
\t}
}`);
  const kinds = lintNames(MODEL).map((f) => `${f.kind}:${f.name}`).sort();
  assert.deepEqual(kinds, ["set:map", "table:ct"]);
});

/* The family half of `table ip fw` is a keyword by definition. Reading the
   whole string would have called every table in the corpus reserved. */
test("the family a table is written with is not its name", () => {
  load(`table ip fw {
\tchain input {
\t\ttype filter hook input priority 0; policy drop;
\t}
}`);
  assert.deepEqual(lintNames(MODEL), []);
});

/* ── and the words it does not ───────────────────────────────────────────── */

/* Nearly every chain anyone writes is called one of these. nft only treats
   them as keywords in the position where one can appear, so a list that
   refused them would be worse than no list at all. */
test("the names people actually use are left alone", () => {
  for (const n of ["input", "output", "forward", "filter", "nat", "route",
                   "prerouting", "postrouting", "state", "new", "last", "zone",
                   "wan_in", "lan-out", "admin_nets", "fw", "my_log", "logging"])
    assert.equal(reservedName(n), null, n);
});

test("a name is only reserved as a whole word", () => {
  assert.equal(reservedName("logs"), null);
  assert.equal(reservedName("ct_states"), null);
  assert.equal(reservedName("drop"), "drop");
});

/* ── the finding, as the interface receives it ───────────────────────────── */

test("analyse reports it as an error, ahead of the advice", () => {
  load(`table ip fw {
\tchain drop {
\t\ttype filter hook input priority 0; policy drop;
\t\ttcp dport 22 accept
\t}
}`);
  const all = analyse();
  const f = all.find((x) => x.at === "name");
  assert.ok(f, "the finding is there");
  assert.equal(f.sev, "error");
  assert.equal(f.kind, "syntax");
  assert.equal(f.where, "ip fw / drop");
  /* it points at a declaration, so there is no rule to go to, and the
     interface must not be handed a chain it would try to scroll to */
  assert.equal(f.chain, undefined);
  const firstAdvice = all.findIndex((x) => x.sev !== "error");
  assert.ok(firstAdvice === -1 || all.indexOf(f) < firstAdvice,
    "an error sorts above the advice");
});

test("each finding says the same thing in both languages", () => {
  load(`table ip fw {
\tchain log {
\t\ttype filter hook input priority 0; policy drop;
\t}
\tset ct {
\t\ttype ipv4_addr
\t}
}`);
  for (const f of lintNames(MODEL)) {
    assert.equal(f.title.length, 2);
    for (const half of f.title) assert.match(half, new RegExp(`"${f.name}"`));
    /* "ningún cadena" reads as nobody having looked */
    assert.doesNotMatch(f.title[1], /ningún (cadena|tabla)|ninguna (set|counter)/);
  }
});

/* ── the corpus stays clean ──────────────────────────────────────────────── */

test("nothing this project ships is named something nft refuses", async () => {
  const { SAMPLES } = await import("../src/core/samples.js");
  for (const s of SAMPLES) {
    load(s.nft);
    assert.deepEqual(lintNames(MODEL).map((f) => f.name), [], s.id);
  }
});

/* ── the list itself ─────────────────────────────────────────────────────── */

test("the list is words, lower case, and holds the ones that cost a session", () => {
  for (const w of RESERVED) assert.match(w, /^[a-z][a-z0-9_-]*$/, w);
  /* `fwd` is the one that found this: a forwarding chain is the obvious thing
     to call `fwd`, and it is the `fwd to <dev>` statement of a netdev chain. */
  for (const w of ["fwd", "log", "ct", "map", "set", "counter", "drop", "accept", "ip", "tcp"])
    assert.ok(RESERVED.has(w), w);
});
