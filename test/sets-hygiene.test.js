/* Sets that grow, and the one that will not load.
 *
 * A rule that writes to a set — `add @banned { ip saddr }` under a rate limit —
 * is the standard shape for tarpitting a scanner, and the standard way to hand
 * a stranger a lever on kernel memory. nft accepts all of it without comment,
 * so nothing tells you until the machine is in trouble.
 *
 * Every claim here about what nftables does or refuses was checked against
 * nft 1.1.6 on a kernel with CONFIG_NF_TABLES=y, not remembered. */
import test from "node:test";
import assert from "node:assert/strict";

import { parseNft } from "../src/core/parse.js";
import { generate } from "../src/core/generate.js";
import { analyse } from "../src/core/analyse.js";
import { MODEL } from "../src/core/model.js";

const load = (src) => {
  const p = parseNft(src);
  Object.assign(MODEL, {
    chains: p.chains, sets: p.sets, objects: p.objects,
    tables: p.tables, prelude: p.prelude,
  });
  return p;
};
const kinds = () => analyse().map((f) => f.kind);
const find = (k) => analyse().find((f) => f.kind === k);

const withSet = (body, rules = "\t\ttcp dport 22 add @s { ip saddr } drop") => `table inet fw {
\tset s {
${body}
\t}

\tchain input {
\t\ttype filter hook input priority 0; policy drop;
${rules}
\t\tip saddr @s counter drop
\t}
}`;

test("a set filled by traffic with no size and no timeout is reported", () => {
  load(withSet("\t\ttype ipv4_addr\n\t\tflags dynamic"));
  const f = find("set-unbounded");
  assert.ok(f, "nothing else in the toolchain will mention this");
  assert.equal(f.sev, "warn");
  assert.equal(f.at, "set");
  assert.match(f.title[0], /no size and no timeout/);
});

test("naming only what is actually missing", () => {
  load(withSet("\t\ttype ipv4_addr\n\t\tflags dynamic,timeout\n\t\ttimeout 1h"));
  const f = find("set-unbounded");
  assert.ok(f);
  assert.match(f.title[0], /no size$/, "it has a timeout, so only size is missing");
  assert.doesNotMatch(f.title[0], /timeout/);
});

test("a set nothing writes to is not accused of growing", () => {
  load(withSet("\t\ttype ipv4_addr\n\t\telements = { 10.0.0.1 }", "\t\ttcp dport 22 accept"));
  assert.ok(!kinds().includes("set-unbounded"),
    "a static blocklist is a list, not a hole");
});

test("bounded on both counts, and it says nothing", () => {
  load(withSet("\t\ttype ipv4_addr\n\t\tflags dynamic,timeout\n\t\ttimeout 1h\n\t\tsize 65535"));
  assert.ok(!kinds().includes("set-unbounded"));
});

/* `size` is a hard limit: past it the kernel refuses new elements and whatever
   fills the set stops working, with no error anybody is watching for. */
test("a set close to its own size is reported", () => {
  const els = Array.from({ length: 9 }, (_, i) => `10.0.0.${i + 1}`).join(", ");
  load(withSet(`\t\ttype ipv4_addr\n\t\tsize 10\n\t\telements = { ${els} }`, "\t\ttcp dport 22 accept"));
  const f = find("set-full");
  assert.ok(f);
  assert.match(f.title[0], /90%/);
});

test("a set with room is not", () => {
  load(withSet("\t\ttype ipv4_addr\n\t\tsize 1000\n\t\telements = { 10.0.0.1 }", "\t\ttcp dport 22 accept"));
  assert.ok(!kinds().includes("set-full"));
});

/* Verified: nft 1.1.6 answers "Could not process rule: Invalid argument" and
   refuses the whole file — which is why this one is an error, not a hint. */
test("an element with a timeout in a set that forbids them is an error", () => {
  load(withSet("\t\ttype ipv4_addr\n\t\telements = { 203.0.113.5 timeout 30s }", "\t\ttcp dport 22 accept"));
  const f = find("set-elem-timeout");
  assert.ok(f, "nft refuses the file over this, so it cannot be a hint");
  assert.equal(f.sev, "error");
});

test("and it is not raised when the set allows them", () => {
  load(withSet("\t\ttype ipv4_addr\n\t\tflags timeout\n\t\telements = { 203.0.113.5 timeout 30s }",
               "\t\ttcp dport 22 accept"));
  assert.ok(!kinds().includes("set-elem-timeout"));
});

/* A fix that produces something nft would still refuse is worse than none. */
test("the fixes leave a set nft accepts, in the order nft prints", () => {
  load(withSet("\t\ttype ipv4_addr\n\t\telements = { 203.0.113.5 timeout 30s }", "\t\ttcp dport 22 accept"));
  find("set-elem-timeout").fix.run();
  assert.ok(!kinds().includes("set-elem-timeout"), "the fix has to settle it");

  const body = generate(MODEL).join("\n");
  assert.match(body, /flags timeout/);
  assert.ok(body.indexOf("type ipv4_addr") < body.indexOf("flags timeout"),
    "nft takes either order and prints type first; ours should read like its output");
});

test("bounding a set adds both, and the flag the timeout needs", () => {
  load(withSet("\t\ttype ipv4_addr\n\t\tflags dynamic"));
  find("set-unbounded").fix.run();
  assert.ok(!kinds().includes("set-unbounded"));

  const s = MODEL.sets[0];
  assert.ok(s.attr.size, "a set filled by strangers needs a ceiling");
  assert.ok(s.attr.timeout, "and a way out");
  assert.match(s.f, /timeout/, "an element timeout needs the flag, or nft refuses the file");
  assert.match(generate(MODEL).join("\n"), /size 65535/);
});

/* The shipped samples must not trip their own analyser. */
test("nothing eFeFlow ships is reported for this", async () => {
  const { SAMPLES } = await import("../src/core/samples.js");
  for (const s of SAMPLES) {
    load(s.nft);
    const bad = kinds().filter((k) => k.startsWith("set-"));
    assert.deepEqual(bad, [], `sample ${s.id} reports ${bad.join(", ")}`);
  }
});
