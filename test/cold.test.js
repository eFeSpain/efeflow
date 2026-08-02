/* Rules the traffic has never reached.
 *
 * The analyser can prove a rule unreachable. Only the kernel can say that a
 * reachable one has matched nothing, and it says it in the counters — which
 * run from the moment the ruleset was loaded, so a zero is worth something
 * without any history being kept.
 *
 * The whole difficulty is that two zeroes look alike. A rule with no `counter`
 * statement reads zero because nothing is counting it. Calling that cold would
 * condemn rules that are perfectly busy, on a screen whose entire claim is
 * that it does not say more than it knows. */
import test from "node:test";
import assert from "node:assert/strict";

import { parseNft } from "../src/core/parse.js";
import { analyse } from "../src/core/analyse.js";
import { refreshCounters } from "../src/host.js";
import { MODEL } from "../src/core/model.js";

/* three rules that count, two of which the host says are at zero, and one
   that carries no counter at all */
const MINE = `table inet fw {
	chain input {
		type filter hook input priority 0; policy drop;
		ct state established,related counter accept
		tcp dport 22 counter accept
		tcp dport 8291 counter accept
		udp dport 5353 accept
	}
}`;
const HOST = MINE
  .replace("ct state established,related counter accept",
           "ct state established,related counter packets 90210 bytes 8000000 accept")
  .replace("tcp dport 22 counter accept", "tcp dport 22 counter packets 0 bytes 0 accept")
  .replace("tcp dport 8291 counter accept", "tcp dport 8291 counter packets 0 bytes 0 accept");

const api = (stdout) => ({ nftList: async () => ({ ok: true, stdout, stderr: "", code: 0 }) });

function load(src) {
  const p = parseNft(src);
  Object.assign(MODEL, {
    chains: p.chains, sets: p.sets, objects: p.objects,
    tables: p.tables, prelude: p.prelude,
  });
  delete MODEL.counters;
  return p;
}
const cold = () => analyse().filter((f) => f.kind === "cold");

test("nothing is called cold before a host has been asked", () => {
  load(MINE);
  assert.deepEqual(cold(), [],
    "every rule reads zero at this point, and that says nothing at all");
});

test("after a read, the rules the kernel never reached are named", async () => {
  load(MINE);
  const r = await refreshCounters({ model: MODEL, target: { kind: "local" }, api: api(HOST) });
  assert.equal(r.ok, true);
  assert.ok(MODEL.counters, "the read has to be recorded, or a zero is ambiguous again");

  const f = cold()[0];
  assert.ok(f, "two rules at zero is worth saying");
  assert.equal(f.sev, "hint", "a cold rule is not a broken one");
  assert.match(f.title[0], /^2 rules/);
  assert.match(f.title[0], /since the ruleset was loaded/,
    "the counters do not know about six months, and must not claim to");
  /* `where` is translated, so match the part that is not: which rules */
  assert.match(f.where, /\b2, 3\b/);
});

/* The distinction the whole feature turns on. */
test("a rule with no counter is unmeasured, not cold", async () => {
  load(MINE);
  await refreshCounters({ model: MODEL, target: { kind: "local" }, api: api(HOST) });
  const f = cold()[0];
  const listed = f.where.match(/[\d,\s]+$/)[0].split(",").map((s) => +s.trim());
  assert.deepEqual(listed, [2, 3], "rule 4 carries no counter and cannot be judged");
  assert.match(f.detail[0], /no <code>counter<\/code>/,
    "and the finding has to say that nothing can be said about it");
});

test("a busy rule is left alone", async () => {
  load(MINE);
  await refreshCounters({ model: MODEL, target: { kind: "local" }, api: api(HOST) });
  const listed = cold()[0].where.match(/[\d,\s]+$/)[0].split(",").map((s) => +s.trim());
  assert.ok(!listed.includes(1), "rule 1 has seen 90210 packets");
  assert.equal(MODEL.chains[0].rules[0].pkts, 90210);
});

test("one quiet rule is not a finding", async () => {
  load(MINE);
  const oneCold = HOST.replace("tcp dport 8291 counter packets 0 bytes 0",
                               "tcp dport 8291 counter packets 44 bytes 3000");
  await refreshCounters({ model: MODEL, target: { kind: "local" }, api: api(oneCold) });
  assert.deepEqual(cold(), [], "an emergency block nobody has needed is not a report");
});

/* A failed read must not leave the zeroes looking like an answer. */
test("a host that would not answer records nothing", async () => {
  load(MINE);
  const r = await refreshCounters({
    model: MODEL, target: { kind: "local" },
    api: { nftList: async () => ({ ok: false, stdout: "", stderr: "no route to host", code: 1 }) },
  });
  assert.equal(r.ok, false);
  assert.equal(MODEL.counters, undefined, "nothing was read, so nothing may be concluded");
  assert.deepEqual(cold(), []);
});

/* Observed, not authored: it must ride in neither undo nor a saved project. */
test("the reading is not part of the ruleset", async () => {
  load(MINE);
  await refreshCounters({ model: MODEL, target: { kind: "local" }, api: api(HOST) });

  const { serialise } = await import("../src/core/project.js");
  assert.ok(!("counters" in JSON.parse(serialise())),
    "a project file describes a ruleset, not a moment on a machine");
});
