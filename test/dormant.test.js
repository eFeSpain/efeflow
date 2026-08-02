/* What the rest of the tool does once it can read `flags dormant`.
 *
 * The flag unregisters every base chain in the table. Nothing in it sees a
 * packet, nft reports nothing wrong, and before this the simulator walked those
 * chains anyway and the analyser costed them — so a parked firewall traced,
 * scored and read exactly like a running one. */
import test from "node:test";
import assert from "node:assert/strict";

import { MODEL } from "../src/core/model.js";
import { evaluate, PRESETS } from "../src/core/simulate.js";
import { analyse, worstCase } from "../src/core/analyse.js";
import { writeTable, readTable } from "../src/core/tables.js";
import { loadFlawed } from "./fixture.js";

const fresh = () => { loadFlawed(); MODEL.objects = []; };
const park = (name) => writeTable(MODEL, name, { dormant: true });
const tableOf = () => MODEL.chains[0].table;

test("a live table is walked, as it always was", () => {
  fresh();
  const r = evaluate({ ...PRESETS.ssh });
  assert.ok(r.steps.length > 0);
  assert.deepEqual(r.parked, []);
});

test("a parked table is not walked at all", () => {
  fresh();
  const name = tableOf();
  park(name);
  const r = evaluate({ ...PRESETS.ssh });
  assert.ok(!r.steps.some((s) => s.chain.table === name),
    "an unregistered chain still saw the packet");
  assert.deepEqual(r.parked, [name], "and the trace has to say why it is short");
});

/* The trace going quiet is not an answer on its own — the point is that the
   verdict changes, and changes to what the kernel would actually do. */
test("the verdict is the kernel's, not the ruleset's on paper", () => {
  fresh();
  const blocked = evaluate({ ...PRESETS.ssh, saddr: "203.0.113.9", dport: 23 });
  park(tableOf());
  const parked = evaluate({ ...PRESETS.ssh, saddr: "203.0.113.9", dport: 23 });
  assert.notEqual(parked.final.v, blocked.final.v,
    "a table that filters nothing cannot reach the same verdict as one that does");
  assert.equal(parked.final.v, "accept");
});

test("waking it up puts every chain back", () => {
  fresh();
  const before = evaluate({ ...PRESETS.ssh }).steps.length;
  park(tableOf());
  writeTable(MODEL, tableOf(), { dormant: false });
  const after = evaluate({ ...PRESETS.ssh });
  assert.equal(after.steps.length, before);
  assert.deepEqual(after.parked, []);
});

test("the analyser says it out loud, once per table", () => {
  fresh();
  assert.ok(!analyse().some((f) => f.kind === "dormant"), "nothing is parked yet");
  const name = tableOf();
  park(name);
  const found = analyse().filter((f) => f.kind === "dormant");
  assert.equal(found.length, 1);
  assert.equal(found[0].table, name);
  assert.match(found[0].title[0], /dormant/);
  /* the number in the finding is the number of rules that are not running */
  assert.match(found[0].title[0], new RegExp(`\\b${readTable(MODEL, name).rules}\\b`));
});

/* A shadowed rule costs an evaluation. A parked table means none of them run. */
test("it is the first warning, not the fourth", () => {
  fresh();
  park(tableOf());
  const warns = analyse().filter((f) => f.sev === "warn");
  assert.ok(warns.length > 1, "the fixture has other warnings to outrank");
  assert.equal(warns[0].kind, "dormant");
});

test("the finding fixes itself, and only the flag", () => {
  fresh();
  const name = tableOf();
  writeTable(MODEL, name, { dormant: true, comment: "parked on purpose" });
  const f = analyse().find((x) => x.kind === "dormant");
  f.fix.run();
  const info = readTable(MODEL, name);
  assert.equal(info.dormant, false);
  assert.equal(info.comment, "parked on purpose", "the comment is not collateral");
  assert.ok(!analyse().some((x) => x.kind === "dormant"));
});

/* An empty table nobody parked anything in is a note, not a risk. */
test("a parked table holding no chains is not reported", () => {
  fresh();
  writeTable(MODEL, "inet spare", { dormant: true });
  assert.ok(!analyse().some((f) => f.kind === "dormant" && f.table === "inet spare"));
});

test("a parked table costs nothing per packet", () => {
  fresh();
  assert.ok(worstCase() > 0);
  for (const name of new Set(MODEL.chains.map((c) => c.table))) park(name);
  assert.equal(worstCase(), 0, "chains that are not registered are not evaluated");
});
