import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, newRuleset, importFixture, $, $$, click, settle } from "./harness.js";
import { MODEL, ruleLine } from "../src/core/model.js";
import { TEMPLATES } from "../src/core/vocabulary.js";
import { lintRule } from "../src/core/lint.js";

after(shutdown);

/* Every category in the palette, against the two ways one can be wrong:
   listing something the ruleset does not contain, and doing nothing at all
   when it is dragged onto a rule. Both were true of several of them. */

const items = (kind) => $$(`.cat[data-kind="${kind}"] .obj .nm`).map((n) => n.textContent.trim());
const canAdd = (kind) => !!$(`.cat[data-kind="${kind}"] [data-add]`);

test("the catalogues are catalogues, not a handful", async () => {
  await boot();
  await newRuleset();
  assert.ok(items("SV").length >= 40, "seven services sent people elsewhere for ftp");
  assert.ok(items("SV").includes("ftp"));
  assert.ok(items("SV").includes("telnet"));
  assert.ok(items("PR").length >= 12);
  assert.ok(items("HL").length >= 6);
});

test("what can be added to is what is open-ended", async () => {
  await boot();
  await newRuleset();
  for (const k of ["SV", "PR", "HL", "IF", "NW"])
    assert.ok(canAdd(k), `${k} is open-ended and should offer +`);
  /* nftables defines these. An eighth verdict would emit a ruleset that does
     not load, so the answer is to complete the list, not to open it. */
  for (const k of ["AC", "CT", "NT", "CN"])
    assert.ok(!canAdd(k), `${k} is closed by nftables' grammar`);
});

test("maps are derived from the ruleset, like sets", async () => {
  await boot();
  await newRuleset();
  assert.equal(MODEL.sets.filter((s) => s.kind === "map").length, 0, "a new ruleset has no maps");
  assert.equal(items("MP").length, 1, "so the category shows one placeholder row");
  assert.doesNotMatch(items("MP")[0], /@/,
    "it listed @port_fwd with three entries, which no ruleset here has ever had");
});

/* Five categories returned nothing from fragment(), so dragging them did
   nothing — no rule changed, no message, no clue why. */
test("every draggable category actually produces something", async () => {
  await boot();
  await importFixture();
  const { fragment } = await import("../src/app.js");
  const chain = MODEL.chains.find((c) => c.hook === "input");

  /* placeholder rows are notes, not objects, and must not be draggable */
  for (const ph of $$(".obj.ph"))
    assert.equal(ph.getAttribute("draggable"), "false", "an empty-state row dragged like an object");

  /* Every row, not the first of each category. Sampling one meant `counter`
     stood in for the two entries beside it, and both of those dropped a plain
     anonymous counter — a label that looks like a feature and is not. */
  const rows = (kind) =>
    $$(`.cat[data-kind="${kind}"] .obj:not(.ph)`).map((row) => [
      row.querySelector(".nm").textContent.trim(),
      row.querySelector(".rf").textContent.trim(),
    ]);

  for (const kind of ["SV", "PR", "HL", "MP", "TP", "CT", "AC", "NT",
                      "CN", "ME", "MK", "SE", "IF", "NW"]) {
    for (const [name, ref] of rows(kind)) {
      const frag = fragment(kind, name, ref, chain);
      assert.ok(frag, `dragging ${kind} "${name}" onto a rule does nothing`);
      assert.ok(frag.expr || frag.verdict || frag.ctr || frag.rules,
        `${kind} "${name}" produced an empty contribution`);
    }
  }
});

/* A palette that offers a statement nftables will not take is worse than one
   that does not offer it: the ruleset stops applying and the rule you dragged
   is the last place anybody looks. */
test("everything the palette drops is something nft would load", async () => {
  await boot();
  await importFixture();
  const { fragment } = await import("../src/app.js");
  const chain = MODEL.chains.find((c) => c.hook === "input");
  const ctx = {
    chains: MODEL.chains.filter((c) => c.table === chain.table).map((c) => c.id),
    sets: MODEL.sets.filter((s) => !s.table || s.table === chain.table).map((s) => s.n),
  };

  /* dnat and snat arrive with the destination blank on purpose — better an
     incomplete rule than somebody else's address written into your firewall.
     The contract for those is not that they load; it is that the gap is
     reported rather than left for nft to find. */
  const blankOnPurpose = (kind, name) => kind === "NT" && /^[ds]nat to$/.test(name);

  for (const kind of ["SV", "PR", "HL", "MP", "TP", "CT", "AC", "NT",
                      "CN", "ME", "MK", "SE", "IF", "NW"]) {
    for (const row of $$(`.cat[data-kind="${kind}"] .obj:not(.ph)`)) {
      const name = row.querySelector(".nm").textContent.trim();
      const frag = fragment(kind, name, row.querySelector(".rf").textContent.trim(), chain);
      if (!frag) continue;
      /* a fragment is half a rule, so it is linted as one that accepts */
      const lines = frag.rules
        ? frag.rules.map(ruleLine)
        : [ruleLine({ ...frag, verdict: frag.verdict || "accept", on: true })];
      for (const line of lines) {
        const codes = lintRule(line, ctx).map((f) => f.code);
        if (blankOnPurpose(kind, name))
          assert.deepEqual(codes, ["no-target"], `${kind} "${name}" must say what it is missing`);
        else
          assert.deepEqual(codes, [], `${kind} "${name}" drops ${line}`);
      }
    }
  }
});

/* Two leftovers from the demo ruleset that stopped shipping long ago. */
test("nothing dropped carries an address or a chain the user does not have", async () => {
  await boot();
  await newRuleset();
  const { fragment } = await import("../src/app.js");
  const chain = MODEL.chains.find((c) => c.hook === "input");

  /* `redirect` names no address at all, which is the strongest form of not
     carrying one — dnat and snat need somewhere to go, and arrive blank. */
  for (const name of ["dnat to", "snat to", "redirect"]) {
    const frag = fragment("NT", name, "", chain);
    assert.ok(!frag.to, `${name} arrived carrying somebody else's address`);
  }

  const jump = fragment("AC", "jump", "", chain);
  if (jump) {
    const exists = MODEL.chains.some((c) => c.id === jump.to);
    assert.ok(exists, `jump aims at ${jump.to}, which this ruleset does not have`);
  }
});

test("a counter claims no packets it has not seen", async () => {
  await boot();
  await newRuleset();
  const { fragment } = await import("../src/app.js");
  const chain = MODEL.chains.find((c) => c.hook === "input");
  const frag = fragment("CN", "counter", "", chain);
  assert.equal(frag.ctr, true, "ctr is the statement");
  assert.ok(!frag.pkts, "pkts is what it has counted, and it has counted nothing");
});

test("templates carry the number of rules they actually hold", async () => {
  await boot();
  await newRuleset();
  const rows = $$('.cat[data-kind="TP"] .obj');
  assert.equal(rows.length, TEMPLATES.length);
  rows.forEach((row, i) => {
    const shown = row.querySelector(".rf").textContent.trim();
    assert.match(shown, new RegExp(`^${TEMPLATES[i].rules.length} `),
      "the counts here were invented, and dropping one did nothing");
  });
});

test("a service you add survives, and shows its port", async () => {
  await boot();
  await newRuleset();
  const before = items("SV").length;

  click('.cat[data-kind="SV"] [data-add]');
  await settle(40);
  $("#cf-body input").value = "myapp 9443/tcp";
  click("#cf-yes");
  await settle(60);

  assert.equal(items("SV").length, before + 1);
  assert.ok(items("SV").includes("myapp"));
  const row = $$('.cat[data-kind="SV"] .obj').find(
    (o) => o.querySelector(".nm").textContent.trim() === "myapp");
  assert.match(row.querySelector(".rf").textContent, /9443\/tcp/);

  /* kept on the machine rather than in the project: a new ruleset keeps it */
  await newRuleset();
  assert.ok(items("SV").includes("myapp"),
    "a port you looked up once should be there in the next project too");
});

test("a line that is not a service is refused, not stored", async () => {
  await boot();
  await newRuleset();
  const before = items("SV").length;

  click('.cat[data-kind="SV"] [data-add]');
  await settle(40);
  $("#cf-body input").value = "nonsense";
  click("#cf-yes");
  await settle(60);

  assert.equal(items("SV").length, before, "a service with no port is not a service");
});

/* What you add is knowledge about the world, so it is kept per machine rather
   than per project — which is exactly why it needs a way off the machine. */
test("the catalogue can be carried to another machine", async () => {
  await boot();
  await newRuleset();

  click('.cat[data-kind="SV"] [data-add]');
  await settle(40);
  $("#cf-body input").value = "acme 9911/tcp";
  click("#cf-yes");
  await settle(60);
  assert.ok(items("SV").includes("acme"));

  /* export writes through the same path the project save uses */
  let written = null;
  const win = globalThis.window;
  const real = globalThis.URL.createObjectURL;
  globalThis.URL.createObjectURL = (b) => { written = b; return "blob:captured"; };
  try {
    click("#lib-menu");
    await settle(40);
    const exportItem = $$("[data-act]").find((a) => a.dataset.act === "export");
    assert.ok(exportItem, "there has to be a way out");
    click(exportItem);
    await settle(80);
  } finally {
    globalThis.URL.createObjectURL = real;
  }

  assert.ok(written, "export produced nothing");
  const payload = JSON.parse(await written.text());
  assert.ok(payload.services.some((s) => s.n === "acme"),
    "the exported catalogue must contain what you added");
  assert.ok(Array.isArray(payload.protocols) && Array.isArray(payload.helpers),
    "and all three vocabularies, so an import is complete");
});

test("the menu offers to say where the catalogue is kept", async () => {
  await boot();
  await newRuleset();
  click("#lib-menu");
  await settle(40);
  const acts = $$("[data-act]").map((a) => a.dataset.act);
  for (const a of ["where", "export", "import"]) assert.ok(acts.includes(a), `${a} is missing`);
});
