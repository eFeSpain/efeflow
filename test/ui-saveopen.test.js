import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, newRuleset, $, $$, click, settle, until } from "./harness.js";
import { project } from "../src/core/project.js";
import { MODEL } from "../src/core/model.js";

after(shutdown);

/* Save and Open each used to inline their own JSON instead of calling
   serialise/deserialise. The pair in core/project.js was covered — that is the
   point — but the interface never called it, so the covered code was not the
   code that ran: a saved project lost the interfaces and networks you had
   typed, and opening one never restored its name.
   These drive the buttons, so they fail if the two ever drift apart again. */

/* What the save button hands to the platform, without touching the disk. */
async function saved() {
  const win = globalThis.window;
  let blob = null;
  const real = win.URL.createObjectURL;
  globalThis.URL.createObjectURL = (b) => { blob = b; return "blob:captured"; };
  try {
    click("#btn-save");
    await until(() => blob, { timeout: 2000 });
    return JSON.parse(await blob.text());
  } finally {
    globalThis.URL.createObjectURL = real;
  }
}

async function openPayload(payload, filename = "PBX.efeflow.json") {
  const win = globalThis.window;
  const input = $('input[type="file"]');
  const file = new win.File([payload], filename, { type: "application/json" });
  const before = JSON.stringify([project.name, MODEL.chains.length]);
  Object.defineProperty(input, "files", { value: [file], configurable: true });
  input.dispatchEvent(new win.Event("change", { bubbles: true }));
  /* The file is read through a FileReader, so the open lands a tick or several
     later. Waiting a fixed 120ms was enough on an idle machine and not on a
     loaded one, which is a test that fails for reasons the product does not
     have. Wait for the project to arrive — and for the payload that is meant
     to be rejected, fall through to the same short settle as before. */
  await until(() => JSON.stringify([project.name, MODEL.chains.length]) !== before,
              { timeout: 2000 }).catch(() => {});
  await settle(40);
}

async function addVia(kind, value) {
  click(`[data-add="${kind}"]`);
  await settle(30);
  $("#cf-body input").value = value;
  click("#cf-yes");
  await settle(40);
}

test("the save button is wired at all", async () => {
  await boot();
  assert.ok($("#btn-save"), "the toolbar Save button needs an id to hang a handler on");
});

test("a saved project carries the name and the kept names", async () => {
  await boot();
  await newRuleset();
  await addVia("IF", "eth7");
  await addVia("NW", "10.44.0.0/16");

  const out = await saved();

  assert.equal(out.app, "eFeFlow");
  assert.ok(out.name, "a project without its name reopens as something else");
  assert.ok(Array.isArray(out.chains) && out.chains.length, "and it has to carry the rules");
  assert.ok(out.scratch, "scratch is part of the project, not of the session");
  assert.ok(out.scratch.ifaces.includes("eth7"),
    "an interface you typed by hand is work, and saving must not drop it");
  assert.ok(out.scratch.networks.includes("10.44.0.0/16"));
});

test("opening a project restores its name, not just its rules", async () => {
  await boot();
  await newRuleset();

  await openPayload(JSON.stringify({
    app: "eFeFlow", v: 1, name: "PBX",
    scratch: { ifaces: ["vlan20"], networks: ["192.168.50.0/24"] },
    chains: [{ id: "input", table: "inet filter", hook: "input", prio: 0,
               type: "filter", policy: "drop",
               rules: [{ expr: "tcp dport 5060", verdict: "accept", on: true }] }],
    sets: [],
  }));

  assert.equal(project.name, "PBX");
  assert.equal($("#proj-name-t").textContent.trim(), "PBX",
    "the header has to say so too, or the rename never came back");
  assert.ok(project.scratch.ifaces.includes("vlan20"), "the kept names come back with it");
  assert.ok(project.scratch.networks.includes("192.168.50.0/24"));
  assert.equal(MODEL.chains.length, 1);
  assert.equal(MODEL.chains[0].rules[0].expr, "tcp dport 5060");
});

/* Import is a scrim over the screens. Opening a project switched the screen
   underneath and left the overlay up, with every button in it disabled — the
   close cross was the only way out, on top of a project that had loaded fine. */
test("opening a project leaves no dialog standing", async () => {
  await boot();
  await newRuleset();

  click('[data-go="import"]');
  await settle(60);
  assert.ok($("#scrim-import").classList.contains("on"), "the import dialog should be up");

  await openPayload(JSON.stringify({
    app: "eFeFlow", v: 1, name: "PBX", scratch: { ifaces: [], networks: [] },
    chains: [{ id: "input", table: "inet filter", hook: "input", prio: 0,
               type: "filter", policy: "drop", rules: [] }],
    sets: [],
  }));

  assert.equal($$(".scrim.on").length, 0, "the project loaded behind a dialog nobody could dismiss");
  assert.ok($("#s-editor").classList.contains("on"), "and it should land on the editor");
});

test("what save writes is what open accepts", async () => {
  await boot();
  await newRuleset();
  await addVia("IF", "bond0");

  const out = await saved();
  const name = out.name;

  await newRuleset();
  assert.ok(!project.scratch.ifaces.includes("bond0"), "a new ruleset starts clean");

  await openPayload(JSON.stringify(out));

  assert.equal(project.name, name, "a round trip through the disk changes nothing");
  assert.ok(project.scratch.ifaces.includes("bond0"));
});

test("a file that is not a project says so instead of throwing", async () => {
  await boot();
  await newRuleset();
  await openPayload(JSON.stringify({ hello: "world" }), "notes.json");

  assert.ok($$(".toast").length >= 0);
  assert.equal(project.name, "untitled", "and it leaves what you had alone");
});
