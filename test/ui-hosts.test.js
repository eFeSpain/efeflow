/* Picking between the firewalls you look after.
 *
 * The dialog knew one host. This is the list, and the two things about it that
 * are easy to get wrong: which row is lit while you are still choosing, and
 * whether forgetting one also selects it. */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, $, $$, click, settle } from "./harness.js";

after(shutdown);

const KNOWN = [
  { id: "h1", name: "Edge", kind: "ssh", host: "fw01.example.net", user: "ana", port: "", sudo: true },
  { id: "h2", name: "Database", kind: "ssh", host: "fw02.example.net", user: "ana", port: "2222", sudo: true },
  { id: "h3", name: "", kind: "ssh", host: "branch.example.net", user: "", port: "", sudo: false },
];

/* Namespace, not a destructured copy: forgetting a host replaces the array,
   and a `const { hosts }` taken beforehand would still be looking at the old
   one. The interface reads the live binding, so a test that does not is
   testing something the product does not do. */
async function withHosts() {
  await boot();
  const tg = await import("../src/target.js");
  tg.hosts.length = 0;
  tg.hosts.push(...JSON.parse(JSON.stringify(KNOWN)));
  return tg;
}

const rows = () => $$(".hostrow .nm").map((n) => n.textContent.trim());
const lit = () => $$(".hostrow.on .nm").map((n) => n.textContent.trim());

test("the firewalls you know are listed, named or not", async () => {
  await withHosts();
  click("#tb-target");
  await settle(120);
  assert.deepEqual(rows(), ["Edge", "Database", "branch.example.net"],
    "one without a name is shown as the way you would reach it");
});

/* The highlight has to follow what you are choosing. Comparing against the
   saved target meant picking a row in this dialog lit up nothing at all. */
test("picking one lights it up before anything is saved", async () => {
  await withHosts();
  const { saveTarget } = await import("../src/target.js");
  saveTarget({ kind: "ssh", host: "fw01.example.net", user: "ana", port: "", sudo: true });

  click("#tb-target");
  await settle(120);
  assert.deepEqual(lit(), ["Edge"], "the one in use opens selected");

  click('.hostrow[data-host="h2"]');
  await settle(80);
  assert.deepEqual(lit(), ["Database"]);
  assert.equal($("#tg-host").value, "fw02.example.net");
  assert.equal($("#tg-port").value, "2222");
  assert.match($("#tg-preview").textContent, /ana@fw02\.example\.net:2222/);
});

/* The cross sits inside the row that selects. */
test("forgetting one does not also point at it", async () => {
  const tg = await withHosts();
  click("#tb-target");
  await settle(120);
  const before = $("#tg-host").value;

  click('[data-forget="h3"]');
  await settle(80);
  assert.deepEqual(rows(), ["Edge", "Database"]);
  assert.equal(tg.hosts.length, 2);
  assert.equal($("#tg-host").value, before, "the fields must not have followed the row that went");
});

test("with none known, the list keeps out of the way", async () => {
  await boot();
  const { hosts } = await import("../src/target.js");
  hosts.length = 0;
  click("#tb-target");
  await settle(120);
  assert.equal($("#tg-saved-fld").style.display, "none");
});

/* An inventory names your firewalls; a project file gets attached to bug
   reports. They must not be the same file. */
test("the estate is kept on the machine, not in the project", async () => {
  await withHosts();
  const { serialise } = await import("../src/core/project.js");
  const saved = serialise();
  assert.ok(!/fw01\.example\.net/.test(saved), "a project must not carry your hostnames");
  assert.ok(!/hosts/.test(JSON.stringify(Object.keys(JSON.parse(saved)))));
});
