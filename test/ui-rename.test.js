import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, $, $$, click, settle } from "./harness.js";
import { project } from "../src/core/project.js";

after(shutdown);

const code = () => $$("#codeout .ln .tx").map((n) => n.textContent).join("\n");

function type(value, key = "Enter") {
  const input = $("#proj-input");
  input.value = value;
  input.dispatchEvent(
    new globalThis.window.KeyboardEvent("keydown", { key, bubbles: true }),
  );
}

test("the project name can be renamed from the toolbar", async () => {
  await boot();
  assert.equal($("#proj-input").classList.contains("on"), false, "starts as a label");

  click("#proj-name");
  assert.ok($("#proj-input").classList.contains("on"), "clicking the name should open an input");
  assert.equal($("#proj-name").style.display, "none");

  type("edge-fw-barcelona");
  assert.equal(project.name, "edge-fw-barcelona");
  assert.equal($("#proj-name-t").textContent, "edge-fw-barcelona");
  assert.equal($("#tb-proj").textContent, "edge-fw-barcelona", "the titlebar should follow");
});

test("the name reaches the generated ruleset, which is why it matters", async () => {
  await boot();
  click("#proj-name");
  type("border-router");
  assert.match(code(), /# border-router/, "the header comment carries the project name");
});

test("Escape cancels and Enter commits", async () => {
  await boot();
  click("#proj-name");
  type("throwaway", "Escape");
  assert.notEqual(project.name, "throwaway", "Escape should discard the edit");

  click("#proj-name");
  type("kept");
  assert.equal(project.name, "kept");
});

test("an empty or whitespace name is refused rather than accepted", async () => {
  await boot();
  click("#proj-name");
  const before = project.name;
  type("   ");
  assert.equal(project.name, before, "a blank name would produce a nameless export");
});

test("the table list is derived, not hard-coded", async () => {
  await boot();
  const shown = $("#proj-tables").textContent;
  assert.match(shown, /inet filter/, `expected the real tables, got "${shown}"`);

  click("#btn-new");
  await settle(60);
  assert.match($("#proj-tables").textContent, /inet filter/, "it should follow the new ruleset");
});

test("nothing throws once the deferred work has landed", async () => {
  const { errors } = await boot();
  await settle(900);
  assert.deepEqual(errors.map((e) => (e && e.stack) || String(e)), []);
});
