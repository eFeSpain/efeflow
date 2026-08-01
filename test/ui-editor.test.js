import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, $, $$, click, setValue, text } from "./harness.js";
import { MODEL } from "../src/core/model.js";

after(shutdown);

const rules = () => $$("#chains .rule");
const codeText = () => $$("#codeout .ln .tx").map((n) => n.textContent).join("\n");
const inputChain = () => MODEL.chains.find((c) => c.id === "input");

test("selecting a rule fills the properties panel", async () => {
  await boot();
  click('.rb[data-go="editor"]');
  click(rules()[4]);

  const body = $("#props-body");
  assert.ok(body.querySelector(".rule-hero"), "no rule header rendered");
  assert.ok(body.querySelector("#f-dport"), "no editable match fields");
  assert.equal($$("#chains .rule.sel").length, 1, "exactly one rule should be selected");
});

test("selecting highlights the matching line of generated code", async () => {
  await boot();
  click('.rb[data-go="editor"]');
  const row = $('.chain[data-chain="inet fw/input"] .rule');
  click(row);

  const hl = $$("#codeout .ln.hl");
  assert.equal(hl.length, 1, "the selected rule should highlight exactly one code line");
  // the highlighted source must be the rule that was clicked, not merely one line
  const expr = row.querySelector(".expr").textContent.trim();
  assert.ok(
    hl[0].textContent.includes(expr.split(" ").slice(0, 3).join(" ")),
    `highlighted "${hl[0].textContent.trim()}" for rule "${expr}"`,
  );
});

test("editing a field re-emits the ruleset", async () => {
  await boot();
  click('.rb[data-go="editor"]');
  click(rules()[5]); // tcp dport 443 ip saddr @admin_nets

  assert.match(codeText(), /dport 443/);
  setValue("#f-dport", "8443", "input");
  assert.match(codeText(), /dport 8443/, "the code pane should follow the edit");
  assert.ok(!/dport 443\b/.test($(".expr-big").textContent), "the panel should follow too");
});

test("an edit lands in history and undo puts it back", async () => {
  await boot();
  click('.rb[data-go="editor"]');
  const before = inputChain().rules.length;

  click($('.chain[data-chain="inet fw/input"] .addrule'));
  assert.equal(inputChain().rules.length, before + 1, "add rule did not add a rule");
  assert.ok(!$("#undo").disabled, "undo should be available after an edit");

  click("#undo");
  assert.equal(inputChain().rules.length, before, "undo did not restore the rule count");
  assert.ok(!$("#redo").disabled, "redo should be available after an undo");

  click("#redo");
  assert.equal(inputChain().rules.length, before + 1, "redo did not reapply");
  click("#undo"); // leave the model as we found it
});

test("the canvas flags the rules the analyser reported", async () => {
  await boot();
  click('.rb[data-go="editor"]');
  const flagged = $$("#chains .rule.warn, #chains .rule.err");
  assert.ok(flagged.length > 0, "findings never reached the canvas");
});

test("applying a fix changes the model and the findings", async () => {
  await boot();
  click('.rb[data-go="validate"]');
  const before = $$("#findings .finding").length;
  assert.ok(before > 0);

  const fix = $("#findings [data-fix]");
  assert.ok(fix, "no finding offered an automatic fix");
  click(fix);

  const after_ = $$("#findings .finding").length;
  assert.ok(after_ < before, `findings should drop after a fix: ${before} → ${after_}`);
  click("#undo");
});

test("the language switch translates without breaking the views", async () => {
  await boot();
  click('.rb[data-go="editor"]');
  const es = text('.addrule');
  click('#lang button[data-lang="en"]');
  const en = text('.addrule');
  assert.notEqual(es, en, "switching language changed nothing");
  assert.equal(en, "Add rule");
  assert.ok($$("#chains .rule").length > 20, "the canvas survived a re-render");
  click('#lang button[data-lang="es"]');
});
