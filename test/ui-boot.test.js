import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, importFixture, $, $$, click, text, settle } from "./harness.js";

after(shutdown);

const SCREENS = ["dash", "editor", "sim", "sets", "topo", "code", "validate"];

test("the interface evaluates without throwing", async () => {
  const { errors } = await boot();
  assert.deepEqual(errors, [], "no error may escape during module evaluation");
});

test("the boot splash is dismissed rather than left covering the app", async () => {
  const { win } = await boot();
  // main.js dismisses on a timer; the guard exposes the same entry point
  win.__efeflowBooted();
  assert.ok($("#boot") === null || $("#boot").classList.contains("done"));
});

test("every screen exists and exactly one is shown", async () => {
  await boot();
  for (const id of SCREENS) assert.ok($(`#s-${id}`), `#s-${id} should exist`);
  assert.equal($$(".screen.on").length, 1, "one screen visible at a time");
});

test("every screen renders content when navigated to", async () => {
  await boot();
  for (const id of SCREENS) {
    click(`.rb[data-go="${id}"]`);
    const screen = $(`#s-${id}`);
    assert.ok(screen.classList.contains("on"), `${id} should become visible`);
    assert.equal($$(".screen.on").length, 1, `${id} must not leave another screen up`);
    assert.ok(
      screen.textContent.trim().length > 40,
      `${id} rendered empty — a blank screen reads as broken`,
    );
  }
});

test("the canvas is built from the model, not from markup", async () => {
  await boot();
  await importFixture();
  click('.rb[data-go="editor"]');
  const chains = $$("#chains .chain");
  assert.ok(chains.length >= 5, `expected chains on the canvas, got ${chains.length}`);
  assert.ok($$("#chains .rule").length > 20, "rules should be rendered");
  // every chain card is anchored, which is the whole premise of the layout
  for (const c of chains) {
    assert.match(c.style.left, /px$/, `${c.dataset.chain} has no x anchor`);
    assert.match(c.style.top, /px$/, `${c.dataset.chain} has no y anchor`);
  }
});

test("generated code is emitted into the drawer", async () => {
  await boot();
  await importFixture();
  const lines = $$("#codeout .ln");
  assert.ok(lines.length > 30, `expected generated nft source, got ${lines.length} lines`);
  const src = lines.map((l) => l.textContent).join("\n");
  assert.match(src, /table inet fw/);
  assert.match(src, /hook input/);
});

test("nothing throws on a deferred timer either", async () => {
  const { errors } = await boot();
  // the interface schedules work at 400ms and 600ms; let it land
  await settle(900);
  assert.deepEqual(
    errors.map((e) => (e && e.stack) || String(e)),
    [],
    "an exception inside a timer never reaches the user — it just makes a feature quietly not work",
  );
});

test("the analyser reaches the badges", async () => {
  await boot();
  await importFixture();
  click('.rb[data-go="validate"]');
  const findings = $$("#findings .finding");
  assert.ok(findings.length > 0, "the demo ruleset contains defects; none were reported");
  assert.notEqual(text("#val-grade"), "—", "health grade never filled in");
  assert.match(text("#st-problems") || "", /\d/, "status bar problem count never filled in");
});

/* Two 10px letters in the dimmest text colour were being missed, so the switch
   is flags now. Losing the text means the accessible name has to be explicit,
   and the pair has to keep showing which of the two is active. */
test("the language switch is legible and still says which is active", async () => {
  await boot();

  const buttons = $$("#lang [data-lang]");
  assert.equal(buttons.length, 2);

  for (const b of buttons) {
    assert.ok(b.getAttribute("aria-label")?.trim(),
      "a button with no text needs a name for anything that cannot see it");
    assert.ok(b.querySelector("svg.flag"), "and a flag to be legible at all");
    assert.equal(b.querySelector("svg").getAttribute("aria-hidden"), "true",
      "the flag is decoration; the label carries the meaning");
  }

  const on = buttons.filter((b) => b.classList.contains("on"));
  assert.equal(on.length, 1, "exactly one language is current");

  const other = buttons.find((b) => !b.classList.contains("on"));
  click(other);
  assert.ok(other.classList.contains("on"), "clicking a flag switches to it");
  assert.equal($$("#lang [data-lang].on").length, 1, "and only one stays lit");
});
