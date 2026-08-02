import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, newRuleset, $, $$, click, setValue, settle } from "./harness.js";
import { TOUR } from "../src/core/tour.js";
import { MODEL } from "../src/core/model.js";

after(shutdown);

const open = () => $("#tour").classList.contains("on");
const stepN = () => $("#tour-n").textContent.trim();

async function startTour() {
  click('.rb[data-go="help"]');
  await settle(40);
  click("#g-tour-go");
  await settle(60);
}

test("the guide starts it, and it lands on the first step", async () => {
  await boot();
  await newRuleset();
  assert.ok(!open(), "it should not run uninvited");

  await startTour();
  assert.ok(open());
  assert.equal(stepN(), `1/${TOUR.length}`);
  assert.ok($("#tour-title").textContent.trim(), "the step has a heading");
  assert.ok($("#tour-body").textContent.trim(), "and something to read");
});

test("it moves forwards and back", async () => {
  await boot();
  await newRuleset();
  await startTour();

  assert.equal($("#tour-back").style.visibility, "hidden", "there is nothing before the first step");
  click("#tour-next");
  await settle(40);
  assert.equal(stepN(), `2/${TOUR.length}`);
  assert.notEqual($("#tour-back").style.visibility, "hidden");

  click("#tour-back");
  await settle(40);
  assert.equal(stepN(), `1/${TOUR.length}`);
});

/* The point of the thing: a step that asks for an action waits for the action,
   and notices when the ruleset changes rather than when a button is pressed. */
test("a step that waits advances when the work is done, not when a button is", async () => {
  await boot();
  await newRuleset();
  await startTour();

  click("#tour-next"); await settle(30);   /* canvas */
  click("#tour-next"); await settle(40);   /* add a rule to input — waits */
  assert.equal(stepN(), `3/${TOUR.length}`);
  assert.ok($("#tour-wait").classList.contains("on"), "it should say it is your turn");

  const input = MODEL.chains.find((c) => c.id === "input");
  const before = input.rules.length;
  click('.chain[data-chain$="/input"] .addrule');
  await settle(80);

  assert.equal(input.rules.length, before + 1, "the rule was added");
  assert.equal(stepN(), `4/${TOUR.length}`, "and the step noticed on its own");
});

test("a waiting step still lets you out", async () => {
  await boot();
  await newRuleset();
  await startTour();
  click("#tour-next"); await settle(30);
  click("#tour-next"); await settle(40);

  assert.match($("#tour-next").textContent, /Skip|Saltar/,
    "a tutorial you cannot leave is a trap");
  click("#tour-next"); await settle(40);
  assert.equal(stepN(), `4/${TOUR.length}`);
});

test("it closes, and stays closed", async () => {
  await boot();
  await newRuleset();
  await startTour();
  click("#tour-x");
  await settle(40);
  assert.ok(!open());
  assert.equal(localStorage.getItem("efeflow.tour"), "1", "so it can stop offering itself");
});

/* Half the targets are in the properties panel, which does not exist until a
   rule is selected — so this checks them where the tutorial meets them, after
   the step that puts a rule on the screen. */
test("every step points at something that is there when it is reached", async () => {
  await boot();
  await newRuleset();
  click('.rb[data-go="editor"]');
  await settle(60);
  click($$("#chains .rule")[0]);            /* the panel writes its form on select */
  await settle(60);

  for (const s of TOUR) {
    if (!s.target) continue;
    click(`.rb[data-go="${s.screen}"]`);
    await settle(40);
    assert.ok($(s.target), `step ${s.id} points at ${s.target}, which is not there`);
  }
});

/* And if one ever is missing, the step has to degrade rather than point at the
   corner of the screen. */
test("a step with nothing to point at dims everything instead", async () => {
  await boot();
  await newRuleset();
  await startTour();

  /* the first step has no target at all */
  assert.ok($("#tour-hole").classList.contains("blind"),
    "with no target the spotlight must not sit in a corner");
});
