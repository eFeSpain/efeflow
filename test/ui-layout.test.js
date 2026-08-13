import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, importFixture, $, $$, click, settle } from "./harness.js";

after(shutdown);

/* jsdom reports zero for every measurement, so real overlap cannot be detected
   here. What can be checked is the thing that caused it: layout must ask the
   document for heights rather than deriving them from a rule count. A guessed
   height is always going to collide with a card that grows with its content. */

test("chain rows are assigned after the cards are in the document", async () => {
  await boot();
  await importFixture();
  click('.rb[data-go="editor"]');
  const chains = $$("#chains .chain");
  assert.ok(chains.length >= 5);
  for (const c of chains) {
    assert.match(c.style.left, /^-?\d+px$/, `${c.dataset.chain} has no column`);
    assert.match(c.style.top, /^-?\d+px$/, `${c.dataset.chain} has no row`);
  }
});

test("layout no longer estimates card height from rule count", async () => {
  const { default: _ } = { default: null };
  /* the layout lives in ui/canvas.js since the split; reading app.js here
     made both assertions vacuously true of a file that no longer lays out */
  const src = await import("node:fs").then((fs) =>
    fs.readFileSync(new URL("../src/ui/canvas.js", import.meta.url), "utf8"),
  );
  assert.ok(
    !/rules\.length\s*\*\s*33/.test(src),
    "a height derived from rule count is a guess, and guesses overlap",
  );
  assert.match(src, /offsetHeight/, "placeChains must measure");
});

test("chains within a hook are ordered by priority, top to bottom", async () => {
  await boot();
  await importFixture();
  click('.rb[data-go="editor"]');
  const rows = $$("#chains .chain")
    .map((n) => ({ uid: n.dataset.chain, top: parseInt(n.style.top) }))
    .filter((r) => r.uid.includes("prerouting") === false);

  // raw_pre is priority -300, nat_pre is -100: the lower number sits higher
  const raw = $('.chain[data-chain="inet fw/raw_pre"]');
  const nat = $('.chain[data-chain="ip nat/nat_pre"]');
  assert.ok(raw && nat, "both prerouting chains should be on the canvas");
  assert.ok(
    parseInt(raw.style.top) < parseInt(nat.style.top),
    "priority -300 must be laid out above priority -100",
  );
  assert.ok(rows.length > 0);
});

test("dragging a chain sticks, and re-arranging clears it", async () => {
  const { win } = await boot();
  await importFixture();
  click('.rb[data-go="editor"]');
  const node = $('.chain[data-chain="inet fw/input"]');
  const before = node.style.top;

  const grip = node.querySelector(".chain-hd");
  const opts = { bubbles: true, clientX: 500, clientY: 400, button: 0 };
  grip.dispatchEvent(new win.MouseEvent("pointerdown", opts));
  grip.dispatchEvent(new win.MouseEvent("pointermove", { ...opts, clientY: 620 }));
  grip.dispatchEvent(new win.MouseEvent("pointerup", { ...opts, clientY: 620 }));

  assert.notEqual(node.style.top, before, "the card did not move");
  assert.ok($("#chain-reset").classList.contains("on"), "reset should offer itself");

  click("#chain-reset");
  assert.ok(!$("#chain-reset").classList.contains("on"));
});

/* The priority ruler runs down the left of the canvas from the top, and it is
   the one column carrying information you cannot read anywhere else. Nothing
   that is merely furniture may be anchored up there. The legend used to say so
   itself; it is positioned by the dock now, so the dock has to. */
test("canvas furniture stays out of the priority ruler", async () => {
  const css = await import("node:fs").then((fs) =>
    fs.readFileSync(new URL("../src/styles/app.css", import.meta.url), "utf8"),
  );
  const at = (sel) => css.match(new RegExp(`\\${sel}\\{([^}]*)\\}`))[1];

  const dock = at(".cv-dock");
  assert.match(dock, /bottom\s*:/, "the dock belongs on the bottom edge");
  assert.ok(!/top\s*:/.test(dock), "not the top: the ruler lives there");

  const legend = at(".legend");
  assert.ok(!/position\s*:\s*absolute/.test(legend),
    "the legend rides in the dock now; positioning it again would let the two drift apart");
  assert.ok(!/top\s*:/.test(legend));
});

test("nothing throws once the deferred work has landed", async () => {
  const { errors } = await boot();
  await settle(1000);
  assert.deepEqual(
    errors.map((e) => (e && e.stack) || String(e)),
    [],
  );
});
