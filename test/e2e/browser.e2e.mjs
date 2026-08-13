/* The frontend in a real engine, on the platform CI actually runs.
 *
 * jsdom implements the DOM, not a browser: the harness stubs scrollIntoView,
 * Element.animate and every measurement, so a whole class of defect passes it
 * untouched — a panel a stylesheet leaves at display:none, two chain cards
 * laid out on top of each other, a drag whose DataTransfer never existed. The
 * built-app e2e catches those, and runs only on Windows, only before a
 * release, because WebKitGTK's inspector speaks a handshake nothing attaches
 * to (test/e2e/README.md tells that story).
 *
 * This is the missing middle step: the production build, served by vite
 * preview, driven by the Chromium that was already in devDependencies for
 * `npm run shots`. native.js in its browser mode — no Tauri bridge, and
 * honestly so; the bridge is the Windows run's job. Everything else is real:
 * real layout, real CSS, real drag events, real focus. Journeys, not units —
 * the 1023 jsdom assertions stay the granular layer.
 */
import test, { before, after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { build, preview } from "vite";
import { chromium } from "playwright";

const PORT = 5201;                     /* not 5199: leave `npm run shots` alone */
const fixture = readFileSync(new URL("../fixtures/flawed.nft", import.meta.url), "utf8");

let server, browser, page;
const errors = [];

before(async () => {
  /* The production build, freshly made — a preview of a stale dist/ would
     test the last build, which is the trap the Windows harness checks
     mtimes to avoid. Building takes under two seconds here; checking would
     cost the same and answer less. */
  await build({ logLevel: "silent" });
  server = await preview({ preview: { port: PORT, strictPort: true } });

  browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  page = await ctx.newPage();
  page.on("pageerror", (e) => errors.push(String(e?.message || e)));
  page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });

  await page.goto(`http://localhost:${PORT}/`, { waitUntil: "networkidle" });
  await page.waitForSelector('.rb[data-go="editor"]', { timeout: 15000 });
}, { timeout: 120000 });

after(async () => {
  await browser?.close();
  await new Promise((r) => server?.httpServer.close(r));
});

const SCREENS = ["dash", "editor", "sim", "sets", "topo", "code", "validate", "help"];
const goTo = (id) => page.click(`.rb[data-go="${id}"]`);

/* ── the state the application opens in ─────────────────────────────────── */

test("every screen draws on a blank project, in a real engine", async () => {
  for (const id of SCREENS) {
    await goTo(id);
    const on = await page.$eval(`#s-${id}`, (n) => n.classList.contains("on"));
    assert.equal(on, true, `${id} did not come up`);
  }
});

/* ── import, and the geometry jsdom cannot measure ──────────────────────── */

test("a pasted ruleset imports, and the chains land without overlapping", async () => {
  /* through the door a person uses — the toolbar Open lands on import. In
     jsdom a click ignores visibility, so only this engine notices whether
     the dialog is actually open before its button is pressed. */
  await page.locator('[data-go="import"]').first().click();
  await page.waitForSelector("#scrim-import.on");
  await page.evaluate((text) => {
    const area = document.querySelector("#imp-text");
    area.value = text;
    area.dispatchEvent(new Event("input", { bubbles: true }));
  }, fixture);
  await page.waitForFunction(() => !document.querySelector("#imp-go").disabled);
  await page.click("#imp-go");
  await page.waitForSelector("#s-editor.on");
  await page.waitForFunction(() => document.querySelectorAll(".chain").length >= 3);

  /* The assertion ui-layout.test.js can only approximate: every card has a
     real height, and no two cards occupy the same place. A hidden element
     measures zero in jsdom, so only an engine with layout can say this.

     Measured settled, not mid-flight: placeChains measures again a frame
     after the screen is visible, so two reads a beat apart have to agree
     before the numbers mean anything. The first draft asserted on the
     transition and reported an overlap the finished layout does not have. */
  const read = () => page.$$eval(".chain", (ns) =>
    ns.map((n) => {
      const b = n.getBoundingClientRect();
      return { id: n.dataset.chain, x: b.x, y: b.y, w: b.width, h: b.height };
    }));
  let boxes = await read();
  for (let tries = 0; tries < 20; tries++) {
    await page.waitForTimeout(250);
    const next = await read();
    const same = JSON.stringify(next) === JSON.stringify(boxes);
    boxes = next;
    if (same) break;
  }
  for (const b of boxes) assert.ok(b.h > 60, `${b.id} measures ${b.h}px tall`);
  for (let i = 0; i < boxes.length; i++)
    for (let j = i + 1; j < boxes.length; j++) {
      const a = boxes[i], b = boxes[j];
      const overlap = Math.max(0, Math.min(a.x + a.w, b.x + b.w) - Math.max(a.x, b.x))
                    * Math.max(0, Math.min(a.y + a.h, b.y + b.h) - Math.max(a.y, b.y));
      assert.equal(overlap, 0, `${a.id} and ${b.id} overlap by ${overlap}px²`);
    }
});

/* ── the editor, through real events ────────────────────────────────────── */

test("clicking a rule fills the panel, and an edit lands in the rule", async () => {
  await page.click(".rule >> nth=1");
  await page.waitForSelector("#f-raw");
  await page.fill("#f-dport", "8443");
  /* change fires on blur, which is how a person leaves a field */
  await page.click("#props-body .stat-strip");
  const row = await page.$eval(".rule.sel", (n) => n.textContent);
  assert.match(row, /8443/, "the edited port should be in the selected rule");
});

test("a library object dragged onto a rule merges into it", async () => {
  /* Dropping on a rule merges; dropping on empty card space appends. The
     first is the deterministic one to drive — aim at a rule that does not
     carry the state yet and watch that same rule gain it. The first draft
     dropped on the card, hit a row, merged correctly, and then failed its
     own assertion waiting for a rule count that was never going to move. */
  const target = page.locator(".rule").filter({ hasNotText: "established" }).first();
  const [cid, idx] = await target.evaluate((n) => [n.dataset.chain, n.dataset.i]);
  /* the Connection states category ships closed; a person would open it */
  await page.click('details.cat[data-kind="CT"] summary');
  const src = page.locator('details.cat[data-kind="CT"] .obj', { hasText: "established" }).first();
  await src.dragTo(target);
  await page.waitForFunction(([c, i]) =>
    (document.querySelector(`.rule[data-chain="${c}"][data-i="${i}"]`)?.textContent || "")
      .includes("established"), [cid, idx]);
});

/* ── the simulator arrives already run ──────────────────────────────────── */

test("the simulator reaches a verdict without being asked", async () => {
  await goTo("sim");
  await page.waitForSelector("#vb.show", { timeout: 20000 });
  const verdict = (await page.$eval("#vb-txt", (n) => n.textContent)).trim();
  assert.ok(["ACCEPT", "DROP", "REJECT"].includes(verdict), `unexpected verdict ${verdict}`);
});

test("changing the packet stales the trace; Simular runs it", async () => {
  /* the report that motivated it: a parameter change used to fire the whole
     animation — now it has to say the shown trace is the old one, visibly,
     and wait for the button. Visibly is this engine's department. */
  await page.click('#sim-dir [data-dir="fwd"]');
  await page.waitForSelector("#s-sim.stale #sim-stale", { state: "visible" });
  /* the dimming is a .2s transition — wait for it to land, then hold it */
  await page.waitForFunction(() => +getComputedStyle(document.querySelector("#lane")).opacity < 0.6);
  await page.click("#run-sim");
  await page.waitForSelector("#vb.show", { timeout: 20000 });
  assert.equal(await page.$eval("#s-sim", (n) => n.classList.contains("stale")), false,
    "running must clear the staleness");
  await page.click('#sim-dir [data-dir="in"]');
  await page.click("#run-sim");
  await page.waitForSelector("#vb.show", { timeout: 20000 });
});

/* ── the export dialog opens counted ────────────────────────────────────
   The regression this pins: go("export") used to reach a wrapper only app.js
   had, so any other module opened the dialog with stale stats. One navigator
   now, and the stats are filled on the way in. */
test("the export dialog opens with its numbers already filled", async () => {
  await page.click('[data-go="export"]');
  await page.waitForSelector("#scrim-export.on");
  const first = await page.$eval("#scrim-export .card .num", (n) => n.textContent.trim());
  assert.ok(+first > 0, `the line count reads "${first}" — stats were not refreshed`);
  await page.click("#scrim-export [data-close]");
});

/* ── both languages, in the engine that renders them ────────────────────── */

test("the language switch translates the chrome", async () => {
  await page.click('#lang [data-lang="es"]');
  await page.waitForFunction(() =>
    /tablas/.test(document.querySelector("#st-counts")?.textContent || ""));
  await page.click('#lang [data-lang="en"]');
  await page.waitForFunction(() =>
    /tables/.test(document.querySelector("#st-counts")?.textContent || ""));
});

/* ── and nothing above threw ────────────────────────────────────────────── */

test("the whole journey put no errors in the console", () => {
  const real = errors.filter((e) => !/favicon|Tauri|__TAURI/i.test(e));
  assert.deepEqual(real, [], "console errors during the journeys");
});
