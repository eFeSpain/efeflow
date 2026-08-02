/* Screenshots for the README.
 *
 * Runs the real frontend in a headless browser, loads the flawed fixture the
 * way a user would — through the import dialog — and captures each screen.
 * Committed images go stale silently, so this exists to regenerate them:
 *
 *   npm run shots
 */

import { chromium } from "playwright";
import { readFileSync, mkdirSync } from "node:fs";
import { createServer } from "vite";

const OUT = new URL("../docs/", import.meta.url);
const W = 1440;
const H = 900;

mkdirSync(OUT, { recursive: true });

const fixture = readFileSync(new URL("../test/fixtures/flawed.nft", import.meta.url), "utf8");

const server = await createServer({ server: { port: 5199, strictPort: true } });
await server.listen();

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: W, height: H }, deviceScaleFactor: 2 });
page.on("pageerror", (e) => console.log("  page error:", e.message));

await page.goto("http://localhost:5199/", { waitUntil: "networkidle" });

/* the splash draws itself for ~2.1s; catch it mid-draw for the hero, then let
   it finish rather than tearing it off early */
await page.waitForTimeout(1200);
await shot("boot", "the mark drawing itself");
await page.waitForTimeout(1800);

/* What a launch actually looks like now: nothing open. Captured before the
   fixture goes in, because afterwards there is no way back to it. */
await shot("empty", "no project open");

/* load something worth looking at */
await page.evaluate((text) => {
  const area = document.querySelector("#imp-text");
  area.value = text;
  area.dispatchEvent(new Event("input", { bubbles: true }));
  document.querySelector("#imp-go").click();
}, fixture);
await page.waitForTimeout(400);

async function shot(name, note) {
  /* Park the pointer somewhere with nothing under it. Switching screens leaves
     it on the rail button that was clicked, and its tooltip then opens over
     whatever the shot was of — the set list spent a release with "Gestor de
     sets Alt 4" across it. */
  await page.mouse.move(W / 2, H - 4);
  await page.waitForTimeout(200);
  await page.screenshot({ path: new URL(`${name}.png`, OUT).pathname.slice(1) });
  console.log(`  ${name.padEnd(12)} ${note}`);
}

async function screen(id, name, note, before) {
  await page.click(`.rb[data-go="${id}"]`);
  if (before) await before();
  await page.waitForTimeout(500);
  await shot(name, note);
}

await screen("editor", "editor", "the hook rail canvas", async () => {
  await page.waitForTimeout(400);
  await page.click('.chain[data-chain="inet fw/input"] .rule:nth-child(6)').catch(() => {});
});

await screen("validate", "validate", "findings derived from the ruleset");
await screen("sim", "simulator", "a packet walking the chains", () => page.waitForTimeout(3200));
await screen("sets", "sets", "sets with their back-references");
await screen("topo", "topology", "interfaces derived from the rules");
await screen("code", "code", "generated source and the optimiser");
await screen("dash", "dashboard", "the ruleset at a glance");

await browser.close();
await server.close();
console.log("\ndocs/ updated");
