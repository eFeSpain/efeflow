/* The one screenshot the README still uses.
 *
 * There were nine. Eight of them showed a window rather than a finding, which
 * is the difference between "look at my interface" and "look at what it found"
 * — and anything that moves belongs to the recorder now (`npm run gifs`). What
 * survives is the canvas, because its layout is the one idea here that prose
 * struggles with: a chain sits at the hook it is attached to, left to right in
 * the order a packet meets them, and at its priority, top to bottom.
 *
 *   npm run shots
 *
 * Committed images go stale silently, so this exists to regenerate it.
 */

import { chromium } from "playwright";
import { readFileSync, mkdirSync } from "node:fs";
import { createServer } from "vite";

const OUT = new URL("../docs/", import.meta.url);
const W = 1440, H = 900;
/* one per README: an English page illustrated with a Spanish interface reads
   as nobody having looked */
const LANGS = [["en", ""], ["es", ".es"]];

const path = (u) => decodeURIComponent(u.pathname).replace(/^\/([A-Za-z]:)/, "$1");

mkdirSync(OUT, { recursive: true });

const fixture = readFileSync(new URL("../test/fixtures/flawed.nft", import.meta.url), "utf8");
const server = await createServer({ server: { port: 5199, strictPort: true } });
await server.listen();
const browser = await chromium.launch();

for (const [lang, suffix] of LANGS) {
  const ctx = await browser.newContext({ viewport: { width: W, height: H }, deviceScaleFactor: 2 });
  await ctx.addInitScript(`localStorage.setItem("efeflow.lang", ${JSON.stringify(lang)});`);
  const page = await ctx.newPage();
  page.on("pageerror", (e) => console.log("  page error:", e.message));

  await page.goto("http://localhost:5199/", { waitUntil: "networkidle" });
  await page.waitForTimeout(3400);        /* the mark draws itself for ~2.1s */

  /* through the import dialog, the way a ruleset actually arrives */
  await page.evaluate((text) => {
    const area = document.querySelector("#imp-text");
    area.value = text;
    area.dispatchEvent(new Event("input", { bubbles: true }));
    document.querySelector("#imp-go").click();
  }, fixture);
  await page.waitForTimeout(1200);

  await page.click('.rb[data-go="editor"]');
  await page.waitForTimeout(700);
  await page.click('.chain[data-chain="inet fw/input"] .rule:nth-child(6)').catch(() => {});
  await page.waitForTimeout(600);

  /* Park the pointer where nothing is under it. Switching screens leaves it on
     the rail button that was clicked, and its tooltip then opens over whatever
     the shot was of — the set list spent a release with "Gestor de sets Alt 4"
     across it. */
  await page.mouse.move(W / 2, H - 4);
  await page.waitForTimeout(250);

  const name = `editor${suffix}.png`;
  await page.screenshot({ path: path(new URL(name, OUT)) });
  console.log(`  ${name.padEnd(16)} the hook rail canvas, in ${lang}`);
  await ctx.close();
}

await browser.close();
await server.close();
console.log("\ndocs/ updated");
