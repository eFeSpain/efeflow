/* The GIFs for the README.
 *
 * A screenshot proves the window exists. It does not prove the thing works, and
 * it cannot show the only argument this tool really has: that you watch it find
 * something you had not seen. So each scene here is a claim the README makes,
 * acted out, in the language of the README that carries it.
 *
 *   npm run gifs
 *
 * Playwright records one webm per browser context, so every scene gets its own:
 * boot, set the stage, mark the moment, act, close. ffmpeg trims the setup off
 * the front and encodes with a per-scene palette — one shared palette turns the
 * aqua on near-black into mud.
 *
 * Two things a recorder has to be told, because neither is automatic:
 *   — the pointer is not in the video. A browser records the page, not the
 *     cursor, so without a drawn one every click looks like the interface
 *     moving on its own.
 *   — a demo is not a test. Acting at test speed produces something nobody can
 *     read, so the pauses here are deliberate and they are the point.
 *
 * Needs ffmpeg on PATH. It is the only dependency here that is not npm.
 */

import { chromium } from "playwright";
import { readFileSync, mkdirSync, rmSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createServer } from "vite";

const OUT = new URL("../docs/", import.meta.url);
const TMP = new URL("../.gif-tmp/", import.meta.url);
const W = 1440, H = 900;
/* 760 wide is about what GitHub renders a README image at; more is bytes
   nobody sees. 10fps reads fine for interface motion, and a hero GIF that
   takes four seconds to arrive has already lost the reader it was for. */
const WIDE = 760, FPS = 10;

/* Which scene each README carries. Both languages, because an English README
   illustrated with a Spanish interface is the kind of detail that reads as
   nobody having looked. */
const LANGS = [["en", ""], ["es", ".es"]];

const path = (u) => decodeURIComponent(u.pathname).replace(/^\/([A-Za-z]:)/, "$1");

mkdirSync(OUT, { recursive: true });
rmSync(TMP, { recursive: true, force: true });
mkdirSync(TMP, { recursive: true });

/* The fixture, minus its own header — which lists the defects by rule number.
   Showing the answers next to the analyser finding them is the crossword
   printed beside its solution. The rules underneath are untouched. */
const fixture = readFileSync(new URL("../test/fixtures/flawed.nft", import.meta.url), "utf8")
  .replace(/^(?:#.*\n|\s*\n)+/, "");
const server = await createServer({ server: { port: 5198, strictPort: true } });
await server.listen();
const browser = await chromium.launch();

/* A pointer, drawn into the page, because the recording has none. It follows
   real mouse events, so it cannot claim a click that did not happen. */
const CURSOR = `
  const dot = document.createElement("div");
  dot.style.cssText = "position:fixed;z-index:2147483647;pointer-events:none;left:0;top:0;" +
    "width:18px;height:18px;margin:-9px 0 0 -9px;border-radius:50%;" +
    "background:rgba(57,213,255,.28);border:1.5px solid rgba(57,213,255,.95);" +
    "box-shadow:0 0 12px 2px rgba(57,213,255,.45);transition:transform .09s ease-out";
  const ring = document.createElement("div");
  ring.style.cssText = dot.style.cssText.replace("transition:transform .09s ease-out", "") +
    "opacity:0;transition:transform .38s ease-out,opacity .38s ease-out";
  addEventListener("DOMContentLoaded", () => { document.body.append(ring, dot); });
  addEventListener("mousemove", (e) => {
    for (const n of [dot, ring]) { n.style.left = e.clientX + "px"; n.style.top = e.clientY + "px"; }
  }, true);
  addEventListener("mousedown", () => {
    dot.style.transform = "scale(.6)";
    ring.style.transition = "none"; ring.style.transform = "scale(1)"; ring.style.opacity = ".9";
    requestAnimationFrame(() => {
      ring.style.transition = "transform .38s ease-out,opacity .38s ease-out";
      ring.style.transform = "scale(3.2)"; ring.style.opacity = "0";
    });
  }, true);
  addEventListener("mouseup", () => { dot.style.transform = "scale(1)"; }, true);
`;

/** Boot the app in one language, with the pointer drawn and nothing imported. */
async function open(lang) {
  const ctx = await browser.newContext({
    viewport: { width: W, height: H },
    recordVideo: { dir: path(TMP), size: { width: W, height: H } },
  });
  await ctx.addInitScript(`localStorage.setItem("efeflow.lang", ${JSON.stringify(lang)});`);
  await ctx.addInitScript(CURSOR);
  const started = Date.now();
  const page = await ctx.newPage();
  page.on("pageerror", (e) => console.log("  page error:", e.message));
  await page.goto("http://localhost:5198/", { waitUntil: "networkidle" });
  await page.waitForTimeout(3400);      /* the mark draws itself for ~2.1s */
  await page.mouse.move(W / 2, H - 120);
  return { ctx, page, started };
}

/** Paste the ruleset the way a user does, and wait for the round-trip readout. */
async function paste(page) {
  await page.evaluate((text) => {
    const area = document.querySelector("#imp-text");
    area.value = text;
    area.dispatchEvent(new Event("input", { bubbles: true }));
  }, fixture);
}

/* Deliberate pacing. `to` walks the pointer rather than teleporting it, so the
   eye can follow what is about to be clicked. */
const beat = (page, ms = 900) => page.waitForTimeout(ms);
async function to(page, sel) {
  const box = await page.locator(sel).first().boundingBox();
  if (!box) return false;
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps: 22 });
  return true;
}
async function tap(page, sel, wait = 900) {
  if (!(await to(page, sel))) return;
  await beat(page, 260);
  await page.mouse.down(); await page.waitForTimeout(90); await page.mouse.up();
  await beat(page, wait);
}

function encode(webm, name, from, seconds) {
  const gif = path(new URL(`${name}.gif`, OUT));
  const palette = path(new URL(`${name}.png`, TMP));
  const filter = `fps=${FPS},scale=${WIDE}:-1:flags=lanczos`;
  const run = (args) => execFileSync("ffmpeg", ["-y", "-loglevel", "error", ...args]);
  run(["-ss", String(from), "-t", String(seconds), "-i", webm,
       "-vf", `${filter},palettegen=max_colors=128:stats_mode=diff`, palette]);
  run(["-ss", String(from), "-t", String(seconds), "-i", webm, "-i", palette,
       "-lavfi", `${filter}[x];[x][1:v]paletteuse=dither=bayer:bayer_scale=3:diff_mode=rectangle`,
       "-loop", "0", gif]);
  const kb = Math.round(readFileSync(gif).byteLength / 1024);
  console.log(`  ${name.padEnd(14)} ${seconds.toFixed(0).padStart(2)}s ${String(kb).padStart(5)} KB`);
  return kb;
}

/* Everything a scene needs on screen before it starts. Driven straight at the
   DOM rather than through the pointer, because it happens before the mark and
   nobody is going to see it. */
async function preload(page) {
  await page.evaluate((text) => {
    document.querySelector("#es-import").click();
    const area = document.querySelector("#imp-text");
    area.value = text;
    area.dispatchEvent(new Event("input", { bubbles: true }));
  }, fixture);
  await beat(page, 700);
  await page.evaluate(() => document.querySelector("#imp-go").click());
  await beat(page, 1300);
}

async function scene(name, lang, suffix, note, { setup, act }) {
  const { ctx, page, started } = await open(lang);
  if (setup) await setup(page);
  const mark = Date.now();
  await act(page);
  await beat(page, 800);
  const video = page.video();
  await ctx.close();                    /* the webm is only written on close */
  const kb = encode(await video.path(), name + suffix, (mark - started) / 1000,
                    (Date.now() - mark) / 1000);
  if (kb > 3500) console.log(`    ${name}${suffix} is heavy — shorten it or drop WIDE`);
  return note;
}

/* ── the whole argument in one pass ───────────────────────────────────────
   Paste what you already run, watch it proved line by line, be told what is
   wrong with it, and watch a packet reach a verdict. Nothing here is staged:
   the findings are derived from the ruleset that just went in. */
const hero = {
  act: async (page) => {
    await tap(page, "#es-import", 800);
    await paste(page);
    await beat(page, 1600);                        /* the verified-lines readout */
    await tap(page, "#imp-go", 1500);              /* the canvas fills */
    await tap(page, '.rb[data-go="validate"]', 2000);
    await page.mouse.wheel(0, 240);
    await beat(page, 1400);
    await tap(page, '.rb[data-go="sim"]', 4200);   /* the packet walks */
  },
};

/* ── what nothing else answers comfortably: which rule decides this packet ── */
const simulate = {
  setup: preload,
  act: async (page) => {
    await tap(page, '.rb[data-go="sim"]', 1400);
    await tap(page, '[data-preset="dnat"]', 5400);
  },
};

/* ── the finding most people do not know they have ── */
const shadowed = {
  setup: preload,
  act: async (page) => {
    await tap(page, '.rb[data-go="validate"]', 2000);
    await page.mouse.wheel(0, 210);
    await beat(page, 900);
    await tap(page, ".finding:nth-of-type(2) summary", 2800);
  },
};

const SCENES = [
  ["hero", hero, "paste → proved → findings → verdict"],
  ["simulate", simulate, "a packet walking the chains"],
  ["shadowed", shadowed, "a rule that can never match"],
];

for (const [lang, suffix] of LANGS)
  for (const [name, act, note] of SCENES)
    console.log("             " + (await scene(name, lang, suffix, note, act)));

await browser.close();
await server.close();
if (existsSync(TMP)) rmSync(TMP, { recursive: true, force: true });
console.log("\ndocs/ updated");
