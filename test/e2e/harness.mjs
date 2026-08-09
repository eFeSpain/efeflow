/* Launching the built application and getting a handle on it.
 *
 * jsdom evaluates every module and dispatches real events, which catches a
 * great deal — but it is not the desktop app, and it cannot reach the Tauri
 * bridge. Every expensive defect of the last two days got past it: the
 * simulator throwing on a project with no chains, `openApply` firing the drift
 * check alongside a probe nobody had waited for, an edit dropping the handle
 * that `nft replace` keeps, and two content security policies contradicting
 * each other about the bridge. All four were found by driving the real
 * application by hand. This is that, written down.
 *
 * Windows only, and honestly so: the debugging protocol used here is
 * WebView2's, and WebKitGTK — the Linux webview — does not speak it. CI runs
 * on ubuntu, so this is a gate to run before a release rather than on every
 * push. A run that cannot happen says so and exits 0; a run that happens and
 * fails exits non-zero.
 */
import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdirSync, statSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
export const repo = join(here, "..", "..");
export const EXE = join(repo, "src-tauri", "target", "release", "eFeFlow.exe");
const PORT = 9333;                       /* not 9222: leave a hand-driven one alone */

/** Why this run cannot happen, or null. */
export function unavailable() {
  if (process.platform !== "win32")
    return "the debugging protocol this drives is WebView2's, and this is not Windows";
  if (!existsSync(EXE))
    return `no built application at ${EXE} — run \`npx tauri build --no-bundle\` first`;
  const newest = (dir) => readdirSync(dir, { withFileTypes: true }).reduce((t, d) => {
    const p = join(dir, d.name);
    return Math.max(t, d.isDirectory() ? newest(p) : statSync(p).mtimeMs);
  }, 0);
  if (newest(join(repo, "src")) > statSync(EXE).mtimeMs)
    return "the built application is older than src/ — rebuild it, or this tests the last one";
  return null;
}

/** The stand-in firewall, compiled fresh so no binary lives in the repository. */
function buildFakeSsh() {
  const dir = join(tmpdir(), "efeflow-e2e-bin");
  mkdirSync(dir, { recursive: true });
  execFileSync("rustc", ["-O", "-o", join(dir, "ssh.exe"), join(here, "fake-ssh.rs")],
               { stdio: "pipe" });
  return dir;
}

let child = null, browser = null;

/**
 * @param env  what the stand-in should answer with, per scenario
 * @returns the page, plus the console errors it has seen
 */
export async function launch(env = {}) {
  const { chromium } = await import("playwright");
  const bin = buildFakeSsh();

  child = spawn(EXE, [], {
    env: {
      ...process.env,
      PATH: bin + ";" + process.env.PATH,
      WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: `--remote-debugging-port=${PORT}`,
      EFEFLOW_FAKE_RULESET: join(here, "fixtures", "live.nft"),
      ...env,
    },
    stdio: "ignore",
    detached: false,
  });

  /* the window takes a moment, and the splash holds for another two seconds */
  const deadline = Date.now() + 45000;
  for (;;) {
    try {
      browser = await chromium.connectOverCDP(`http://127.0.0.1:${PORT}`);
      const p = browser.contexts()[0]?.pages().find((x) => x.url().includes("tauri.localhost"));
      if (p) {
        const errors = [];
        p.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
        p.on("pageerror", (e) => errors.push("uncaught: " + (e.stack || String(e)).split("\n")[0]));
        await p.waitForFunction(() => !!document.querySelector("#tb-target-t"), null, { timeout: 20000 });
        await p.waitForTimeout(2600);              /* the splash */
        return { page: p, errors };
      }
      await browser.close();
      browser = null;
    } catch { /* not up yet */ }
    if (Date.now() > deadline) throw new Error("the application never answered on the debug port");
    await new Promise((r) => setTimeout(r, 400));
  }
}

export async function shutdown() {
  try { await browser?.close(); } catch { /* already gone */ }
  browser = null;
  if (child && !child.killed) {
    try { execFileSync("taskkill", ["/PID", String(child.pid), "/T", "/F"], { stdio: "pipe" }); }
    catch { child.kill("SIGKILL"); }
  }
  child = null;
  try { rmSync(join(tmpdir(), "efeflow-e2e-bin"), { recursive: true, force: true }); } catch { /* fine */ }
}

/** Put the application back where it starts: no project, no saved target. */
export async function reset(page, target = null) {
  await page.evaluate((tg) => {
    localStorage.clear();
    if (tg) localStorage.setItem("efeflow.target", JSON.stringify(tg));
  }, target);
  await page.reload();
  await page.waitForFunction(() => !!document.querySelector("#tb-target-t"), null, { timeout: 20000 });
  await page.waitForTimeout(2800);
}

export const SSH = { kind: "ssh", host: "fw.example", user: "netops", port: "", sudo: true };

/** Every screen the rail can reach. */
export const SCREENS = ["dash", "editor", "sim", "validate", "topo", "sets"];

export const goTo = async (page, id) => {
  await page.evaluate((i) => document.querySelector(`.rb[data-go="${i}"]`)?.click(), id);
  await page.waitForTimeout(500);
};

export const visible = (page, sel) =>
  page.evaluate((s) => {
    const e = document.querySelector(s);
    return !!e && getComputedStyle(e).display !== "none";
  }, sel);

export const text = (page, sel) =>
  page.evaluate((s) => document.querySelector(s)?.textContent ?? null, sel);
