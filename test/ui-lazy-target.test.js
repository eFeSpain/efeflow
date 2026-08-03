/* Opening an editor is not asking to be connected to a firewall.
 *
 * Boot called refreshTarget(), which is two ssh connections — is the host
 * reachable, and is a rollback pending — before the window had settled. On a
 * host that is slow or away that is sixteen seconds of ConnectTimeout, and on
 * any host at all it is an application reaching into production because
 * somebody opened a design tool. Reported as "it slows down and a couple of
 * cmd windows open behind it".
 *
 * It also contradicted the first thing the README promises about this
 * application: nothing reaches a live host unless you ask. */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { boot, shutdown, $, click, settle } from "./harness.js";

after(shutdown);

const APP = readFileSync(new URL("../src/app.js", import.meta.url), "utf8");
const MAIN = readFileSync(new URL("../src/main.js", import.meta.url), "utf8");

/* Comments here explain what used to happen and name the call while doing it,
   so this has to read code rather than prose. */
const code = (s) => s.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");

test("nothing on the way up goes looking for a host", () => {
  const boot = code(APP.slice(APP.indexOf("loadTarget();")));
  const upTo = boot.slice(0, boot.indexOf("if(!native.isDesktop())"));
  assert.doesNotMatch(upTo, /refreshTarget\(\)/,
    "boot contacts the host before anybody has asked it to");
  /* and what it does instead is say so, rather than leaving the chip blank */
  assert.match(upTo, /paintTargetChip\(null\)/);

  assert.doesNotMatch(code(MAIN), /await probe\(/,
    "main.js probes on the way up, which is the same thing one file over");
});

/* The two moments that are a question about the host, and so may ask one. */
test("the dialogs that are about the host do ask", () => {
  for (const fn of ["function openTarget()", "function openApply()"]) {
    const body = APP.slice(APP.indexOf(fn), APP.indexOf(fn) + 1200);
    assert.match(body, /REACH === null && native\.isDesktop\(\)/,
      `${fn} should find out, and only if nobody has yet`);
  }
});

test("a browser is answered without a socket, because it can be", async () => {
  await boot();
  const { REACH } = await import("../src/app.js").then((m) => ({ REACH: m.REACH })).catch(() => ({}));
  void REACH;
  /* jsdom is not the desktop app: probe() settles that from isDesktop() alone,
     so the apply dialog knows it cannot apply without contacting anything */
  const chip = $("#tb-target-t");
  assert.ok(chip, "the chip has to exist");
  assert.match(chip.textContent, /navegador|browser|nft/i);
});

/* Not contacted is not the same as did not answer, and the chip may not say
   the second when it means the first. */
test("the chip distinguishes unasked from unanswered", () => {
  const paint = APP.slice(APP.indexOf("function paintTargetChip"), APP.indexOf("function paintHostStatus"));
  assert.match(paint, /state === null/, "null is a question nobody asked, not a failure");
  assert.match(paint, /not contacted yet|sin contactar/i);

  const host = APP.slice(APP.indexOf("function paintHostStatus"), APP.indexOf("function paintHostStatus") + 1600);
  assert.match(host, /state === null/,
    "the status bar reported `no host answering` on a host it had never called");
});
