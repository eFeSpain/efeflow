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

/* ── the whole rule, in one place ────────────────────────────────────────
 *
 * Over ssh it must not open a connection unless told to. On the local machine
 * it must not read the running ruleset unless told to. Reading this machine is
 * an option in the import dialog — "Read from host" against a local target —
 * and that is where it belongs: something a person clicks.
 *
 * The list below is every place in the interface that reaches a machine, and
 * what makes it happen. A new one has to be added here, which is the point:
 * it forces whoever adds it to say out loud what asked for it. */
const REACHES = {
  nftCheck:   "Check with nft -c, and the export dialog's verify",
  nftList:    "Read from host in the import dialog, counters, and the drift check",
  nftWatch:   "Watch, on the canvas",
  nftUnwatch: "Watch again, to stop it — and teardown",
  hostProbe:  "probe(), from the target and apply dialogs only",
  nftArm:     "Apply, when a rollback window was asked for",
  nftApply:   "Apply",
  nftDisarm:  "Keep, after an apply",
  nftRollback:"Roll back now",
  nftArmed:   "the pending-rollback question, asked with the others",
  nftRuleOp:  "the handle chip on a rule, pushed one at a time",
};

test("everything that touches a machine is something a person pressed", () => {
  const read = (f) => code(readFileSync(new URL("../src/" + f, import.meta.url), "utf8"));
  const all = [code(APP), read("target.js"), read("apply.js"), read("host.js")].join("\n");

  /* whatever the object is called where it is used — native, api, nativeApi */
  const found = new Set(
    [...all.matchAll(/\b(?:native|nativeApi|api)\.(nft\w+|hostProbe)\(/g)].map((m) => m[1]));

  for (const f of found)
    assert.ok(f in REACHES,
      `${f} reaches a machine and nothing here says what asked it to`);
  for (const f of Object.keys(REACHES))
    assert.ok(found.has(f), `${f} has gone — update the list, and say what replaced it`);
});

test("the one that reads this machine is the import dialog's, not the boot's", () => {
  const at = APP.indexOf('$("#imp-host")');
  assert.ok(at > 0, "the button that reads a host has to exist");
  const handler = APP.slice(at, at + 400);
  assert.match(handler, /addEventListener\("click"/, "it is a click, not something on the way up");
  assert.match(handler, /native\.nftList\(asTauriTarget\(\)\)/,
    "and it reads whatever target is configured — this machine, when that is the target");
});
