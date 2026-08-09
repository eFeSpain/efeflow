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

const APP = ["../src/app.js", "../src/ui/host.js"]
  /* the interface, wherever it now lives: the target chip, the apply screen
     and the live watch moved into ui/host.js when app.js was split, and an
     assertion about them should not care which side of that they landed. */
  .map((f) => readFileSync(new URL(f, import.meta.url), "utf8")).join("\n");
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
  /* and the label may not be a hostname: one up there reads as a connection to
     it, which is what it looked like on every launch */
  assert.match(paint, /t\("not connected", "sin conectar"\)/,
    "the chip has to say it has not connected, not name a host as though it had");

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

/* Reported from the running app: "as soon as it starts, efe@192.168.109.137
   appears top right, and it should not — if that label is there on launch it
   gives the impression it is connected." The saved host is remembered; it is
   simply not claimed until something has answered. */
test("the chip names no host until one has answered", async () => {
  await boot();
  const { saveTarget } = await import("../src/target.js");
  const { paintTargetChip } = await import("../src/app.js").catch(() => ({}));
  saveTarget({ kind: "ssh", host: "fw01.example.net", user: "ana", port: "", sudo: true });

  /* not contacted */
  if (paintTargetChip) paintTargetChip(null);
  await settle(30);
  const label = $("#tb-target-t").textContent;
  assert.doesNotMatch(label, /fw01\.example\.net/,
    "a hostname on the chip reads as a live connection to it");
  assert.match(label, /not connected|sin conectar/i);
  assert.match($("#tb-target").title, /fw01\.example\.net/,
    "and the destination is still there to be seen, in the tooltip");

  /* once it has answered, it may say so */
  if (paintTargetChip) paintTargetChip({ ok: true, version: "1.1.3", kernel: "6.12", banner: "", uname: "" });
  await settle(30);
  assert.match($("#tb-target-t").textContent, /fw01\.example\.net/);
  assert.ok($("#tb-target").classList.contains("remote"));

  /* asked and did not answer is a third state, and it is not the second.
     Measured on the running app against TEST-NET-1: after eight seconds of
     ConnectTimeout the chip read `efe@192.0.2.1`, exactly as it does when the
     host is up — the only difference was the colour of a six-pixel dot. */
  if (paintTargetChip) paintTargetChip({ ok: false, why: "connection timed out" });
  await settle(30);
  assert.doesNotMatch($("#tb-target-t").textContent, /fw01\.example\.net/,
    "a host that did not answer is named as though it had");
  assert.match($("#tb-target-t").textContent, /no answer|sin respuesta/i);
  assert.match($("#tb-target").title, /fw01\.example\.net/, "and which host it was is still there");
  assert.match($("#tb-target").title, /timed out/, "along with why");
  assert.ok(!$("#tb-target").classList.contains("remote"));
});
