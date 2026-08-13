import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, $, $$, click, setValue, settle } from "./harness.js";
import { target, describe as describeTarget } from "../src/target.js";

after(shutdown);

/* The titlebar chip used to say "no local nft" and its tooltip suggested
   adding an SSH target — with nothing behind it. An affordance that promises
   something the product cannot do is worse than no affordance. */

test("the target chip opens a dialog rather than only explaining itself", async () => {
  await boot();
  const chip = $("#tb-target");
  assert.ok(chip, "the titlebar should carry a target chip");
  click(chip);
  assert.ok($("#scrim-target").classList.contains("on"), "the chip must lead somewhere");
});

test("choosing SSH reveals the fields it needs", async () => {
  await boot();
  click("#tb-target");
  assert.equal($("#tg-fields").style.display, "none", "local needs no host");

  click('[data-target="ssh"]');
  assert.equal($("#tg-fields").style.display, "flex");
  assert.ok($("#tg-host"), "a host field");
  assert.ok($("#tg-user"), "a user field");
});

test("the command preview shows what will actually be run", async () => {
  await boot();
  click("#tb-target");
  click('[data-target="ssh"]');
  setValue("#tg-host", "fw01.example.net", "input");
  setValue("#tg-user", "netops", "input");
  setValue("#tg-port", "2222", "input");
  assert.equal($("#tg-preview").textContent, "netops@fw01.example.net:2222");
});

test("a saved target is remembered and described in the chip", async () => {
  await boot();
  click("#tb-target");
  click('[data-target="ssh"]');
  setValue("#tg-host", "edge.example.net", "input");
  click("#tg-save");
  await settle(60);

  assert.equal(target.kind, "ssh");
  assert.equal(target.host, "edge.example.net");
  assert.match(localStorage.getItem("efeflow.target") || "", /edge\.example\.net/);

  /* Saving contacts it, and here nothing answers — a browser has no nft. So
     the chip may not name the host: on the real app that reading was
     indistinguishable from a host that was up. It is remembered, and it is in
     the tooltip; it is simply not claimed until it has answered. */
  assert.doesNotMatch($("#tb-target-t").textContent, /edge\.example\.net/);
  assert.match($("#tb-target").title, /edge\.example\.net/);
});

test("testing a target reports why it failed instead of doing nothing", async () => {
  await boot();
  click("#tb-target");
  click('[data-target="ssh"]');
  setValue("#tg-host", "unreachable.invalid", "input");
  click("#tg-test");
  await settle(120);

  const out = $("#tg-result");
  assert.notEqual(out.style.display, "none", "the result must be shown");
  assert.ok(out.textContent.trim().length > 0, "and it must say something");
  // in a browser the honest answer is that this needs the desktop app
  assert.match(out.className, /bad/);
});

test("the actions a target exists for are present", async () => {
  await boot();
  assert.ok($("#imp-host"), "import should offer to read from the host");
  assert.ok($("#val-nft"), "validation should offer the real nft -c check");
});

test("nothing throws once the deferred work has landed", async () => {
  const { errors } = await boot();
  await settle(900);
  assert.deepEqual(errors.map((e) => (e && e.stack) || String(e)), []);
});

/* ── the sudo switch tells the truth ─────────────────────────────────────
   Reported from the running app, mid-parachute-jump: "a pesar de desactivar
   sudo: sudo: command not found". A global document handler flips every
   .sw-toggle's class; the target dialog flipped the draft AND painted the
   class itself, so the two cancelled — after every click the switch showed
   the opposite of the draft, and the user's "off" reached the host as sudo.
   The ssh-argv shim caught it; this pins both halves. */
test("clicking the sudo switch flips the state and the paint together", async () => {
  await boot();
  const { target, saveTarget } = await import("../src/target.js");
  saveTarget({ kind: "ssh", host: "lab.example", user: "", port: "", sudo: true });
  click("#tb-target");
  await settle(50);

  click("#tg-sudo");
  await settle(20);
  assert.equal($("#tg-sudo").classList.contains("on"), false,
    "one click must show off — two handlers used to cancel each other");

  click("#tg-save");
  await settle(20);
  assert.equal(target.sudo, false, "and what was shown is what was saved");
});

test("the estate learns a sudo change instead of restoring the old one", async () => {
  await boot();
  const { saveTarget, hosts } = await import("../src/target.js");
  saveTarget({ kind: "ssh", host: "lab.example", user: "", port: "", sudo: true });
  saveTarget({ kind: "ssh", host: "lab.example", user: "", port: "", sudo: false });
  const entry = hosts.find((h) => h.host === "lab.example");
  assert.equal(entry?.sudo, false,
    "picking the host from the list used to silently turn sudo back on");
});
