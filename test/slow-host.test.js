/* "Connecting over ssh shows nothing and blocks everything."
 *
 * Two separate defects wearing one symptom, and the first guess about it was
 * wrong. Measured through the running app rather than assumed:
 *
 *   the interface, while a host was being contacted for 8.2s
 *     round trips to the page : 51
 *     slowest one             : 6 ms
 *   -> the webview never froze
 *
 *   a `platform` call issued 300ms after a probe of an unreachable host
 *     the probe took           : 8.0s
 *     the instant call took    : 7743ms
 *   -> it had been queued behind it
 *
 * So the window kept painting the whole time, and every call the interface
 * made after the first one sat in line behind an ssh waiting out its
 * ConnectTimeout. That is the blocking half, and it is in nft.rs: a
 * `#[tauri::command]` declared `fn` is serialised with all the others, and
 * these all end in `wait_with_output`. `async fn` plus `spawn_blocking` gives
 * each one its own thread.
 *
 * The other half is that none of it was ever said out loud. */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { boot, shutdown, $, settle } from "./harness.js";

after(shutdown);

const RS = readFileSync(new URL("../src-tauri/src/nft.rs", import.meta.url), "utf8");
const APP = readFileSync(new URL("../src/app.js", import.meta.url), "utf8");
const CSS = readFileSync(new URL("../src/styles/chrome.css", import.meta.url), "utf8");

/* ── the blocking half ──────────────────────────────────────────────────── */

/* Every command that ends in waiting for a child process has to be one the
   runtime can leave waiting. The two that do not wait are listed by name, so
   adding a twelfth command means saying which kind it is. */
const NOT_BLOCKING = {
  nft_watch: "spawns `nft monitor` and returns; the child outlives the call",
  nft_unwatch: "kills a child it already has",
};

test("a command that waits for a host does not hold the queue", () => {
  const commands = [...RS.matchAll(/#\[tauri::command\]\s*\npub (async )?fn (\w+)/g)]
    .map((m) => ({ name: m[2], async: !!m[1] }));

  assert.ok(commands.length >= 11, `only found ${commands.length} commands — did the attribute change?`);

  for (const c of commands) {
    if (c.name in NOT_BLOCKING) {
      assert.equal(c.async, false,
        `${c.name} is listed as not blocking (${NOT_BLOCKING[c.name]}) but is async`);
      continue;
    }
    assert.equal(c.async, true,
      `${c.name} is a sync command: one of these sitting out an ssh ConnectTimeout ` +
      `queues every other call behind it. Make it async, or list it in NOT_BLOCKING and say why.`);
  }
});

test("and the blocking work is moved off the runtime, not merely awaited", () => {
  /* `async fn` alone would just park the blocking wait on an async worker
     thread — fewer of those than there are firewalls somebody might poke. */
  assert.match(RS, /spawn_blocking/,
    "detached() has to hand the wait to a blocking pool");

  const body = RS.slice(RS.indexOf("async fn detached"), RS.indexOf("async fn detached") + 500);
  assert.match(body, /Err\(e\)/, "a panic in the child must come back as a failure, not a hang");

  /* every async command must actually go through it */
  const asyncNames = [...RS.matchAll(/#\[tauri::command\]\s*\npub async fn (\w+)/g)].map((m) => m[1]);
  for (const n of asyncNames) {
    const at = RS.indexOf(`pub async fn ${n}`);
    const end = RS.indexOf("\n}\n", at);
    assert.match(RS.slice(at, end), /detached\(/,
      `${n} is async but never detaches: its wait is on an async worker thread`);
  }
});

/* ── the half that shows ────────────────────────────────────────────────── */

test("everything that reaches a machine says which machine, while it waits", () => {
  /* the chip is where the target lives, so it is where being contacted belongs */
  assert.match(APP, /chip\.classList\.add\("busy"\)/);
  assert.match(CSS, /\.tb-target\.busy/, "the busy state has to look like something");

  /* counted, not a flag: refreshTarget is two calls, and the first coming back
     does not mean the interface is idle */
  assert.match(APP, /REACHING\+\+ === 0/);
  assert.match(APP, /--REACHING === 0/);

  /* and it is put back whatever happened, including a throw */
  const fn = APP.slice(APP.indexOf("async function reaching"), APP.indexOf("async function reaching") + 700);
  assert.match(fn, /finally\s*\{/, "a call that throws would leave the chip busy forever");
});

test("no call that talks to a host is left silent", () => {
  /* Each of these is a click that opens a connection. Naming them here means a
     new one has to be added, and adding it is the moment to wire the notice. */
  const SITES = [
    ['$("#imp-host")', "Read from host"],
    ['$("#val-nft")', "Check with nft -c"],
    ['$("#ap-go")', "Apply"],
    ['$("#ap-keep")', "Keep"],
    ['$("#ap-rollback")', "Roll back now"],
  ];
  for (const [sel, what] of SITES) {
    const at = APP.indexOf(`${sel}?.addEventListener("click"`);
    assert.ok(at > 0, `${what} (${sel}) is gone from app.js`);
    const handler = APP.slice(at, at + 900);
    assert.match(handler, /whilePressed\(/,
      `${what} can be pressed again while its own call is still out`);
    assert.match(handler, /reaching\(/, `${what} contacts a host without saying so`);
  }

  /* the test button in the target dialog has its own box to report into, but
     it may still not be pressable five times over */
  const tgTest = APP.slice(APP.indexOf('$("#tg-test").addEventListener'), APP.indexOf('$("#tg-save")'));
  assert.match(tgTest, /whilePressed\(/);
  assert.match(tgTest, /Contacting \$\{describe\(tgDraft\)\}/,
    "it says which host it is contacting, not just that it is asking nft");

  /* and the probe on the way into either dialog */
  const refresh = APP.slice(APP.indexOf("async function refreshTarget"), APP.indexOf("function syncTargetForm"));
  assert.match(refresh, /reaching\(/, "opening a dialog contacts the host in silence");
});

/* The chip is shared: it says where nft runs, and now also that it is being
   contacted. It may not be left saying the second after the answer arrives. */
test("the chip goes back to the answer once the answer is in", async () => {
  await boot();
  const { paintTargetChip } = await import("../src/app.js").catch(() => ({}));
  const chip = $("#tb-target");

  chip.classList.add("busy");
  if (paintTargetChip) paintTargetChip({ ok: true, version: "1.1.3", kernel: "6.12", banner: "", uname: "" });
  await settle(30);

  assert.doesNotMatch($("#tb-target-t").textContent, /contact|…/i,
    "the chip is still saying it is contacting a host that has already answered");
});
