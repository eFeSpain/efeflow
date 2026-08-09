/* The dialog that stands in front of the one operation that can lock you out.
 *
 * It used to show a single line — "3 it has that you have not, 1 that differs"
 * — and three separate things were wrong with it.
 *
 * `warnOnDrift` returned early on `!r.ok`, so *I could not read that machine*
 * and *nothing has changed* were both drawn as nothing at all. Same defect
 * family as the counters: a zero that means nothing, painted like a zero that
 * means something, in the place where the difference costs the most.
 *
 * It compared every table on the host, while the default apply replaces only
 * the project's own. Measured: a firewall with Docker on it reports three
 * rules of drift before every single apply, for ever, about chains that are
 * never going to be touched.
 *
 * And it never mentioned the part with no text. A scoped apply is `delete
 * table` and rebuild, so every rule in those tables is destroyed and recreated
 * whether or not a character of it changed — handles reassigned, counters back
 * to zero. Measured on nft 1.1.6, on a live kernel:
 *
 *   before  tcp dport 22 handle 2    tcp dport 80  packets 5  handle 3
 *   after   tcp dport 25 handle 2    tcp dport 80  packets 0  handle 4
 *
 * jsdom is not the desktop app, so probe() never says ok and the drift path
 * cannot be driven end to end here. What can be pinned is the shape of the
 * code that runs it, and every one of these fails if the old shape comes
 * back. */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const APP = ["../src/app.js", "../src/ui/host.js"]
  /* the interface, wherever it now lives: the target chip, the apply screen
     and the live watch moved into ui/host.js when app.js was split, and an
     assertion about them should not care which side of that they landed. */
  .map((f) => readFileSync(new URL(f, import.meta.url), "utf8")).join("\n");
const HTML = readFileSync(new URL("../index.html", import.meta.url), "utf8");

/* Comments here describe the defect and name the thing that caused it, so
   these have to read code rather than prose. */
const code = (s) => s.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");
const fn = (name, until) => {
  const at = APP.indexOf(name);
  assert.ok(at > 0, `${name} is gone from app.js`);
  const end = until ? APP.indexOf(until, at) : at + 2600;
  return code(APP.slice(at, end > at ? end : at + 2600));
};

/* ── could not look is not the same as nothing to see ────────────────────── */

test("a host it could not read is said out loud, never drawn as no changes", () => {
  const body = fn("async function warnOnDrift", "function paintApplyPlan");

  assert.doesNotMatch(body, /if\s*\(\s*!r\.ok\s*\|\|/,
    "!r.ok leaves by the same door as inSync again — silence means both things");
  assert.match(body, /if\s*\(\s*!r\.ok\s*\)\s*\{/,
    "the unreadable host needs a branch of its own, not a shared early return");
  assert.match(body, /Could not read|No se ha podido leer/,
    "and that branch has to say something");
});

test("and it does not disable Apply because it could not draw a picture", () => {
  const body = fn("async function warnOnDrift", "function paintApplyPlan");
  assert.doesNotMatch(body, /#ap-go"\)\.disabled\s*=\s*true/,
    "a screen that blocks the urgent operation teaches people to apply blind");

  /* the only thing that may disable it is having nowhere to apply to */
  const form = fn("function paintApplyForm", "function showApplyStage");
  assert.match(form, /\$\("#ap-go"\)\.disabled\s*=\s*!!unreachable/);
});

/* ── the alarm that was always on ────────────────────────────────────────── */

test("the drift check is scoped to what the apply actually replaces", () => {
  const body = fn("async function warnOnDrift", "function paintApplyPlan");
  assert.match(body, /tables:\s*APPLY\.scope === "tables" \? applyTables\(\) : undefined/,
    "every table on the host counts again, so Docker is drift on every apply");
});

test("changing the scope redraws the plan without going back to the host", () => {
  /* two places match `#ap-scope [data-scope]` — the form's own repaint and the
     click handler. This is about the second. */
  const at = APP.indexOf('$$("#ap-scope [data-scope]").forEach(b=>b.addEventListener("click"');
  assert.ok(at > 0, "the scope buttons no longer have a click handler");
  const handler = code(APP.slice(at, APP.indexOf('$$("#ap-window', at)));
  assert.match(handler, /paintApplyPlan\(\)/,
    "the scope is what `this replaces` means, and the picture has to follow it");
  assert.doesNotMatch(handler, /checkDrift|nftList/,
    "switching scope is a question about a reading already in hand, not a new connection");

  const paint = fn("function paintApplyPlan", "$$(\"#ap-scope");
  assert.match(paint, /applyPlan\(MODEL,\s*PLAN\.host/,
    "the plan is recomputed from the stored reading");
});

/* Found by driving the dialog rather than by reading it, which is the only way
   it could have been found: warnOnDrift opens with `if(!REACH?.ok) return`, and
   openApply fired it alongside a probe that had not come back. So on the first
   open REACH was still null and the check returned instantly — every time. The
   diff appeared on the second open of the dialog and never on the first, which
   is not when anybody needs it. */
test("the drift check waits for the probe it depends on", () => {
  const body = fn("function openApply", '$("#val-apply")');
  assert.match(body, /await refreshTarget\(\)/,
    "warnOnDrift runs while REACH is still null and returns before it does anything");
  assert.ok(body.indexOf("await refreshTarget()") < body.indexOf("warnOnDrift"),
    "the probe has to have answered before the thing that reads its answer");
});

/* ── the connection nobody announced ─────────────────────────────────────── */

test("reading the host for the diff says it is reading the host", () => {
  const body = fn("async function warnOnDrift", "function paintApplyPlan");
  assert.match(body, /reaching\(/,
    "opening the apply dialog reads the whole ruleset over ssh in silence");
});

/* ── the part a diff cannot say ──────────────────────────────────────────── */

test("the cost of the rebuild is stated, not left to the diff to imply", () => {
  const paint = fn("function paintApplyPlan", "$$(\"#ap-scope");

  for (const [what, re] of [
    ["how many rules are rebuilt", /p\.recreated/],
    ["that handles are assigned afresh", /assigned afresh|se asignan de nuevo/i],
    ["that counters go to zero", /go to zero|vuelven a cero/i],
    ["how much traffic that costs", /p\.packets/],
    ["when the host was read", /PLAN\.at/],
  ])
    assert.match(paint, re, `the plan never says ${what}`);

  /* Measured on nft 1.1.3, applying a 27-rule ruleset: 7 rules came back
     reading the handle they read before. They are new rules and numbering
     simply restarts and coincides — but "every handle is reassigned" is a
     promise somebody can check, and 7 times out of 27 they would find it
     broken and stop believing the rest of the screen. */
  assert.doesNotMatch(paint, /every handle is reassigned|todos los handles se reasignan/i,
    "a claim about every handle is one the kernel does not keep");
  assert.match(paint, /coincidence|casualidad/i,
    "and the reason a handle can look unchanged has to be said");
});

/* Three fates, three marks. An edited rule was drawn `−` old / `+` new — the
   same two marks a deletion and a creation get — with only the colour telling
   them apart. In a chain of a dozen entries that scans as a list of deletions,
   which is the alarming reading of the one screen that has to be read quickly
   before a firewall changes. */
test("a changed rule is not marked like a deleted one", () => {
  const paint = fn("function paintApplyPlan", "$$(\"#ap-scope");

  assert.match(paint, /line\("was", "~"/, "the old half of a change still reads as a deletion");
  assert.match(paint, /line\("now", "~"/, "and the new half as an unrelated addition");
  assert.match(paint, /line\("gone", "−"/, "`−` has to keep meaning gone");
  assert.match(paint, /line\("new", "\+"/, "and `+` new");

  /* and the pair is marked as a pair, not left to the text colour alone */
  const css = readFileSync(new URL("../src/styles/chrome.css", import.meta.url), "utf8");
  assert.match(css, /\.ap-plan \.ln\.was > i,\s*\n\s*\.ap-plan \.ln\.now > i/,
    "the two halves of a change need to look like one thing");
});

test("a rule only the host has is shown as one this deletes", () => {
  const paint = fn("function paintApplyPlan", "$$(\"#ap-scope");
  assert.match(paint, /c\.destroy/, "the rules being deleted are not drawn");
  /* order matters: those are running right now and will not be afterwards */
  assert.ok(paint.indexOf("c.destroy") < paint.indexOf("c.create"),
    "rules this destroys come first — they are the ones somebody loses");
  assert.match(paint, /Applying deletes them|Aplicar las borra/,
    "and it has to say what happens to them, not merely list them");
});

/* ── the markup it needs ─────────────────────────────────────────────────── */

test("the dialog has somewhere to put it, hidden until there is something", () => {
  assert.match(HTML, /id="ap-plan-fld"[^>]*style="display:none"/,
    "the panel must start hidden — an empty box is a claim that nothing changes");
  assert.match(HTML, /id="ap-plan"/);
  assert.match(HTML, /id="ap-plan-cost"/);
  /* and it sits before the warning and the button, not after them */
  assert.ok(HTML.indexOf('id="ap-plan-fld"') < HTML.indexOf('id="ap-warn"'));
});
