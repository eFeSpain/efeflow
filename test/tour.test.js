import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { TOUR, tourStep } from "../src/core/tour.js";
import { blankRuleset } from "../src/core/model.js";

const html = readFileSync(new URL("../index.html", import.meta.url), "utf8");
const app = readFileSync(new URL("../src/app.js", import.meta.url), "utf8");

/* The steps are data, so they can be held to the same bar as the samples. */

test("the tutorial is worth the name", () => {
  assert.ok(TOUR.length >= 6, "a handful of slides is not a tutorial");
  const ids = TOUR.map((s) => s.id);
  assert.equal(new Set(ids).size, ids.length, "two steps share an id");
  assert.ok(TOUR.some((s) => s.done), "no step waits for the user; that is a slideshow");
  assert.equal(tourStep(TOUR.length), null, "walking off the end must be an ending, not a crash");
});

test("every step is written in both languages", () => {
  for (const s of TOUR) {
    for (const field of ["title", "body"]) {
      assert.ok(s[field].en?.trim(), `${s.id}: no English ${field}`);
      assert.ok(s[field].es?.trim(), `${s.id}: no Spanish ${field}`);
      assert.notEqual(s[field].en, s[field].es, `${s.id}: the ${field} was never translated`);
    }
  }
});

test("every step belongs to a screen the rail can reach", () => {
  for (const s of TOUR) {
    if (!s.screen) continue;
    assert.match(html, new RegExp(`id="s-${s.screen}"`), `${s.id}: no screen #s-${s.screen}`);
  }
});

/* A predicate that is true before the user has done anything would skip its own
   step; one that never becomes true would strand them on it. */
test("no waiting step is already satisfied on a blank ruleset", () => {
  const m = blankRuleset();
  for (const s of TOUR) {
    if (!s.done) continue;
    const base = s.baseline ? s.baseline(m) : null;
    assert.equal(s.done(m, base), false,
      `${s.id} is satisfied before the user has done anything, so it would flash past`);
  }
});

test("the waiting steps are satisfied by the work they describe", () => {
  const m = blankRuleset();
  const input = m.chains.find((c) => c.id === "input");

  const add = TOUR.find((s) => s.id === "add");
  const base = add.baseline(m);
  input.rules.push({ expr: "", verdict: "continue", on: true });
  assert.ok(add.done(m, base), "adding a rule should finish the add step");

  const rule = input.rules.at(-1);
  rule.expr = "tcp dport 22";
  assert.ok(TOUR.find((s) => s.id === "port").done(m), "the port step reads the expression");

  rule.expr = "tcp dport 22 ip saddr 192.168.1.0/24";
  assert.ok(TOUR.find((s) => s.id === "source").done(m), "and so does the source step");

  rule.verdict = "accept";
  assert.ok(TOUR.find((s) => s.id === "verdict").done(m), "the verdict step reads the verdict");
});

test("the steps stay free of the DOM, like the rest of core", () => {
  const src = readFileSync(new URL("../src/core/tour.js", import.meta.url), "utf8");
  assert.doesNotMatch(src, /\bdocument\b|\bwindow\b|querySelector/,
    "a predicate that reads the DOM cannot be tested without a browser");
  assert.match(app, /from "\.\/core\/tour\.js"/, "app.js is where the DOM half belongs");
});
