/* Opening the simulator on a project with no chains.
 *
 * `evaluate()` ends with `chain: chainOf(last)`, and with no chains `last` is
 * undefined — so the verdict came back naming a chain that did not exist and
 * the screen threw on `res.final.chain.table`. A blank project is the state
 * this application opens in, and the simulator is one click from it, so this
 * is the first thing a new user could do to break it.
 *
 * It went unseen for a long time because every test and every smoke run
 * imported a ruleset first. It surfaced while driving the built app through
 * its screens with nothing loaded.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { evaluate, BASE } from "../src/core/simulate.js";
import { MODEL } from "../src/core/model.js";

test("a ruleset with no chains gives a verdict rather than an exception", () => {
  MODEL.chains = [];
  MODEL.sets = [];
  MODEL.objects = [];
  MODEL.tables = [];

  const res = evaluate({ ...BASE, saddr: "10.0.0.1", daddr: "10.0.0.2", proto: "tcp", dport: 80 });
  assert.equal(res.final.v, "accept", "nothing looks at it, so nothing stops it");
  assert.equal(res.final.chain, null,
    "an undefined chain is what the screen then dereferenced");
  assert.deepEqual(res.steps, [], "and it walked nothing, which is the truth");
});

/* The other half: the screen has to have something to say about it. */
test("and the screen says so instead of naming a chain that is not there", () => {
  const app = readFileSync(new URL("../src/ui/simulator.js", import.meta.url), "utf8");
  const at = app.indexOf("function finish(){");
  assert.ok(at > 0, "the verdict banner is gone");
  const body = app.slice(at, at + 2200);

  assert.doesNotMatch(body, /res\.final\.chain\.table/,
    "the chain is dereferenced without asking whether there is one");
  assert.match(body, /no chains|ninguna cadena/i,
    "an empty ruleset needs a sentence, not a blank panel");
});
