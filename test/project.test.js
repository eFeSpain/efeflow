/* Opening a project file. A corrupt or hand-edited one must degrade, not throw
 * on the next render where nothing can catch it. */
import test from "node:test";
import assert from "node:assert/strict";
import { deserialise } from "../src/core/project.js";

test("a project needs a chains array to be a project at all", () => {
  assert.throws(() => deserialise('{"name":"x"}'));
  assert.throws(() => deserialise('{"chains":"nope"}'));
});

test("a non-array sets/objects/tables degrades to empty instead of crashing", () => {
  const o = deserialise(JSON.stringify({
    chains: [], sets: "corrupt", objects: 42, tables: { a: 1 }, prelude: null, preludeAt: "x",
  }));
  assert.deepEqual(o.sets, []);
  assert.deepEqual(o.objects, []);
  assert.deepEqual(o.tables, []);
  assert.deepEqual(o.prelude, []);
  assert.deepEqual(o.preludeAt, []);
});

test("well-formed arrays are preserved", () => {
  const o = deserialise(JSON.stringify({
    name: "p", chains: [{ id: "input" }], sets: [{ n: "s" }], objects: [{ name: "c" }],
  }));
  assert.equal(o.name, "p");
  assert.equal(o.chains.length, 1);
  assert.equal(o.sets[0].n, "s");
  assert.equal(o.objects[0].name, "c");
});
