import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

/* app.js and index.html are two halves of one contract. Nothing enforces it,
   and a missing id fails silently at whatever moment that code path first
   runs — often inside a timer, where the exception disappears. */

const html = readFileSync(new URL("../index.html", import.meta.url), "utf8");
const js = readFileSync(new URL("../src/app.js", import.meta.url), "utf8");
const main = readFileSync(new URL("../src/main.js", import.meta.url), "utf8");

const ids = new Set([...html.matchAll(/\bid="([\w-]+)"/g)].map((m) => m[1]));

/* Elements the code creates at runtime rather than finding in the markup. */
const CREATED = new Set([
  "toast", "step-bar", "step-go", "step-n", "step-all",
  "props-dock", "mm-vp", "flow-layer", "runtime-error",
  // the properties panel writes its own form each time a rule is selected
  "f-", "f-proto", "f-saddr", "f-daddr", "f-sport", "f-dport",
  "f-iif", "f-oif", "f-verdict", "f-to", "f-cmt", "rule-on", "elem-add",
]);

test("every id the interface looks up exists in the markup", () => {
  const missing = new Map();
  for (const [file, src] of [["src/app.js", js], ["src/main.js", main]]) {
    for (const m of src.matchAll(/\$\("#([\w-]+)"/g)) {
      const id = m[1];
      if (ids.has(id) || CREATED.has(id)) continue;
      const line = src.slice(0, m.index).split("\n").length;
      if (!missing.has(id)) missing.set(id, `${file}:${line}`);
    }
  }
  assert.deepEqual(
    [...missing.entries()],
    [],
    "ids referenced but absent from index.html:\n" +
      [...missing].map(([id, at]) => `  #${id}  (${at})`).join("\n"),
  );
});

test("every screen the rail can reach has a section", () => {
  const targets = [...js.matchAll(/\{id:"(\w+)",\s*en:/g)].map((m) => m[1]);
  assert.ok(targets.length >= 7, "nav table should be discoverable");
  for (const id of targets) {
    assert.ok(ids.has(`s-${id}`), `nav points at #s-${id}, which does not exist`);
  }
});
