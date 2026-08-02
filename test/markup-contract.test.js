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
  "rule-on", "rule-push", "elem-add",
]);

/* The properties panel writes its own form every time a rule is selected, and
   every field in it is `f-something`. Naming them one by one meant the list
   went stale the moment the panel grew a control — which it needed to, since
   several of the ones already there were painted and wired to nothing. The
   object editor writes its own the same way, with `obj-`. */
const created = (id) =>
  CREATED.has(id) || id.startsWith("f-") || (id.startsWith("obj-") && id !== "obj-new");

test("every id the interface looks up exists in the markup", () => {
  const missing = new Map();
  for (const [file, src] of [["src/app.js", js], ["src/main.js", main]]) {
    for (const m of src.matchAll(/\$\("#([\w-]+)"/g)) {
      const id = m[1];
      if (ids.has(id) || created(id)) continue;
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

/* The status bar carried `main ↑2` — a branch and two unpushed commits, as
   literal text, over a project with no version control of any kind. It is the
   same class of thing as a map called @port_fwd: it reads as a feature. */
/* `nft 1.0.9 · kernel 6.8` sat in the status bar, in the export dialog and in
   the about panel as literal text — on every machine, whether or not one had
   ever been contacted. Both numbers come from the host now, and a guard here
   is cheaper than noticing again in a year. */
test("the markup claims no version of anything it has not asked", () => {
  /* comments explaining what used to be here are allowed to quote it */
  const prose = html.replace(/<!--[\s\S]*?-->/g, "");
  const claims = [...prose.matchAll(/\bnft\s+[\d.]+|\bkernel\s+[\d.]+|nf_tables API [\d.x]+/gi)]
    .map((m) => m[0]);
  assert.deepEqual(claims, [], `hard-coded versions in index.html: ${claims.join(", ")}`);
});

test("nothing in the markup claims a version control that does not exist", () => {
  assert.ok(!/>main\s*<span class="dimmer">/.test(html),
    "a hard-coded branch name and commit count");
  assert.doesNotMatch(html, /Version history\|Historial de versiones/,
    "the undo history was labelled as version history");
  const gitCode = /\bgit\s+(rev-parse|status|branch|log)\b/;
  assert.ok(!gitCode.test(js) && !gitCode.test(main),
    "if git is ever shown, this test should be replaced by one that checks it works");
});
