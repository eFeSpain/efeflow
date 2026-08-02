/* Every name imported from a local module is a name that module exports.
 *
 * `native.nftVersion()` outlived the function by several commits. Rollup said
 * "not exported by src/native.js", printed it in yellow, and produced the
 * bundle anyway — so a release installer shipped with `undefined()` on the one
 * code path that only runs where a local `nft` exists, which is the platform
 * nobody here builds on. The build fails on it now; this fails on it sooner,
 * and without needing a build.
 *
 * A namespace import (`import * as native`) is the case rollup catches and a
 * simple import check does not, so member access through the namespace is
 * checked too. */
import test from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";

const SRC = new URL("../src/", import.meta.url);

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const at = new URL(name, dir);
    if (statSync(at).isDirectory()) walk(new URL(name + "/", dir), out);
    else if (name.endsWith(".js")) out.push(at);
  }
  return out;
}

const FILES = walk(SRC);
const text = new Map(FILES.map((u) => [u.href, readFileSync(u, "utf8")]));

/** Every name a module exports, however it spells the export. */
function exportsOf(src) {
  const names = new Set();
  for (const m of src.matchAll(/^export\s+(?:async\s+)?(?:function|class)\s+([\w$]+)/gm))
    names.add(m[1]);
  for (const m of src.matchAll(/^export\s+(?:const|let|var)\s+([\w$]+)/gm)) names.add(m[1]);
  /* `export { a, b as c }` — the exported name is what follows `as` */
  for (const m of src.matchAll(/^export\s*\{([^}]*)\}/gm))
    for (const part of m[1].split(","))
      if (part.trim()) names.add(part.trim().split(/\s+as\s+/).pop().trim());
  return names;
}

const resolve = (from, spec) => new URL(spec, from).href;
const local = (spec) => spec.startsWith("./") || spec.startsWith("../");

/** The module with its imports and comments taken out, for scanning member use. */
const body = (src) =>
  src.replace(/^import[\s\S]*?from\s*["'][^"']+["'];?/gm, "")
     .replace(/\/\*[\s\S]*?\*\//g, "")
     .replace(/(^|[^:])\/\/.*$/gm, "$1");

test("every named import resolves to a real export", () => {
  const broken = [];
  for (const file of FILES) {
    const src = text.get(file.href);
    for (const m of src.matchAll(/import\s*\{([^}]*)\}\s*from\s*["']([^"']+)["']/g)) {
      const [, list, spec] = m;
      if (!local(spec)) continue;
      const target = resolve(file, spec);
      assert.ok(text.has(target), `${file.pathname} imports ${spec}, which does not exist`);
      const has = exportsOf(text.get(target));
      for (const raw of list.split(",")) {
        const name = raw.trim().split(/\s+as\s+/)[0].trim();
        if (name && !has.has(name))
          broken.push(`${spec} does not export ${name}  (${file.pathname.split("/").pop()})`);
      }
    }
  }
  assert.deepEqual(broken, [], "imports with nothing behind them:\n  " + broken.join("\n  "));
});

/* The shape that shipped: `import * as native` and then `native.somethingGone()`. */
test("every call through a namespace import is a function that exists", () => {
  const broken = [];
  for (const file of FILES) {
    const src = text.get(file.href);
    for (const m of src.matchAll(/import\s*\*\s*as\s+([\w$]+)\s*from\s*["']([^"']+)["']/g)) {
      const [, alias, spec] = m;
      if (!local(spec)) continue;
      const target = resolve(file, spec);
      if (!text.has(target)) continue;
      const has = exportsOf(text.get(target));
      const used = new RegExp(`\\b${alias}\\.([\\w$]+)`, "g");
      /* without this the specifier of the import itself matches: `./native.js`
         reads as native.js, a member called `js` that nothing exports */
      for (const u of body(src).matchAll(used))
        if (!has.has(u[1]))
          broken.push(`${alias}.${u[1]} — ${spec} has no such export  (${file.pathname.split("/").pop()})`);
    }
  }
  assert.deepEqual(broken, [], "namespace members with nothing behind them:\n  " + broken.join("\n  "));
});

/* The guard above only helps if the build refuses too: the suite is not what
   produces an installer. */
test("the bundler is told to fail on it rather than warn", () => {
  const conf = readFileSync(new URL("../vite.config.js", import.meta.url), "utf8");
  assert.ok(existsSync(new URL("../vite.config.js", import.meta.url)));
  assert.match(conf, /MISSING_EXPORT/, "rollup's warning has to be fatal, not yellow");
  assert.match(conf, /throw new Error/);
});
