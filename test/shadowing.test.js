import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

/* `t` is the translation helper and it is used everywhere, including inside
   callbacks. A parameter of the same name shadows it, and the call site then
   throws only when that path runs — which is how the packet simulator stayed
   broken through a green test suite. Cheap to check, so check it. */

const SHADOWED = ["t", "$", "$$", "el", "esc", "generate", "analyse", "evaluate", "packet"];

const sources = ["src/app.js", "src/main.js", "src/i18n.js", "src/native.js"];

for (const file of sources) {
  test(`${file} does not shadow shared helpers`, () => {
    const src = readFileSync(new URL(`../${file}`, import.meta.url), "utf8");
    const offenders = [];

    // arrow params: (a, t, b) =>   /  t =>
    const arrow = /\(([^()]{0,120}?)\)\s*=>|(?:^|[^.\w])([A-Za-z_$][\w$]*)\s*=>/g;
    // function params: function foo(a, t)
    const fn = /function\s*[\w$]*\s*\(([^()]{0,160}?)\)/g;

    const scan = (params, index) => {
      for (const raw of params.split(",")) {
        const name = raw.split("=")[0].replace(/[{}[\].\s]/g, "").trim();
        if (SHADOWED.includes(name)) {
          offenders.push({ name, line: src.slice(0, index).split("\n").length });
        }
      }
    };

    let m;
    while ((m = arrow.exec(src))) {
      if (m[1] !== undefined) scan(m[1], m.index);
      else if (m[2] !== undefined) scan(m[2], m.index);
    }
    while ((m = fn.exec(src))) scan(m[1], m.index);

    assert.deepEqual(
      offenders,
      [],
      "shared helpers shadowed by parameters:\n" +
        offenders.map((o) => `  ${file}:${o.line} shadows \`${o.name}\``).join("\n"),
    );
  });
}
