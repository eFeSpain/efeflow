/* The README's test count, held to the suite that just ran.
 *
 * Both READMEs quote the number of automated checks as evidence, twice each,
 * and the number drifted three times in one week — 892, 987, 1,020 — each
 * time noticed by a person, after the fact. A contract test cannot hold this:
 * a test inside the run cannot know the run's final count, and counting
 * `test(` calls statically misses the ones made in loops — measured before
 * this was written: ten files register 842 literals and run 1,023 tests.
 *
 * So the check rides the runner itself. node --test accepts more than one
 * reporter; this one consumes the same event stream the summary is printed
 * from, counts what the summary counts, and at the end compares it with what
 * the READMEs claim. A new test now fails `npm test` until the READMEs tell
 * the truth about it — which turns drift from a thing somebody notices into a
 * thing nobody can miss.
 *
 * Enforced only when the run was the whole suite. The runner hides the CLI
 * from a reporter — argv arrives rewritten — but two things survive: the
 * filter flags stay visible in process.execArgv, and every event names the
 * file it came from. So the gate is evidence, not invocation: no filter
 * flags, and every test file on disk seen in the stream. A single file, a
 * subset, a --test-name-pattern run all count fewer tests and prove nothing
 * about the claim, and all of them leave the gate closed.
 */
import { readFileSync, readdirSync } from "node:fs";
import { basename } from "node:path";

const CLAIMS = [
  ["README.md",    /([\d,]+) automated assertions/, (n) => n.toLocaleString("en-US")],
  ["README.md",    /# ([\d,]+) assertions/,         (n) => n.toLocaleString("en-US")],
  ["README.es.md", /([\d.]+) comprobaciones autom/, (n) => n.toLocaleString("de-DE")],
  ["README.es.md", /# ([\d.]+) aserciones/,         (n) => n.toLocaleString("de-DE")],
];

export default async function* readmeCount(source) {
  let ran = 0;
  const seen = new Set();
  for await (const e of source) {
    if ((e.type === "test:pass" || e.type === "test:fail")
        && e.data?.details?.type !== "suite") {
      ran++;
      if (e.data?.file) seen.add(basename(e.data.file));
    }
  }

  const filtered = process.execArgv.some((a) =>
    a.startsWith("--test-name-pattern") || a.startsWith("--test-skip-pattern") || a === "--test-only");
  if (filtered || ran === 0) return;
  const every = readdirSync(new URL("./", import.meta.url))
    .filter((f) => f.endsWith(".test.js"));
  if (!every.every((f) => seen.has(f))) return;   /* a subset proves nothing */

  const wrong = [];
  for (const [file, re, fmt] of CLAIMS) {
    const text = readFileSync(new URL("../" + file, import.meta.url), "utf8");
    const m = text.match(re);
    if (!m) { wrong.push(`  ${file}: nothing matches ${re} — the claim moved or vanished`); continue; }
    const said = +m[1].replace(/[,.]/g, "");
    if (said !== ran)
      wrong.push(`  ${file}: says ${m[1]}, the suite ran ${ran} — make it ${fmt(ran)}`);
  }
  if (wrong.length) {
    process.exitCode = 1;
    yield `\n✖ the README quotes a test count the suite no longer has:\n${wrong.join("\n")}\n`
        + `  (four claims, two per language — all must say ${ran})\n`;
  }
}
