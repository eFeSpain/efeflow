/* Real rulesets, written by people who have never heard of this parser.
 *
 * The samples in this repository were written to be parsed. Every fixture in
 * test/ was written next to the code it tests. That is a corpus with a bias in
 * it the size of a house: it contains the syntax somebody thought of, which is
 * exactly the syntax that works.
 *
 * nftables' grammar is enormous and most of it is never written by hand. This
 * fetches what people actually committed to public repositories and asks two
 * questions of each file:
 *
 *   does parseNft leave any line unread?
 *   does verify() reproduce every line it did read?
 *
 * And a third, which decides whether an answer means anything: does nft itself
 * accept the file? A ruleset nft refuses is not evidence about this parser. On
 * a machine with nft — WSL counts — that check runs in a network namespace so
 * nothing touches the host's firewall.
 *
 *   node scripts/corpus.mjs fetch     search GitHub, cache to .corpus/
 *   node scripts/corpus.mjs run       parse and verify everything cached
 *   node scripts/corpus.mjs run --nft also ask nft whether each file is valid
 *
 * The corpus is other people's code and is not committed: .corpus/ is ignored.
 * What comes back into the repository is a minimal reproduction of each shape
 * that broke, written from scratch, as an ordinary test.
 */
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "..");
const CACHE = join(repo, ".corpus");

/* ── fetching ───────────────────────────────────────────────────────────── */

/* Several queries rather than one, because a single one returns a single
   flavour of file. Each names something only a real ruleset would carry. */
const QUERIES = [
  '"hook input priority" extension:nft',
  '"hook prerouting priority" extension:nft',
  '"table inet" "counter" extension:nft',
  '"flowtable" "hook ingress" extension:nft',
  '"ct state" "jump" extension:nft',
  '"nft -f" filename:nftables.conf',
  '"type filter hook" filename:nftables.conf',
  '"meta l4proto" extension:nft',
  '"vmap" "dport" extension:nft',
  '"add rule" "handle" extension:nft',
];

const token = () => {
  const out = execFileSync("git", ["credential", "fill"], {
    input: "protocol=https\nhost=github.com\n\n", encoding: "utf8",
  });
  const m = out.match(/^password=(.*)$/m);
  if (!m) throw new Error("no github credential to search with");
  return m[1];
};

const api = async (url, tok) => {
  const r = await fetch(url, {
    headers: { Authorization: `Bearer ${tok}`, "User-Agent": "efeflow", Accept: "application/vnd.github+json" },
  });
  if (!r.ok) throw new Error(`${r.status} ${r.statusText} for ${url}`);
  return r.json();
};

async function fetchCorpus() {
  const tok = token();
  mkdirSync(CACHE, { recursive: true });
  const seen = new Set(readdirSync(CACHE).map((f) => f));
  let added = 0, skipped = 0;

  for (const [i, q] of QUERIES.entries()) {
    /* code search allows ten a minute; a whole minute between them is simpler
       than reading the headers and getting it slightly wrong */
    if (i) await new Promise((r) => setTimeout(r, 7000));
    process.stdout.write(`  ${q}\n`);
    let hits;
    try {
      hits = await api(`https://api.github.com/search/code?q=${encodeURIComponent(q)}&per_page=100`, tok);
    } catch (e) {
      console.log(`    skipped: ${e.message}`);
      continue;
    }
    for (const it of hits.items || []) {
      /* one name per repo+path, flattened so the cache is a flat directory */
      const name = `${it.repository.full_name}__${it.path}`.replace(/[^\w.-]+/g, "_");
      if (seen.has(name)) { skipped++; continue; }
      try {
        const raw = `https://raw.githubusercontent.com/${it.repository.full_name}/${it.repository.default_branch || "HEAD"}/${it.path}`;
        const r = await fetch(raw, { headers: { "User-Agent": "efeflow" } });
        if (!r.ok) continue;
        const text = await r.text();
        /* a file that names no table and no chain is not a ruleset, whatever
           its extension says — templates and fragments are most of the noise */
        if (!/^\s*table\s+\S+/m.test(text) || !/\bchain\b/.test(text)) continue;
        if (text.length > 400_000) continue;
        writeFileSync(join(CACHE, name), text);
        seen.add(name);
        added++;
      } catch { /* a file that will not download is not a finding */ }
    }
    console.log(`    ${added} kept so far`);
  }
  console.log(`\n  ${added} new, ${skipped} already had, ${readdirSync(CACHE).length} in the corpus\n`);
}

/* ── running ────────────────────────────────────────────────────────────── */

/** Which of the cached files nft itself accepts.
 *
 * Asked in one crossing rather than one per file: a corpus scraped off GitHub
 * is mostly templates — `policy $OUT_POLICY`, Ansible loops, shell here-docs —
 * and a file nft refuses says nothing about this parser. Without this filter
 * the count measures how much Jinja is on GitHub.
 *
 * Each check runs in a network namespace of its own, so nothing here can touch
 * the firewall of the machine running it.
 */
function nftAcceptable() {
  const script = `
    cd "$1" || exit 1
    for f in *; do
      [ -f "$f" ] || continue
      if unshare -rn /usr/sbin/nft -c -f "$f" >/dev/null 2>&1; then printf '%s\\n' "$f"; fi
    done`;
  try {
    const wslPath = execFileSync("wsl", ["wslpath", "-a", CACHE.replace(/\\/g, "/")], { encoding: "utf8" }).trim();
    const out = execFileSync("wsl", ["-e", "sh", "-c", script, "sh", wslPath],
                             { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, timeout: 900_000 });
    return new Set(out.split("\n").map((s) => s.trim()).filter(Boolean));
  } catch (e) {
    console.log(`  could not ask nft (${String(e.message).split("\n")[0]}) — counting every file instead`);
    return null;
  }
}

/* A diff is only useful once it is a shape rather than a line: `tcp dport 80`
   and `tcp dport 443` are one finding, not two. */
const shapeOf = (line) => String(line)
  .replace(/"[^"]*"/g, '"…"')
  .replace(/\b\d+(\.\d+){3}(\/\d+)?\b/g, "A.B.C.D")
  .replace(/\b[0-9a-f]{0,4}(:[0-9a-f]{0,4}){2,}\b/gi, "V6")
  .replace(/\b\d+\b/g, "N")
  .replace(/\s+/g, " ")
  .trim()
  .slice(0, 130);

async function run(withNft) {
  const { parseNft, verify } = await import("../src/core/parse.js");
  if (!existsSync(CACHE)) { console.log("  nothing fetched yet — run `fetch` first\n"); return; }
  const files = readdirSync(CACHE)
    .filter((f) => !f.startsWith("_") && statSync(join(CACHE, f)).isFile());

  const buckets = new Map();          /* shape -> {n, example, files:Set} */
  const bump = (kind, line, file) => {
    const key = kind + "|" + shapeOf(line);
    const b = buckets.get(key) || { kind, shape: shapeOf(line), n: 0, files: new Set(), example: line };
    b.n++; b.files.add(file);
    buckets.set(key, b);
  };

  const acceptable = withNft ? nftAcceptable() : null;
  let clean = 0, invalid = 0, checked = 0, totalLines = 0, lostLines = 0;
  for (const f of files) {
    const text = readFileSync(join(CACHE, f), "utf8");
    if (acceptable && !acceptable.has(f)) { invalid++; continue; }
    checked++;
    let v;
    try { v = verify(text); } catch (e) { bump("threw", e.message, f); continue; }
    totalLines += v.total;
    lostLines += v.diffs.length;
    for (const e of parseNft(text).errors) bump("unparsed", e.line, f);
    /* A line we invented is bucketed by what we wrote, not by the nothing it
       replaced — grouping every one of them under "—" said only that they
       existed, which is the least useful thing about them. */
    for (const d of v.diffs)
      d.out === "—" ? bump("lost", d.src, f)
      : d.src === "—" ? bump("invented", d.out, f)
      : bump("changed", `${d.src}   ⇢   ${d.out}`, f);
    if (!v.diffs.length) clean++;
  }

  console.log(`\n── ${checked} rulesets${withNft ? ` (${invalid} nft itself refuses, left out)` : ""} ──\n`);
  console.log(`  ${clean} reproduced entirely · ${totalLines - lostLines}/${totalLines} lines (${(100 * (totalLines - lostLines) / totalLines).toFixed(1)}%)\n`);

  const worst = [...buckets.values()].sort((a, b) => b.n - a.n);
  console.log(`  ${worst.length} distinct shapes we do not reproduce, commonest first:\n`);
  for (const b of worst.slice(0, 30))
    console.log(`  ${String(b.n).padStart(4)} × [${b.kind}] ${b.shape}`);
  if (worst.length > 30) console.log(`       … and ${worst.length - 30} more`);
  console.log();

  writeFileSync(join(CACHE, "_findings.json"),
    JSON.stringify(worst.map((b) => ({ ...b, files: [...b.files].slice(0, 3) })), null, 1));
  console.log(`  the whole list is in .corpus/_findings.json\n`);
}

/* ── asking the kernel instead of the text ───────────────────────────────
 *
 * `run` compares two pieces of text, and text is the wrong authority. A file
 * that came back differently written may have lost nothing at all, and a file
 * whose text matched exactly could have lost everything and said nothing.
 *
 * So: load the original into an empty netfilter instance and list it back;
 * load our re-emission the same way and list that back. Both listings are
 * nft's own canonical form, so comparing them asks whether the round trip
 * changed what the ruleset *means*. That is the question, and it is the only
 * one whose answer is not our own opinion.
 *
 * scripts/differ.mjs does exactly this and is the tool for it — but it needs
 * node on the machine that has nft, and WSL here has none. So the JavaScript
 * stays on this side, the two loads happen in one crossing, and each of them
 * is inside a network namespace of its own that did not exist a moment before.
 */
async function kernel() {
  const { parseNft } = await import("../src/core/parse.js");
  const { generate } = await import("../src/core/generate.js");
  const files = readdirSync(CACHE).filter((f) => !f.startsWith("_") && statSync(join(CACHE, f)).isFile());
  const acceptable = nftAcceptable();
  if (!acceptable) { console.log("  no nft to ask\n"); return; }

  const mine = join(CACHE, "_reemit");
  mkdirSync(mine, { recursive: true });
  const pairs = [];
  for (const f of files) {
    if (!acceptable.has(f)) continue;
    try {
      writeFileSync(join(mine, f), generate(parseNft(readFileSync(join(CACHE, f), "utf8"))).join("\n") + "\n");
      pairs.push(f);
    } catch (e) { console.log(`  ${f}: generate threw — ${String(e.message).split("\n")[0]}`); }
  }

  /* One crossing. `list ruleset` without -a, because handles are the kernel's
     to hand out and comparing them would be comparing load order, not meaning. */
  const script = `
    ok=0; bad=0
    for f in "$1"/*; do
      [ -f "$f" ] || continue
      n="$(basename "$f")"
      [ -f "$2/$n" ] || continue
      # Counters are runtime state, not policy: a file that came out of a
      # ruleset listing carries real packet counts, and putting them back into
      # a fresh kernel would be restoring somebody traffic they never had. A
      # bare counter is the right thing to emit, so this is not a difference.
      # differ.mjs has always normalised them; this had not, and called six
      # rulesets changed in meaning over a number nobody should restore.
      norm() { sed -E 's/counter packets [0-9]+ bytes [0-9]+/counter/g'; }
      a=$(unshare -rn sh -c '/usr/sbin/nft -f "$1" >/dev/null 2>&1 && /usr/sbin/nft list ruleset' sh "$f" 2>/dev/null | norm)
      b=$(unshare -rn sh -c '/usr/sbin/nft -f "$1" >/dev/null 2>&1 && /usr/sbin/nft list ruleset' sh "$2/$n" 2>/dev/null | norm)
      if [ -z "$b" ]; then printf 'REFUSED\\t%s\\n' "$n"
      elif [ "$a" = "$b" ]; then ok=$((ok+1)); printf 'SAME\\t%s\\n' "$n"
      else bad=$((bad+1)); printf 'MOVED\\t%s\\n' "$n"; fi
    done
    printf 'TOTALS\\t%s\\t%s\\n' "$ok" "$bad"`;
  const wp = (p) => execFileSync("wsl", ["wslpath", "-a", p.replace(/\\/g, "/")], { encoding: "utf8" }).trim();
  const out = execFileSync("wsl", ["-e", "sh", "-c", script, "sh", wp(CACHE), wp(mine)],
                           { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, timeout: 1_800_000 });

  const rows = out.split("\n").map((l) => l.split("\t")).filter((r) => r[0]);
  const same = rows.filter((r) => r[0] === "SAME").map((r) => r[1]);
  const moved = rows.filter((r) => r[0] === "MOVED").map((r) => r[1]);
  const refused = rows.filter((r) => r[0] === "REFUSED").map((r) => r[1]);

  console.log(`\n── ${pairs.length} rulesets, put through the kernel twice ──\n`);
  console.log(`  ${same.length} the kernel cannot tell apart from the original`);
  console.log(`  ${moved.length} whose meaning moved`);
  console.log(`  ${refused.length} where nft refused what we wrote\n`);
  for (const f of [...refused, ...moved].slice(0, 20))
    console.log(`  ${refused.includes(f) ? "REFUSED" : "MOVED  "}  ${f.slice(0, 68)}`);
  writeFileSync(join(CACHE, "_kernel.json"), JSON.stringify({ same, moved, refused }, null, 1));
  console.log(`\n  the lists are in .corpus/_kernel.json\n`);
}

const cmd = process.argv[2];
if (cmd === "fetch") await fetchCorpus();
else if (cmd === "kernel") await kernel();
else if (cmd === "run") await run(process.argv.includes("--nft"));
else console.log(`
  node scripts/corpus.mjs fetch        search GitHub, cache to .corpus/
  node scripts/corpus.mjs run          parse and verify what is cached
  node scripts/corpus.mjs run --nft    and only count files nft itself accepts
`);
