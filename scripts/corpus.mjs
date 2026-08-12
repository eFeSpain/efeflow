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
 *   node scripts/corpus.mjs fetch [--pages N]   search GitHub, cache to .corpus/
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
   flavour of file. Each names something only a real ruleset would carry.
 *
 * The first ten found what people write most: hooks, conntrack, counters. The
 * rest name the parts of nftables this parser has the least evidence about,
 * which is where the next defect is — a corpus assembled out of what somebody
 * thought to search for contains what they thought of, and that bias is the
 * thing to attack deliberately.
 *
 * The families matter as much as the statements. Almost every ruleset on
 * GitHub is `inet` or `ip`; `bridge`, `netdev` and `arp` are rare and are
 * exactly where a parser that assumed two families would fall over. */
const QUERIES = [
  /* what everyone writes */
  '"hook input priority" extension:nft',
  '"hook prerouting priority" extension:nft',
  '"table inet" "counter" extension:nft',
  '"ct state" "jump" extension:nft',
  '"nft -f" filename:nftables.conf',
  '"type filter hook" filename:nftables.conf',
  '"meta l4proto" extension:nft',
  '"add rule" "handle" extension:nft',
  /* the other families */
  '"table bridge" extension:nft',
  '"table netdev" extension:nft',
  '"table arp" extension:nft',
  '"hook ingress" "device" extension:nft',
  /* statements this parser has the least evidence about */
  '"flowtable" "hook ingress" extension:nft',
  '"synproxy" extension:nft',
  '"secmark" extension:nft',
  '"tproxy to" extension:nft',
  '"numgen" extension:nft',
  '"jhash" extension:nft',
  '"fib daddr" extension:nft',
  '"osf name" extension:nft',
  '"queue num" extension:nft',
  '"dup to" extension:nft',
  '"meta mark set" extension:nft',
  '"vmap" "dport" extension:nft',
  '"typeof" "set" extension:nft',
  '"ct helper" extension:nft',
  '"quota over" extension:nft',
  '"flags dynamic" extension:nft',
  '"limit rate over" extension:nft',
  '"socket" "transparent" extension:nft',
  '"rt mtu" extension:nft',
  '"iifgroup" extension:nft',
  '"log prefix" "group" extension:nft',
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

async function fetchCorpus(pages) {
  const tok = token();
  mkdirSync(CACHE, { recursive: true });
  const seen = new Set(readdirSync(CACHE).map((f) => f));
  let added = 0, skipped = 0, asked = 0;

  /* Code search allows ten requests a minute and caps any one query at a
     thousand results however many pages are asked for — so the ceiling is the
     query list, not the paging. Seven seconds between requests is simpler than
     reading the rate headers and getting it slightly wrong. */
  const wait = () => new Promise((r) => setTimeout(r, 7000));

  for (const q of QUERIES) {
    let kept = 0;
    for (let page = 1; page <= pages; page++) {
      if (asked++) await wait();
      let hits;
      try {
        hits = await api(`https://api.github.com/search/code?q=${encodeURIComponent(q)}&per_page=100&page=${page}`, tok);
      } catch (e) {
        console.log(`  ${q} p${page}: ${e.message}`);
        break;
      }
      if (!(hits.items || []).length) break;
      const before = added;
      await keepAll(hits.items, seen, () => added++, () => skipped++);
      kept += added - before;
      if (hits.items.length < 100) break;      /* the last page of this query */
    }
    console.log(`  ${String(kept).padStart(3)} new   ${q}`);
  }
  console.log(`\n  ${added} new, ${skipped} already had, ${readdirSync(CACHE).filter((f) => !f.startsWith("_")).length} in the corpus\n`);
}

async function keepAll(items, seen, onAdd, onSkip) {
  for (const it of items) {
    /* one name per repo+path, flattened so the cache is a flat directory */
    const name = `${it.repository.full_name}__${it.path}`.replace(/[^\w.-]+/g, "_");
    if (seen.has(name)) { onSkip(); continue; }
    seen.add(name);                    /* asked for once, whatever comes back */
    try {
      const raw = `https://raw.githubusercontent.com/${it.repository.full_name}/${it.repository.default_branch || "HEAD"}/${it.path}`;
      const r = await fetch(raw, { headers: { "User-Agent": "efeflow" } });
      if (!r.ok) continue;
      const text = await r.text();
      /* a file that names no table and no chain is not a ruleset, whatever its
         extension says — templates and fragments are most of the noise */
      if (!/^\s*table\s+\S+/m.test(text) || !/\bchain\b/.test(text)) continue;
      if (text.length > 400_000) continue;
      writeFileSync(join(CACHE, name), text);
      onAdd();
    } catch { /* a file that will not download is not a finding */ }
  }
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
                             { encoding: "utf8", maxBuffer: 256 * 1024 * 1024, timeout: 3_600_000 });
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

  /* Why a file is not reproduced whole, which is a different question from
     which line it was. Two of the reasons are the parser doing exactly what it
     should and are expected to stay: a ruleset that declares one table in nine
     blocks comes back as one block, and a ruleset with a `flush ruleset` in the
     middle of it comes back without the firewall the kernel would have thrown
     away. Both are text losses and neither is a defect, so counting them apart
     is the difference between a list to work through and a list to read. */
  const reasons = new Map();
  const reason = (text) => {
    const lines = text.split("\n");
    const firstTable = lines.findIndex((l) => /^\s*table\s/.test(l) && l.includes("{"));
    const flush = lines.findIndex((l) => /^\s*flush\s+ruleset\s*$/.test(l));
    if (firstTable >= 0 && flush > firstTable) return "a flush ruleset in the middle of the file";
    /* `table inet x {}` is a declaration of the same table as `table inet x {`.
       It is how a scoped reload is made safe — declare it so the delete under it
       cannot fail on a box that has never seen it — and counting only the second
       form left fifteen rulesets filed under "look at this one" when what they
       are is a table declared twice. */
    const decls = lines.map((l) => l.trim().replace(/\{\s*\}$/, "{"))
                       .filter((l) => /^(table|chain|set|map)\s+\S+.*\{$/.test(l));
    if (decls.length !== new Set(decls).size) return "a table or chain declared more than once";
    return "something else — look at this one";
  };
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
    else {
      const r = reason(text);
      const b = reasons.get(r) || { n: 0, files: [] };
      b.n++;
      if (b.files.length < 3) b.files.push(f);
      reasons.set(r, b);
    }
  }

  console.log(`\n── ${checked} rulesets${withNft ? ` (${invalid} nft itself refuses, left out)` : ""} ──\n`);
  console.log(`  ${clean} reproduced entirely · ${totalLines - lostLines}/${totalLines} lines (${(100 * (totalLines - lostLines) / totalLines).toFixed(1)}%)\n`);

  if (reasons.size) {
    console.log(`  ${checked - clean} not reproduced whole, and why:\n`);
    for (const [r, b] of [...reasons].sort((a, c) => c[1].n - a[1].n))
      console.log(`  ${String(b.n).padStart(4)} × ${r}\n         ${b.files.join("\n         ")}`);
    console.log();
  }

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
      #
      # And the clock, for the same reason. A set element with a timeout is
      # listed with the time it has left — 'timeout 5m expires 4m59s996ms' —
      # which is four milliseconds of the kernel doing its job, measured from
      # whenever the load happened. Two loads are never at the same instant, so
      # without this a ruleset with a timeout can never compare equal to itself.
      norm() {
        sed -E -e 's/counter packets [0-9]+ bytes [0-9]+/counter/g' \\
               -e 's/ expires [0-9a-z]+//g'
      }
      a=$(unshare -rn sh -c '/usr/sbin/nft -f "$1" >/dev/null 2>&1 && /usr/sbin/nft list ruleset' sh "$f" 2>/dev/null | norm)
      b=$(unshare -rn sh -c '/usr/sbin/nft -f "$1" >/dev/null 2>&1 && /usr/sbin/nft list ruleset' sh "$2/$n" 2>/dev/null | norm)
      if [ -z "$b" ]; then printf 'REFUSED\\t%s\\n' "$n"
      elif [ "$a" = "$b" ]; then ok=$((ok+1)); printf 'SAME\\t%s\\n' "$n"
      else bad=$((bad+1)); printf 'MOVED\\t%s\\n' "$n"; fi
    done
    printf 'TOTALS\\t%s\\t%s\\n' "$ok" "$bad"`;
  const wp = (p) => execFileSync("wsl", ["wslpath", "-a", p.replace(/\\/g, "/")], { encoding: "utf8" }).trim();
  const out = execFileSync("wsl", ["-e", "sh", "-c", script, "sh", wp(CACHE), wp(mine)],
                           { encoding: "utf8", maxBuffer: 256 * 1024 * 1024, timeout: 5_400_000 });

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
if (cmd === "fetch") {
  /* GitHub caps a query at a thousand results, so ten pages is the ceiling
     and asking for more only costs requests. */
  const n = +(process.argv[process.argv.indexOf("--pages") + 1] || 0);
  await fetchCorpus(process.argv.includes("--pages") && n > 0 ? Math.min(n, 10) : 1);
}
else if (cmd === "kernel") await kernel();
else if (cmd === "run") await run(process.argv.includes("--nft"));
else console.log(`
  node scripts/corpus.mjs fetch        search GitHub, cache to .corpus/
  node scripts/corpus.mjs run          parse and verify what is cached
  node scripts/corpus.mjs run --nft    and only count files nft itself accepts
`);
