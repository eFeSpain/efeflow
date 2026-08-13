/* What 268 real rulesets said about this parser.
 *
 * Every fixture in this repository was written beside the code it tests, which
 * is a corpus with a bias the size of a house in it: it holds the syntax
 * somebody thought of, and that is exactly the syntax that works. So
 * `scripts/corpus.mjs` fetches what people committed to public repositories,
 * keeps only the files nft itself accepts — two of every four turned out to be
 * templates full of `$VARIABLES` and Jinja — and asks whether we can read them
 * and write them back.
 *
 * These are the findings that mattered, each reduced to the smallest case that
 * shows it. The corpus itself is not committed: it is other people's code, and
 * a test that needs a download is a test that fails on a train.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { parseNft, verify, roundTrip } from "../src/core/parse.js";
import { generate } from "../src/core/generate.js";

const chain = (header, body = "\t\tct state established,related accept") =>
  `table inet filter {\n\tchain input {\n\t\t${header}\n${body}\n\t}\n}`;

/* ── the one that mattered ───────────────────────────────────────────────
 *
 * nft prints a chain header with a semicolon and accepts one without. A
 * hand-written config very often has none, and it was one of the commonest
 * shapes in the corpus. Without it the line matched no branch at all: `hook`
 * stayed null and `type` fell back to "regular", so a base chain quietly
 * became an ordinary one.
 *
 * That is not a formatting loss. A chain with no hook is attached to nothing:
 * netfilter never calls it, the simulator never walks it, the canvas never
 * puts it on the packet's path — and the ruleset that comes back out has an
 * input chain that is not an input chain, which nft will load without a word
 * of complaint. The policy went with it, so `policy drop` came back as the
 * `accept` nft applies when nothing says otherwise.
 */
test("a chain header is a chain header without its semicolon", () => {
  for (const header of [
    "type filter hook input priority filter;",
    "type filter hook input priority filter",
    "type filter hook input priority 0",
    "type filter hook input priority filter + 10",
  ]) {
    const ch = parseNft(chain(header)).chains[0];
    assert.equal(ch.hook, "input", `${header}: the chain is not attached to a hook`);
    assert.equal(ch.type, "filter", `${header}: it stopped being a base chain`);
  }
});

test("and a policy on its own line reaches the ruleset that comes out", () => {
  const m = parseNft(chain("type filter hook input priority filter\n\t\tpolicy drop"));
  assert.equal(m.chains[0].policy, "drop", "the policy was read");
  const header = generate(m).find((l) => /hook input/.test(l));
  assert.match(header, /policy drop/,
    "a firewall that drops by default came back out accepting by default");
});

test("a netdev chain keeps its device without one too", () => {
  const ch = parseNft(chain('type filter hook ingress device "eth0" priority -500')).chains[0];
  assert.equal(ch.hook, "ingress");
  assert.equal(ch.dev, 'device "eth0"');
});

/* ── and what the round-trip was calling a loss ──────────────────────────
 *
 * The check compares what a file says against what we would write. nft prints
 * `type … priority …; policy …;` on one line; people write two, and leave the
 * policy out because accept is the default. Both load and both mean the same
 * thing, and this was counted as two losses per chain — then a third and a
 * fourth as the line-by-line comparison slipped a row and reported the
 * neighbours. Across the corpus it accounted for roughly four hundred of five
 * hundred and forty-six reported losses: files that had been understood
 * perfectly, telling their authors they had not been.
 */
test("a chain header split across lines is not a line we lost", () => {
  const split = verify(chain("type filter hook input priority filter\n\t\tpolicy drop"));
  assert.deepEqual(split.diffs, [], JSON.stringify(split.diffs));

  const bare = verify(chain("type filter hook input priority filter"));
  assert.deepEqual(bare.diffs, [], "a header with no policy at all is nft's default, not a loss");
});

test("but a policy we got wrong is still a difference", () => {
  /* the fold may not become a way of not noticing */
  const m = parseNft(chain("type filter hook input priority filter\n\t\tpolicy drop"));
  m.chains[0].policy = "accept";
  const out = generate(m).find((l) => /hook input/.test(l));
  assert.match(out, /policy accept/);
  assert.doesNotMatch(out, /policy drop/,
    "the check must still see a policy that changed under it");
});

/* ── a rule continued onto the next line ─────────────────────────────────
 *
 * A trailing backslash continues a line, and nft reads the pair as one rule.
 * Seventy-one of the five hundred and thirty-four rulesets fetched wrote at
 * least one that way — four hundred and ten lines between them — usually to
 * put the comment on a line of its own:
 *
 *     iifname lo accept \
 *     comment "Accept any localhost traffic"
 *
 * Read as two, the rule lost its comment and the comment became a line that
 * parsed as nothing, and everything after it in the chain shifted. It was why
 * the worst file in the corpus came back at 71%.
 */
test("a backslash at the end of a line continues it", () => {
  const text = [
    "table inet filter {",
    "\tchain input {",
    "\t\ttype filter hook input priority 0; policy drop;",
    "\t\tiifname lo accept \\",
    '\t\tcomment "Accept any localhost traffic"',
    "\t\ttcp dport { 80, 443 } \\",
    "\t\t\tcounter accept",
    "\t}",
    "}",
  ].join("\n");

  const m = parseNft(text);
  const rules = m.chains[0].rules;
  assert.equal(rules.length, 2, "the continuations were read as rules of their own");
  assert.equal(rules[0].expr, "iifname lo");
  assert.equal(rules[0].verdict, "accept");
  assert.equal(rules[0].cmt, "Accept any localhost traffic",
    "the comment was on the next line, and belongs to the rule above it");
  assert.equal(rules[1].expr, "tcp dport { 80, 443 }");
  assert.equal(rules[1].ctr, true, "the counter was on the continued half");
  assert.deepEqual(m.errors, [], "a continuation line parses as nothing on its own");
});

/* ── the four the kernel found ────────────────────────────────────────────
 *
 * Comparing text can only say a file came back written differently. Loading
 * both into an empty netfilter instance and listing them back asks whether it
 * came back *meaning* differently, which is the question. `npm run corpus
 * kernel` does that; these are what it found, and all four produced either a
 * file nft refuses or a firewall that is not the one in the file.
 */

/* A braced list wrapped across lines was read as a block, so the rule's entire
   match went with it and the rule became a bare `accept` — which accepts
   everything. The braces then came back out at table level, where nft refuses
   them. A firewall opened silently, in a file that would not load. */
test("a value list wrapped across lines stays part of its rule", () => {
  const m = parseNft([
    "table inet filter {",
    "\tchain input {",
    "\t\ttype filter hook input priority filter; policy drop;",
    "\t\ticmp type {",
    "\t\t\techo-request,",
    "\t\t\tdestination-unreachable",
    "\t\t} accept",
    "\t}",
    "}",
  ].join("\n"));

  assert.equal(m.chains.length, 1, "the braces were read as a chain of their own");
  const r = m.chains[0].rules;
  assert.equal(r.length, 1);
  assert.match(r[0].expr, /icmp type \{ echo-request, destination-unreachable \}/,
    "the rule lost its match and became a bare verdict");
  assert.equal(r[0].verdict, "accept");
  assert.deepEqual(parseNft(generate(m).join("\n")).chains[0].rules[0].expr, r[0].expr,
    "and it survives being written out and read again");
});

/* `flush table inet x` fails on a table that does not exist, and takes the
   whole file with it. The idiom is to declare it empty first; the declaration
   lived above the flush and everything in the prelude is emitted before any
   table, so the flush was left with nothing to flush. */
test("a flush of a table is preceded by something that creates it", () => {
  const src = [
    "table inet x {",
    "}",
    "flush table inet x",
    "table inet x {",
    "\tchain input {",
    "\t\ttype filter hook input priority filter; policy accept;",
    "\t\ttcp dport 22 accept",
    "\t}",
    "}",
  ].join("\n");
  const out = generate(parseNft(src)).join("\n");
  const flush = out.indexOf("flush table inet x");
  const decl = out.indexOf("table inet x\n");
  assert.ok(flush > 0, "somebody's flush was dropped");
  assert.ok(decl >= 0 && decl < flush,
    "nothing creates the table the flush is about, so nft refuses the file");
});

/* A chain declared twice is one chain, which is how a long ruleset gets split
   across blocks or files. Read as two, we emitted the name twice — the second
   time with a hook — and nft refused it. */
test("a chain declared twice is one chain", () => {
  const m = parseNft([
    "table inet filter {",
    "\tchain input {",
    "\t\ttcp dport 22 accept",
    "\t}",
    "}",
    "table inet filter {",
    "\tchain input {",
    "\t\ttype filter hook input priority filter; policy drop;",
    "\t\ttcp dport 443 accept",
    "\t}",
    "}",
  ].join("\n"));

  const inputs = m.chains.filter((c) => c.id === "input" && c.table === "inet filter");
  assert.equal(inputs.length, 1, "two chains of one name is a file nft will not load");
  assert.equal(inputs[0].hook, "input", "the header from the second block reached it");
  assert.equal(inputs[0].policy, "drop");
  assert.deepEqual(inputs[0].rules.map((r) => r.expr), ["tcp dport 22", "tcp dport 443"],
    "and both blocks' rules are there, in the order the file gives them");
});

/* `flush ruleset` in the middle of a file is not decoration: everything above
   it is gone by the time the kernel reaches it. One ruleset in the corpus was
   two firewalls pasted together, and reading them as a union produced five
   rules the kernel would never have loaded. Drawing a firewall nobody is
   running is the worst thing this application can do. */
test("a flush in the middle of a file discards what came before it", () => {
  const m = parseNft([
    "table inet old {",
    "\tchain input {",
    "\t\ttype filter hook input priority filter; policy accept;",
    "\t\ttcp dport 23 accept",
    "\t}",
    "}",
    "",
    "flush ruleset",
    "",
    "table inet new {",
    "\tchain input {",
    "\t\ttype filter hook input priority filter; policy drop;",
    "\t\ttcp dport 22 accept",
    "\t}",
    "}",
  ].join("\n"));

  assert.deepEqual(m.chains.map((c) => c.table), ["inet new"],
    "the table above the flush is not running on that machine");
  assert.equal(m.chains[0].policy, "drop");
});

/* …but it does not reach what was never in the kernel. A `define` is nft's own
   textual substitution and an `include` is a file it reads; neither is state a
   flush can clear, and the rules below still need them. */
test("and it does not discard the defines above it", () => {
  const m = parseNft([
    'define wan = "eth0"',
    'include "/etc/nftables.d/*.nft"',
    "flush ruleset",
    "table inet filter {",
    "\tchain input {",
    "\t\ttype filter hook input priority filter; policy drop;",
    "\t\tiifname $wan accept",
    "\t}",
    "}",
  ].join("\n"));
  assert.deepEqual(m.prelude, ['define wan = "eth0"', 'include "/etc/nftables.d/*.nft"']);
});

/* ── the second batch: 3,038 rulesets, and two rulers that did not agree ──
 *
 * These two are not parser defects. Both are the round-trip *check* reporting a
 * difference between two lines that said the same thing — which is worse than
 * it sounds, because that check is the whole of the evidence the import screen
 * offers, and a number that cries wolf is a number nobody reads twice.
 */

/* One logical line can carry several counters. An anonymous chain written
   across lines is joined into one, and each branch inside it counts.
 *
 * The figures are runtime statistics and are dropped before comparing — but
 * only the first set was, so the source lost the counter of one branch and our
 * re-emission lost the counter it had lifted out and put back. Different
 * losses, one reported change, nothing actually wrong. Sixty-one of these. */
test("a rule with two counters is compared by all of them, not the first", () => {
  const v = verify(`table ip PREROUTING {
	chain RAW {
		type filter hook prerouting priority raw; policy accept;
		tcp flags syn jump {
			tcp option maxseg size 1-500 counter packets 0 bytes 0 drop
			tcp sport 0 counter packets 0 bytes 0 drop
		}
	}
}`);
  assert.deepEqual(v.diffs, [], JSON.stringify(v.diffs));
});

/* And the counters still have to be *there*. Dropping the figures must not
   drop the statement — a rule that counts and one that does not are different
   rules, and the difference is the whole reason the field exists. */
test("dropping the figures does not drop the counter", () => {
  const m = parseNft(`table ip t {
	chain c {
		tcp dport 22 counter packets 12345 bytes 999 accept
		tcp dport 80 accept
	}
}`);
  assert.deepEqual(m.chains[0].rules.map((r) => r.ctr), [true, false]);
  assert.equal(m.chains[0].rules[0].pkts, 12345, "the figures are read, just not compared");
});

/* A line we do not model comes back exactly as it was written, which is right.
   The comparison then tidied the source and not our copy of it, so the two
   disagreed about a line neither had touched: `elements={ 22, 80, }` against
   the `elements = { 22, 80 }` nft prints. Both sides go through the same mill
   now. */
test("our own output is measured with the ruler used on the source", () => {
  const v = verify(`table ip t {
	set ports {
		type inet_service
		elements={ 22, 80, }
	}
}`);
  assert.deepEqual(v.diffs, [], JSON.stringify(v.diffs));
});

/* nft prints a chain's comment above its header, not below it — asked of nft
   1.1.6 rather than assumed:
 *
 *     chain FORWARD {
 *         comment "netavark dumps its rules here"
 *         type filter hook forward priority filter; policy accept;
 *     }
 *
 * We wrote it underneath, so thirty-three chains across the corpus came back
 * with the line reported lost and then found two lines down. A set's comment
 * and a named counter's are printed where we already put them; only the chain
 * was wrong. */
test("a chain's comment is written where nft writes it", () => {
  const src = `table inet t {
	chain FORWARD {
		comment "netavark dumps its rules here"
		type filter hook forward priority filter; policy accept;
	}
}`;
  assert.deepEqual(verify(src).diffs, [], JSON.stringify(verify(src).diffs));
  const out = generate(parseNft(src));
  assert.ok(out.indexOf('\t\tcomment "netavark dumps its rules here"')
            < out.findIndex((l) => l.includes("type filter hook")),
    "the comment goes above the header");
});

/* Written the other way round — which is how nft itself prints it — it stays
   the same, and nothing else the chain carries moves above the header. */
test("and what is not a comment stays below it", () => {
  const out = generate(parseNft(`table inet t {
	chain fw {
		type filter hook forward priority filter; policy accept;
		flags offload
		comment "both"
	}
}`));
  const at = (s) => out.findIndex((l) => l.includes(s));
  assert.ok(at("comment") < at("type filter hook"), "the comment is above");
  assert.ok(at("type filter hook") < at("flags offload"), "the flags are below");
});

/* ── what the kernel said, which the text could not ─────────────────────────
 *
 * The text check compares two pieces of text and both sides of it are ours. The
 * kernel is the only judge that is not: load the original into an empty
 * netfilter instance, load our re-emission into another, and diff what nft
 * lists back. It convicted us of five things the text agreed with itself about.
 */

/* nft prints an anonymous chain across lines and will not read one back on a
   single line unless every statement in it carries a semicolon — the last one
   included. Measured on nft 1.1.6:
 *
 *     jump { tcp sport 1 drop tcp sport 2 drop }     refused
 *     jump { tcp sport 1 drop; tcp sport 2 drop }    refused
 *     jump { tcp sport 1 drop; tcp sport 2 drop; }   loads
 *
 * Lines are joined here so a rule stays one rule, and joining with spaces gave
 * the first. Thirty-odd corpus rulesets have one, every one of them printed by
 * nft itself, and the file we wrote for each was a file nft would not load. The
 * text check saw nothing: both sides were joined the same way. */
test("an anonymous chain comes back in a form nft will read", () => {
  const src = `table inet t {
	chain c {
		type filter hook input priority filter; policy accept;
		tcp flags syn jump {
			tcp option maxseg size 1-500 counter drop
			tcp sport 0 counter drop
		}
	}
}`;
  const line = generate(parseNft(src)).find((l) => l.includes("jump {"));
  assert.match(line, /jump \{ tcp option maxseg size 1-500 counter drop; tcp sport 0 counter drop; \}/);
  assert.deepEqual(verify(src).diffs, []);
});

/* A value list wrapped inside an anonymous chain is still a value list, and a
   semicolon in the middle of one is a syntax error rather than a separator. */
test("and the lists inside it are left alone", () => {
  const src = `table inet t {
	chain c {
		meta l4proto { tcp, udp } th dport 53 jump {
			ip saddr {
				127.0.0.0/8,
				172.23.0.0/16
			} counter accept
			ip6 saddr ::1 counter accept
		}
	}
}`;
  const line = generate(parseNft(src)).find((l) => l.includes("jump {"));
  assert.match(line, /ip saddr \{ 127\.0\.0\.0\/8, 172\.23\.0\.0\/16 \} counter accept;/);
  assert.deepEqual(verify(src).diffs, []);
});

/* A table name is whatever nft accepts, and `\w+` is not. `table driver-fw {`
   missed the branch that reads a table entirely: it went into the prelude
   carrying its opening brace, everything it held was read as belonging to
   nothing, and the file we wrote had a brace nothing closed. */
test("a table whose name has a hyphen in it is a table", () => {
  const m = parseNft(`table driver-fw {
	chain input {
		type filter hook input priority filter; policy drop;
		iif lo accept
	}
}`);
  assert.deepEqual(m.tables.map((t) => t.name), ["ip driver-fw"]);
  assert.deepEqual(m.prelude, [], "none of it belongs above the first table");
  assert.equal(m.chains[0].table, "ip driver-fw");
});

/* `add` is nft's default verb, so `add table x { … }` is `table x { … }`. Read
   as neither, the block was not a block and its body went to the prelude. */
test("add table and create table declare a table", () => {
  for (const verb of ["add ", "create ", ""]) {
    const m = parseNft(`${verb}table inet t {\n\tchain c {\n\t\tiif lo accept\n\t}\n}`);
    assert.deepEqual(m.tables.map((t) => t.name), ["inet t"], verb || "(no verb)");
    assert.deepEqual(m.prelude, [], verb || "(no verb)");
  }
});

/* An object body can hold a block of its own. A `tunnel` has a `geneve { … }`
   inside it, and with every `}` closing the frame the nested block ended the
   object early and came back out as a sibling — a `geneve` member of a table,
   which is not a thing nftables has. */
test("a block inside an object body stays inside it", () => {
  const src = `table netdev x {
	tunnel geneve-t {
		id 10
		ip saddr 192.168.2.10
		geneve {
			class 0x1 opt-type 0x1 data "0x12345678"
		}
	}
}`;
  const m = parseNft(src);
  assert.equal(m.objects.length, 1, JSON.stringify(m.objects.map((o) => o.kind)));
  assert.equal(m.objects[0].kind, "tunnel");
  assert.ok(m.objects[0].body.includes("geneve {"), "the nested block is part of the body");
  assert.deepEqual(verify(src).diffs, []);
});

/* Tables come back in the order the file declared them. Deriving that order
   from the members instead put every table with none of them at the end, and
   `nft list ruleset` prints tables in creation order — so an empty table
   between two full ones made the two listings differ. */
test("an empty table keeps its place among the full ones", () => {
  const out = generate(parseNft(`table ip t1 {
	chain c {
		iif lo accept
	}
}
table ip t2 {
}
table ip t3 {
	chain c {
		drop
	}
}`)).filter((l) => /^table /.test(l));
  assert.deepEqual(out, ["table ip t1 {", "table ip t2 {", "table ip t3 {"]);
});

/* And the verb is nft's spelling, not a line we failed to reproduce — the same
   argument as the family. Only the form that opens a block, though: a bare
   `add table inet t` with no brace is a top-level command, kept as written. */
test("the verb on a table declaration is not a difference", () => {
  for (const head of ["add table inet t {", "create table inet t {", "table inet t {"]) {
    const v = verify(`${head}\n\tchain c {\n\t\tiif lo accept\n\t}\n}`);
    assert.deepEqual(v.diffs, [], `${head}: ${JSON.stringify(v.diffs)}`);
  }
  const bare = verify("add table inet t\ntable inet t {\n\tchain c {\n\t\tiif lo accept\n\t}\n}");
  assert.deepEqual(bare.diffs, [], JSON.stringify(bare.diffs));
});

/* ── the last of the ways one line is written two ways ──────────────────────
 *
 * Every one of these is the round-trip check reporting a difference between two
 * spellings of the same line. None of them is a defect in what we write, and
 * each one costs the same thing when it is wrong: the percentage on the import
 * screen is the whole of the evidence this application offers about a file it
 * has just read, and one that cries wolf is one nobody reads twice.
 */
test("a line is compared by what it says, not by how it was spaced", () => {
  const cases = [
    /* a declaration written up against its brace */
    ["table ip portknock{", "\tchain c {\n\t\tiif lo accept\n\t}\n}"],
    ["set s{", null],
    /* a chain header written without the space after its semicolon */
    [null, null, `table ip t {
	chain c {
		type filter hook input priority filter;policy drop
		iif lo accept
	}
}`],
    /* a statement written up against the quoted value before it */
    [null, null, `table ip t {
	chain c {
		ct state invalid log flags skuid prefix "Invalid conntrack state: "counter drop
	}
}`],
  ];
  for (const [head, body, whole] of cases) {
    const src = whole ?? (head === "set s{"
      ? `table ip t {\n\tset s{\n\t\ttype ipv4_addr\n\t}\n}`
      : `${head}\n${body}`);
    assert.deepEqual(verify(src).diffs, [], src);
  }
});

/* The chain's comment and its header go at the top of it, in that order, which
   is where nft prints them — wherever in the body they were written. */
test("the top of a chain is the top of a chain, however it was written", () => {
  const src = `table inet filter {
	chain INPUT {
		iifname lo accept
		type filter hook input priority filter; policy drop
		comment "the one that matters"
		ct state established,related accept
	}
}`;
  assert.deepEqual(verify(src).diffs, [], JSON.stringify(verify(src).diffs));
  const out = generate(parseNft(src));
  const at = (s) => out.findIndex((l) => l.includes(s));
  assert.ok(at("comment") < at("type filter hook"), "comment first, as nft prints it");
  assert.ok(at("type filter hook") < at("iifname lo"), "then the header, then the rules");
});

/* A regular chain has no header and still has a comment that belongs at the
   top, which is why this is keyed on the line that opens the chain. */
test("and a chain with no header is no exception", () => {
  const src = `table inet filter {
	chain input {
		limit rate 10/second log prefix "nft-in: drop "
		comment "Drop and log everything not whitelisted"
	}
}`;
  assert.deepEqual(verify(src).diffs, [], JSON.stringify(verify(src).diffs));
});

/* But the space inside a quoted string is not spacing — it is what the firewall
   writes to the log. Collapsing every run of whitespace in the line collapsed
   those too, so two different log prefixes compared equal and the one check
   that exists to catch that could not see it. */
test("a log prefix is compared by every character of it", () => {
  const one = `table ip t {
	chain c {
		log prefix "two  spaces " accept
	}
}`;
  assert.deepEqual(verify(one).diffs, [], "it round-trips as itself");
  const drifted = roundTrip(one, parseNft(one.replace("two  spaces", "two spaces")));
  assert.equal(drifted.diffs.length, 1, JSON.stringify(drifted.diffs));
});

/* A family-qualified `flush ruleset bridge` — `ip`, `inet`, `netdev`, `arp`
   too — vanished on the round trip. It matched the preamble filter that drops
   `flush ruleset` (it starts with those two words) but not the handler that
   obeys the flush, which wanted the exact string — so it fell through both and
   was lost, silently. A corpus of 1,673 real rulesets nft accepts found the
   one file that carried one: a bridge topology that opens `flush ruleset
   bridge` before its table.

   Two halves, both here: the line survives the round trip now, and the flush
   is obeyed for the right family only — a bridge flush leaves an ip table
   standing, because that is what the kernel would do. */
test("a family-qualified flush ruleset survives the round trip", () => {
  for (const fam of ["ip", "ip6", "inet", "arp", "bridge", "netdev"]) {
    const src = `flush ruleset ${fam}\ntable bridge filter {\n\tchain c {\n\t\ttype filter hook forward priority -200; policy accept;\n\t\tiifname "node0" oifname "node1" accept\n\t}\n}`;
    assert.deepEqual(verify(src).diffs, [], `flush ruleset ${fam}: ${JSON.stringify(verify(src).diffs)}`);
  }
});

test("a family flush empties only that family, as the kernel does", () => {
  const src = `table ip keep {\n\tchain c { type filter hook input priority 0; policy drop; }\n}\nflush ruleset bridge\ntable bridge gone {\n\tchain d { type filter hook forward priority -200; policy accept; }\n}`;
  const p = parseNft(src);
  const families = [...new Set(p.chains.map((c) => c.table.split(" ")[0]))].sort();
  assert.deepEqual(families, ["bridge", "ip"], "the ip table declared before the bridge flush must survive it");
});
