import test from "node:test";
import assert from "node:assert/strict";

import { MODEL, ruleLine } from "../src/core/model.js";
import { analyse, worstCase, subsumes, criteria } from "../src/core/analyse.js";
import { parseNft } from "../src/core/parse.js";
import { loadFlawed } from "./fixture.js";

/* every assertion here is about the flawed fixture, not about what the app
   opens on — the product starts blank */
loadFlawed();

const kinds = (f) => f.map((x) => x.kind).sort();

test("the demo ruleset yields exactly the defects it contains", () => {
  const f = analyse();
  assert.deepEqual(kinds(f), ["conflict", "hardening", "merge", "resilience", "shadowed", "unused"]);
  assert.equal(f.filter((x) => x.sev === "error").length, 1);
  assert.equal(f[0].kind, "conflict", "errors sort first");
});

/* The analyser reads a ruleset that works and says what is unwise about it.
   A rule nft will not parse is a different order of problem — the apply fails
   entire, so nothing you were told about the rest of the ruleset matters — and
   until core/lint.js it was invisible without a Linux host to run nft -c on. */
test("a rule nft would refuse is an error on the validation screen", () => {
  const saved = { chains: MODEL.chains, sets: MODEL.sets };
  MODEL.chains = [{
    id: "input", table: "inet filter", hook: "input", prio: 0, type: "filter",
    policy: "drop", rules: [
      { expr: "tcp dport 22", verdict: "jump", to: "nowhere", on: true, pkts: 0, bytes: 0 },
    ],
  }];
  MODEL.sets = [];

  const f = analyse();
  const syntax = f.filter((x) => x.kind === "syntax");
  assert.equal(syntax.length, 1, JSON.stringify(kinds(f)));
  assert.equal(syntax[0].sev, "error");
  assert.match(syntax[0].title[0], /nowhere/);
  assert.equal(f[0].kind, "syntax", "the ruleset not loading outranks everything else");
  assert.ok(!syntax[0].fix, "there is no safe way to invent the chain it meant");

  MODEL.chains = saved.chains;
  MODEL.sets = saved.sets;
});

test("subsumption is about coverage, not text", () => {
  const broad = criteria("tcp dport { 80, 443 }");
  const narrow = criteria("ip saddr 10.10.0.0/24 tcp dport 443");
  assert.ok(subsumes(broad, narrow), "a wider port set covers the narrower rule");
  assert.ok(!subsumes(narrow, broad), "and not the other way round");
});

test("a rate-limited rule never shadows anything", () => {
  const limited = criteria("limit rate 5/second");
  const anything = criteria("tcp dport 22");
  assert.ok(!subsumes(limited, anything), "non-deterministic rules cannot be reasoned about");
});

test("conntrack criteria do not create false positives", () => {
  const stateful = criteria("ct state established,related");
  const plain = criteria("tcp dport 22 ip saddr @admin_nets");
  assert.ok(!subsumes(stateful, plain), "a state match is narrower, not broader");
});

test("every finding carries a fix, and applying them all converges", () => {
  let guard = 0;
  while (guard++ < 25) {
    const next = analyse().find((f) => f.fix);
    if (!next) break;
    next.fix.run();
  }
  assert.equal(analyse().length, 0, "the analyser should be satisfiable");
  assert.ok(guard < 25, "and converge without thrashing");
});

test("a fix still works after the ruleset has been rebuilt underneath it", () => {
  loadFlawed();
  const finding = analyse().find((f) => f.kind === "shadowed");
  assert.ok(finding, "the fixture contains a shadowed rule");

  /* Exactly what undo does: every chain and rule replaced by fresh objects
     parsed from a snapshot. A fix holding references would silently mutate
     orphans and the button would appear dead. */
  const snapshot = JSON.stringify({ c: MODEL.chains, s: MODEL.sets });
  const restored = JSON.parse(snapshot);
  MODEL.chains = restored.c;
  MODEL.sets = restored.s;

  const before = MODEL.chains.reduce((n, c) => n + c.rules.length, 0);
  finding.fix.run();
  const after = MODEL.chains.reduce((n, c) => n + c.rules.length, 0);

  assert.equal(after, before - 1, "the fix did not reach the live ruleset");
  assert.ok(
    !analyse().some((f) => f.kind === "shadowed"),
    "the shadowed rule should be gone",
  );
});

test("worst case is measured over hooks, not chain names", () => {
  const n = worstCase();
  assert.ok(Number.isInteger(n) && n > 0, `got ${n}`);
  const before = n;
  MODEL.chains.forEach((c) => c.rules.forEach((r) => (r.on = false)));
  assert.ok(worstCase() < before, "disabling every rule must lower the cost");
});

/* A rule names a set in two places. `dnat to tcp dport map @port_fwd` keeps
   the map in the verdict target, not the expression — and the unused check
   read only the expression, so the map the whole port-forwarding scheme runs
   on was reported as never referenced, under a button offering to delete it.
   nft refuses a ruleset naming a set that is not there, so taking that offer
   breaks the file. */
test("a map used only as a NAT target is not unused", () => {
  const p = parseNft(`table ip nat {
	map port_fwd {
		type inet_service : ipv4_addr
		elements = { 80 : 10.20.0.10, 443 : 10.20.0.10 }
	}

	set hairpin {
		type ipv4_addr
		elements = { 10.20.0.10 }
	}

	chain nat_pre {
		type nat hook prerouting priority dstnat; policy accept;
		iifname "wan0" tcp dport { 80, 443 } dnat to tcp dport map @port_fwd
	}

	chain nat_post {
		type nat hook postrouting priority srcnat; policy accept;
		ip daddr @hairpin counter masquerade
	}
}`);
  Object.assign(MODEL, { chains: p.chains, sets: p.sets, objects: p.objects,
                         tables: p.tables, prelude: p.prelude });
  const unused = analyse().filter((f) => f.kind === "unused").map((f) => f.set);
  assert.deepEqual(unused, [], "both are referenced, one of them from the target");
});

test("and a set nothing names at all still is", () => {
  const p = parseNft(`table inet fw {
	set orphan {
		type ipv4_addr
		elements = { 10.0.0.1 }
	}

	chain input {
		type filter hook input priority filter; policy drop;
		tcp dport 22 accept
	}
}`);
  Object.assign(MODEL, { chains: p.chains, sets: p.sets, objects: p.objects,
                         tables: p.tables, prelude: p.prelude });
  assert.deepEqual(analyse().filter((f) => f.kind === "unused").map((f) => f.set), ["orphan"]);
});
