import test from "node:test";
import assert from "node:assert/strict";

import { MODEL, ruleLine } from "../src/core/model.js";
import { parseNft, parseRule, roundTrip } from "../src/core/parse.js";
import { generate } from "../src/core/generate.js";

const SAMPLE = `table inet filter {
	set trusted_v4 {
		type ipv4_addr
		flags interval
		elements = { 10.0.0.0/8, 192.168.0.0/16 }
	}

	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related counter packets 88 bytes 99 accept # handle 4
		tcp dport 22 ip saddr @trusted_v4 counter packets 8 bytes 9 accept comment "SSH"
		counter packets 1 bytes 2 drop
	}

	chain forward {
		type filter hook forward priority filter; policy drop;
		iifname "eth1" oifname "eth0" counter packets 5 bytes 6 accept
		log prefix "deny " counter packets 1 bytes 1
	}
}

table ip nat {
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname "eth0" masquerade
	}
}

table ip6 guard {
	chain input {
		type filter hook input priority filter; policy accept;
		icmpv6 type { nd-neighbor-solicit, nd-router-advert } accept
	}
}`;

test("parses tables, chains, sets and priorities by name", () => {
  const p = parseNft(SAMPLE);
  assert.equal(p.errors.length, 0, "every line should parse");
  assert.deepEqual(p.chains.map((c) => c.table + "/" + c.id), [
    "inet filter/input",
    "inet filter/forward",
    "ip nat/postrouting",
    "ip6 guard/input",
  ]);
  assert.equal(p.chains[0].prio, 0, "priority filter is 0");
  assert.equal(p.chains[2].prio, 100, "priority srcnat is 100");
  assert.equal(p.sets[0].el.length, 2);
});

test("every rule re-emits identically", () => {
  const p = parseNft(SAMPLE);
  const rt = roundTrip(SAMPLE, p);
  assert.equal(rt.diffs.length, 0, JSON.stringify(rt.diffs, null, 2));
  assert.equal(rt.ok, rt.total);
});

test("verdict forms survive extraction", () => {
  const cases = [
    ["ip saddr 1.2.3.4 counter packets 5 bytes 6 dnat to 10.0.0.1:80", "dnat", "10.0.0.1:80"],
    ['oifname "wan0" masquerade', "snat", "masquerade"],
    ["tcp dport 22 jump mychain", "jump", "mychain"],
    ["ct state invalid reject", "reject", undefined],
    ["counter packets 1 bytes 2", "continue", undefined],
    ["counter drop", "drop", undefined],
  ];
  for (const [line, verdict, to] of cases) {
    const r = parseRule(line);
    assert.ok(r, `should parse: ${line}`);
    assert.equal(r.verdict, verdict, line);
    if (to !== undefined) assert.equal(r.to, to, line);
  }
});

test("a bare reject is not rewritten on the way out", () => {
  const r = parseRule("ct state invalid reject");
  assert.equal(ruleLine(r), "ct state invalid reject");
});

test("import → generate → import is a fixed point", () => {
  const p1 = parseNft(SAMPLE);
  MODEL.chains = p1.chains;
  MODEL.sets = p1.sets.map((s) => ({ ...s }));

  const gen1 = generate().join("\n");
  const p2 = parseNft(gen1);
  MODEL.chains = p2.chains;
  MODEL.sets = p2.sets.map((s) => ({ ...s }));
  const gen2 = generate().join("\n");

  assert.equal(gen1, gen2, "regenerating a re-imported model must be stable");
  assert.equal(p2.chains.length, p1.chains.length);
  assert.equal(
    p2.chains.reduce((a, c) => a + c.rules.length, 0),
    p1.chains.reduce((a, c) => a + c.rules.length, 0),
  );
});

/* A counter that has never matched reads `counter packets 0 bytes 0`, and that
   is not an edge case: it is what every freshly loaded ruleset looks like, and
   what a rule that should be firing but is not looks like too. Emitting those
   rules without their counter loses a statement the source had. */
test("a counter with no traffic through it still survives the round-trip", () => {
  const src = `table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state invalid counter packets 0 bytes 0 drop
		tcp dport 22 counter packets 0 bytes 0 accept comment "never used yet"
		counter packets 0 bytes 0 drop
	}
}`;
  const p = parseNft(src);
  assert.equal(p.errors.length, 0, JSON.stringify(p.errors));
  const rt = roundTrip(src, p);
  assert.equal(rt.diffs.length, 0, JSON.stringify(rt.diffs, null, 2));
  assert.equal(rt.ok, rt.total);
});

test("a counting rule with no verdict and no traffic is a rule, not an error", () => {
  const r = parseRule("counter packets 0 bytes 0");
  assert.ok(r, "should parse");
  assert.equal(r.verdict, "continue");
  assert.equal(ruleLine(r), "counter");
});

test("a bare counter claims no statistics it does not have", () => {
  const r = parseRule("tcp dport 22 counter accept");
  assert.equal(r.pkts, 0, "a counter with no numbers has counted nothing");
  assert.equal(ruleLine(r), "tcp dport 22 counter accept");
});

test("every table survives generation, not just the ones we expected", () => {
  const p = parseNft(SAMPLE);
  MODEL.chains = p.chains;
  MODEL.sets = p.sets.map((s) => ({ ...s }));
  const out = generate().join("\n");
  for (const tb of ["inet filter", "ip nat", "ip6 guard"]) {
    assert.match(out, new RegExp(`^table ${tb} \\{$`, "m"), `${tb} must be emitted`);
  }
});
