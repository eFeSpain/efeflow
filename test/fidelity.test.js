/* What survives a trip through the model, checked on the whole file rather
 * than on its rules.
 *
 * The rule-level proof in roundtrip.test.js answers "did every rule come back
 * the same". It cannot answer "is this the same ruleset", and the difference
 * is not academic: a flowtable that vanishes takes `flow add @ft` with it, a
 * netdev chain that loses its device will not load, and a set whose elements
 * wrapped over two lines — which is how nft prints every blocklist worth
 * having — used to import empty and report no error at all. */
import test from "node:test";
import assert from "node:assert/strict";

import { parseNft, verify } from "../src/core/parse.js";
import { generate } from "../src/core/generate.js";

const model = (p) => ({ chains: p.chains, sets: p.sets, objects: p.objects, tables: p.tables });
const emit = (src) => generate(model(parseNft(src))).join("\n");

/* A router ruleset: everything nft prints that is not a chain or a set. */
const RICH = `table inet filter {
	set blocklist {
		type ipv4_addr
		flags interval
		auto-merge
		size 65536
		elements = { 1.2.3.0/24, 5.6.7.0/24,
			     8.9.10.0/24, 11.12.13.0/24 }
	}

	map porthost {
		type inet_service : ipv4_addr
		elements = { 80 : 10.0.0.1, 443 : 10.0.0.2 }
	}

	flowtable ft {
		hook ingress priority filter
		devices = { eth0, eth1 }
	}

	counter http_hits {
		packets 12 bytes 900
	}

	chain forward {
		type filter hook forward priority filter; policy drop;
		ip protocol { tcp, udp } flow add @ft
		ct state established,related accept
		tcp dport 22 goto ssh
	}

	chain ssh {
		ip saddr @blocklist drop
		accept
	}
}

table netdev ddos {
	chain ingress {
		type filter hook ingress device "eth0" priority -500; policy accept;
		ip frag-off & 0x1fff != 0 drop
	}
}

table ip nat {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		iifname "wan0" tcp dport 8080 redirect to :80
	}
}`;

test("a table's chains stay in the table they were written in", () => {
  const p = parseNft(RICH);
  assert.deepEqual(
    p.chains.map((c) => c.table + "/" + c.id),
    [
      "inet filter/forward",
      "inet filter/ssh",
      "netdev ddos/ingress",
      "ip nat/prerouting",
    ],
    "a flowtable and a counter each close a brace; neither closes the table",
  );
});

/* The elements are the set. A blocklist that imports empty is a firewall that
   has stopped blocking, and it reported a clean import while doing it. */
test("a set whose elements wrap over several lines keeps them", () => {
  const s = parseNft(RICH).sets.find((x) => x.n === "blocklist");
  assert.deepEqual(s.el, ["1.2.3.0/24", "5.6.7.0/24", "8.9.10.0/24", "11.12.13.0/24"]);
});

/* `;` separates statements in nft, so `type ipv4_addr ; flags interval` is two
   of them. Read as one, the type became the whole string and the flag vanished
   from the set editor — while still round-tripping as text, which is exactly
   why nobody noticed. */
test("statements sharing a line by semicolon are read as the statements they are", () => {
  const src = `table inet fw {
	set admins {
		type ipv4_addr ; flags interval
		elements = { 10.0.0.0/8 }
	}
}`;
  const s = parseNft(src).sets[0];
  assert.equal(s.t, "ipv4_addr");
  assert.equal(s.f, "interval");
  assert.match(emit(src), /type ipv4_addr ; flags interval/, "and go back on the line they came from");
  assert.deepEqual(verify(src).diffs, []);
});

test("set attributes the editor does not model are still emitted", () => {
  const out = emit(RICH);
  assert.match(out, /^\s*auto-merge$/m);
  assert.match(out, /^\s*size 65536$/m);
});

test("objects nftables has and the model does not are kept verbatim", () => {
  const p = parseNft(RICH);
  assert.deepEqual(
    p.objects.map((o) => `${o.table} ${o.kind} ${o.name}`),
    ["inet filter flowtable ft", "inet filter counter http_hits"],
  );
  const out = emit(RICH);
  assert.match(out, /flowtable ft \{/);
  assert.match(out, /devices = \{ eth0, eth1 \}/);
  assert.match(out, /counter http_hits \{/);
  assert.match(out, /packets 12 bytes 900/);
});

/* A netdev base chain without its device is not a chain nft will take. */
test("a netdev chain keeps the device it is attached to", () => {
  const ch = parseNft(RICH).chains.find((c) => c.id === "ingress");
  assert.equal(ch.hook, "ingress");
  assert.match(emit(RICH), /type filter hook ingress device "eth0" priority -500;/);
});

/* nft prints priorities by name. Turning `dstnat` into `-100` is not wrong,
   but it is a diff on every chain header, and a diff you cannot explain is
   indistinguishable from one you should worry about. */
test("a priority written by name comes back by name", () => {
  const out = emit(RICH);
  assert.match(out, /hook forward priority filter;/);
  assert.match(out, /hook prerouting priority dstnat;/);
  assert.match(out, /priority -500;/, "a priority with no name stays a number");
});

/* The honest question is not "did the rules survive" but "is this the same
   ruleset". This is the check the import dialog should be reporting. */
test("the whole file survives, not just its rules", () => {
  const v = verify(RICH);
  assert.deepEqual(v.diffs, [], JSON.stringify(v.diffs, null, 2));
  assert.equal(v.ok, v.total);
  assert.ok(v.total > 20, `expected the whole file to be checked, got ${v.total} lines`);
});

test("a table flag survives, because losing it turns a parked firewall on", () => {
  const src = `table inet parked {
	flags dormant

	chain input {
		type filter hook input priority filter; policy drop;
		accept
	}
}`;
  assert.match(emit(src), /^\s*flags dormant$/m);
  assert.deepEqual(verify(src).diffs, []);
});

test("nothing in the rich sample is reported as an unparsable line", () => {
  assert.deepEqual(parseNft(RICH).errors, []);
});

/* `nft -a list ruleset` is what the app asks a host for, and the handle is the
   only way to address one rule of a live ruleset. It was stripped on the way
   in while the properties panel displayed `4000 + index * 7` in its place. */
test("the handle a host gave a rule is kept, not replaced with a made-up one", () => {
  const p = parseNft(`table inet filter {
	chain input { # handle 2
		type filter hook input priority filter; policy drop;
		ct state established,related accept # handle 4
		tcp dport 22 accept # handle 7
	}
}`);
  assert.equal(p.chains[0].handle, 2);
  assert.deepEqual(p.chains[0].rules.map((r) => r.handle), [4, 7]);
});

test("a ruleset with no handles claims none", () => {
  const p = parseNft(RICH);
  assert.ok(p.chains.every((c) => c.handle === undefined));
  assert.ok(p.chains.every((c) => c.rules.every((r) => r.handle === undefined)));
});
