/* Editing the things a table holds besides chains and sets.
 *
 * The parser has carried flowtables, named counters, quotas and ct helpers
 * verbatim for a while, which meant a ruleset with one survived a round trip
 * and could not be touched: you could look at your offload flowtable and not
 * add a device to it. */
import test from "node:test";
import assert from "node:assert/strict";

import { readObject, editObject, refsToObject, OBJECT_TEMPLATE } from "../src/core/objects.js";
import { parseNft, verify } from "../src/core/parse.js";
import { splitObject } from "../src/core/parse.js";

const obj = (kind, name, body) => ({ table: "inet filter", kind, name, body });

/* `ct helper ftp-standard {` and `flowtable ft {` look alike to a regex, and
   the kind used to swallow the name of the first. */
test("a two-word kind keeps its name", () => {
  assert.deepEqual(splitObject("ct helper ftp-standard {"), { kind: "ct helper", name: "ftp-standard" });
  assert.deepEqual(splitObject("ct timeout aggressive {"), { kind: "ct timeout", name: "aggressive" });
  assert.deepEqual(splitObject("flowtable ft {"), { kind: "flowtable", name: "ft" });
  assert.deepEqual(splitObject("counter http_hits {"), { kind: "counter", name: "http_hits" });
  assert.deepEqual(splitObject("somethingnew {"), { kind: "somethingnew", name: "" });
});

test("a flowtable reads and writes the things people change about one", () => {
  const ft = obj("flowtable", "ft", ["hook ingress priority filter", "devices = { eth0, eth1 }"]);
  const r = readObject(ft);
  assert.equal(r.hook, "ingress");
  assert.equal(r.priority, "filter");
  assert.equal(r.devices, "eth0, eth1");

  ft.body = editObject(ft, { devices: "eth0, eth1, wg0" });
  assert.deepEqual(ft.body, ["hook ingress priority filter", "devices = { eth0, eth1, wg0 }"]);
});

test("a counter and a quota are their numbers", () => {
  const c = obj("counter", "hits", ["packets 12 bytes 900"]);
  assert.equal(readObject(c).packets, "12");
  c.body = editObject(c, { packets: "0", bytes: "0" });
  assert.deepEqual(c.body, ["packets 0 bytes 0"]);

  /* nft refuses `gbytes` — "expecting bytes, kbytes or mbytes", checked
     against 1.1.6 — so it is not a unit this offers. Reading one anyway is
     preserve-by-default doing its job: a file that arrives with it is not a
     file to choke on. */
  const q = obj("quota", "monthly", ["over 10 gbytes"]);
  const r = readObject(q);
  assert.equal(r.mode, "over");
  assert.equal(r.amount, "10");
  assert.equal(r.unit, "gbytes");
  q.body = editObject(q, { amount: "500", unit: "mbytes" });
  assert.deepEqual(q.body, ["over 500 mbytes"]);
});

test("a ct helper is its protocol and the helper it names", () => {
  const h = obj("ct helper", "ftp-standard", ['type "ftp" protocol tcp']);
  const r = readObject(h);
  assert.equal(r.type, "ftp");
  assert.equal(r.protocol, "tcp");
  h.body = editObject(h, { type: "sip", protocol: "udp" });
  assert.deepEqual(h.body, ['type "sip" protocol udp']);
});

/* The point of keeping the body: a kind nothing models is still a kind you can
   keep, and a line nothing models is a line nothing touches. */
test("a line no field models survives an edit to one that is", () => {
  const ft = obj("flowtable", "ft", [
    "hook ingress priority filter",
    "counter",
    "flags offload",
    "devices = { eth0 }",
  ]);
  ft.body = editObject(ft, { devices: "eth0, eth1" });
  assert.deepEqual(ft.body, [
    "hook ingress priority filter",
    "counter",
    "flags offload",
    "devices = { eth0, eth1 }",
  ]);
});

test("a kind with no fields at all is left exactly as it is", () => {
  const s = obj("synproxy", "syn", ["mss 1460", "wscale 7"]);
  assert.deepEqual(editObject(s, {}), ["mss 1460", "wscale 7"]);
});

test("a field the body lacks is added rather than lost", () => {
  const ft = obj("flowtable", "ft", ["devices = { eth0 }"]);
  ft.body = editObject(ft, { hook: "ingress", priority: "filter" });
  assert.ok(ft.body.some((l) => l.includes("hook ingress")));
  assert.ok(ft.body.some((l) => l.includes("devices = { eth0 }")));
});

/* nft refuses a rule naming an object that is not there, which is why the set
   manager guards a delete and why this has to as well. */
test("who is using it, per kind", () => {
  const chains = [{
    table: "inet filter", id: "forward", rules: [
      { expr: "ip protocol { tcp, udp } flow add @ft" },
      { expr: 'tcp dport 80 counter name "hits"' },
      { expr: 'tcp dport 21 ct helper set "ftp-standard"' },
      { expr: "tcp dport 22 accept" },
    ],
  }];
  assert.equal(refsToObject(obj("flowtable", "ft", []), chains).length, 1);
  assert.equal(refsToObject(obj("counter", "hits", []), chains).length, 1);
  assert.equal(refsToObject(obj("ct helper", "ftp-standard", []), chains).length, 1);
  assert.equal(refsToObject(obj("flowtable", "other", []), chains).length, 0);
});

test("a reference in another table is not a reference to this one", () => {
  const chains = [{ table: "ip nat", id: "x", rules: [{ expr: "flow add @ft" }] }];
  assert.equal(refsToObject(obj("flowtable", "ft", []), chains).length, 0);
});

/* `counter name "http_hits"` names a counter object; `counter` on its own is
   the anonymous statement. Reading the first as the second left a dangling
   `name "http_hits"` in the expression and re-emitted the rule reordered. */
test("a named counter reference is not the anonymous counter statement", () => {
  const src = `table inet filter {
	counter http_hits {
		packets 0 bytes 0
	}

	chain c {
		tcp dport 80 counter name "http_hits" accept
		tcp dport 443 counter accept
	}
}`;
  const [named, anon] = parseNft(src).chains[0].rules;
  assert.equal(named.expr, 'tcp dport 80 counter name "http_hits"');
  assert.equal(named.ctr, false, "it counts into the object, not into this rule");
  assert.equal(anon.expr, "tcp dport 443");
  assert.equal(anon.ctr, true);
  assert.deepEqual(verify(src).diffs, []);
});

/* A template has to be a thing nft would take, apart from the one blank it
   deliberately leaves for the user. */
test("every template parses back as the object it claims to be", () => {
  for (const [kind, body] of Object.entries(OBJECT_TEMPLATE)) {
    const src = `table inet filter {\n\t${kind} thing {\n${body.map((l) => "\t\t" + l).join("\n")}\n\t}\n}`;
    const p = parseNft(src);
    assert.equal(p.objects.length, 1, kind);
    assert.equal(p.objects[0].kind, kind);
    assert.equal(p.objects[0].name, "thing");
    assert.deepEqual(verify(src).diffs, [], kind);
  }
});

/* Everything offered has to be something nft would take.
 *
 * The quota template emitted `over 1 gbytes`, and the unit dropdown offered
 * it. nft 1.1.6 answers "Wrong unit format, expecting bytes, kbytes or
 * mbytes" and refuses the file — so making a quota in the editor produced a
 * ruleset that would not load, and nothing said so until the apply. */
test("no offered quota unit is one nft refuses", async () => {
  const { readFileSync } = await import("node:fs");
  const OK = ["bytes", "kbytes", "mbytes"];

  const t = OBJECT_TEMPLATE.quota.join(" ");
  const unit = t.match(/\b(\w*bytes)\b/)[1];
  assert.ok(OK.includes(unit), `the quota template offers ${unit}, which nft refuses`);

  const app = readFileSync(new URL("../src/app.js", import.meta.url), "utf8");
  const list = app.match(/unit:\s*\[([^\]]*)\]/);
  assert.ok(list, "the unit dropdown should be findable");
  for (const u of list[1].split(",").map((s) => s.trim().replace(/"/g, "")))
    assert.ok(OK.includes(u), `the unit dropdown offers ${u}, which nft refuses`);

  for (const m of app.matchAll(/quota over [\d\s]*(\w*bytes)/g))
    assert.ok(OK.includes(m[1]), `the palette drops ${m[1]}, which nft refuses`);
});
