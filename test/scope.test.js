/* What an export is allowed to destroy.
 *
 * `flush ruleset` empties the kernel. On a machine that only runs what eFeFlow
 * designed, that is what you want. On a machine that also runs Docker, libvirt,
 * kubernetes, fail2ban or firewalld — which is most machines — it deletes their
 * tables too, and they will not notice or put them back. Applying a ruleset
 * should replace the tables this project owns and leave the rest standing. */
import test from "node:test";
import assert from "node:assert/strict";

import { parseNft, verify } from "../src/core/parse.js";
import { generate } from "../src/core/generate.js";

const SRC = `table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		tcp dport 22 accept
	}
}

table ip nat {
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		oifname "wan0" masquerade
	}
}`;

const model = () => { const p = parseNft(SRC); return p; };

test("the full export still flushes the ruleset, and says so first", () => {
  const out = generate(model());
  assert.equal(out.filter((l) => l === "flush ruleset").length, 1);
  assert.ok(out.indexOf("flush ruleset") < out.findIndex((l) => l.startsWith("table ")));
});

/* The idiom is create-then-delete-then-create: a bare `table X` is a no-op if
   it exists and creates it if it does not, so the delete after it never fails
   on a host that has never seen this table. */
test("the table-scoped export replaces its own tables and flushes nothing", () => {
  const out = generate(model(), { scope: "tables" });
  assert.ok(!out.includes("flush ruleset"), "a scoped export must not empty the kernel");

  for (const tb of ["inet filter", "ip nat"]) {
    const create = out.indexOf(`table ${tb}`);
    const del = out.indexOf(`delete table ${tb}`);
    const open = out.indexOf(`table ${tb} {`);
    assert.ok(create >= 0, `${tb} is never declared`);
    assert.ok(del > create, `${tb} is deleted before it is guaranteed to exist`);
    assert.ok(open > del, `${tb} is defined before the old one is removed`);
  }
});

test("a scoped export names no table the project does not own", () => {
  const out = generate(model(), { scope: "tables" }).join("\n");
  assert.doesNotMatch(out, /\bdocker\b|\bfirewalld\b|\blibvirt\b/);
  assert.equal((out.match(/^delete table /gm) || []).length, 2, "one delete per owned table");
});

/* Whatever the scope, the tables themselves have to come out identical — the
   difference is the preamble, not the ruleset. */
test("scope changes what is removed, never what is written", () => {
  const body = (lines) => lines.filter((l) => l.startsWith("\t") || l === "}").join("\n");
  assert.equal(body(generate(model())), body(generate(model(), { scope: "tables" })));
});

test("a scoped export still survives the round-trip check", () => {
  const p = parseNft(generate(model(), { scope: "tables" }).join("\n"));
  assert.deepEqual(p.errors, []);
  assert.deepEqual(
    p.chains.map((c) => c.table + "/" + c.id),
    ["inet filter/input", "ip nat/postrouting"],
  );
  assert.deepEqual(verify(SRC).diffs, []);
});
