/* The same invariant as the chain panel, on the three that are left.
 *
 * Opening a panel and saving it unchanged must change nothing. Each of these
 * holds text nft wrote — a set body with its statements sharing lines, an
 * object body kept verbatim because nothing here models it, a table's flags
 * and comment — unwraps it into controls, and wraps it back. Any asymmetry
 * between the two halves is an edit nobody asked for, and `edit()` snapshots
 * it either way, so it does not even read as wrong in the undo history.
 *
 * The chain panel failed this on three fields out of five. These are the rest
 * of the surface where the same shape of mistake fits. */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, newRuleset, $, $$, click, setValue, settle } from "./harness.js";
import { MODEL } from "../src/core/model.js";
import { generate } from "../src/core/generate.js";
import { tableNames, readTable } from "../src/core/tables.js";

after(shutdown);

/* Every shape the panels have to give back untouched: a set whose type and
   flags share a line the way nft prints them, attributes the editor owns, a
   set with a `typeof`, an object body nothing models, and a table carrying
   both a comment and a flag. */
const SRC = `table inet filter {
	counter http_hits {
		packets 12 bytes 900
	}

	ct helper ftp-standard {
		type "ftp" protocol tcp
		l3proto ip
	}

	set blocked {
		type ipv4_addr ; flags interval
		size 65535
		timeout 1h
		gc-interval 12s
		auto-merge
		elements = { 203.0.113.0/24, 198.51.100.7 }
	}

	set shaped {
		typeof ip saddr . tcp dport
		elements = { 10.0.0.1 . 22 }
	}

	chain input {
		type filter hook input priority filter; policy drop;
		ip saddr @blocked drop
		ip saddr . tcp dport @shaped accept
	}
}

table ip parked {
	comment "kept for the migration"
	flags dormant

	chain old {
		type filter hook input priority 0; policy accept;
		tcp dport 3306 accept
	}
}`;

async function load(where) {
  await boot();
  await newRuleset();
  const area = $("#imp-text");
  area.value = SRC;
  area.dispatchEvent(new globalThis.window.Event("input", { bubbles: true }));
  click("#imp-go");
  await settle(90);
  click(`.rb[data-go="${where}"]`);
  await settle(120);
}

const emitted = () => generate(MODEL).join("\n");
const pick = async (name) => {
  const i = [...MODEL.sets, ...MODEL.objects].findIndex((x) => (x.n ?? x.name) === name);
  assert.ok(i >= 0, `no item called ${name}`);
  click($$(".set-item")[i]);
  await settle(80);
};

/* ── sets ────────────────────────────────────────────────────────────────── */

test("selecting a set changes nothing about it", async () => {
  await load("sets");
  const before = emitted();
  await pick("blocked");
  assert.equal(emitted(), before, "just looking at it rewrote it");
});

/* nft prints `type ipv4_addr ; flags interval` on one line, and the model
   remembers that with a join marker so it goes back out the same way. */
test("a set whose statements share a line keeps them there", async () => {
  await load("sets");
  await pick("blocked");
  setValue("#set-type", "ipv4_addr", "change");
  await settle(80);
  assert.ok(emitted().includes("type ipv4_addr ; flags interval"),
    `the shared line came apart:\n${emitted()}`);
});

test("the attributes the editor owns all survive being looked at", async () => {
  await load("sets");
  const before = emitted();
  await pick("blocked");
  setValue("#set-type", "ipv4_addr", "change");
  await settle(80);
  for (const line of ["size 65535", "timeout 1h", "gc-interval 12s", "auto-merge"])
    assert.ok(emitted().includes(line), `${line} was lost:\n${emitted()}`);
  assert.equal(emitted(), before, "and nothing moved");
});

test("a typeof set is not turned into a type one by being opened", async () => {
  await load("sets");
  const before = emitted();
  await pick("shaped");
  assert.equal(emitted(), before);
  assert.ok(emitted().includes("typeof ip saddr . tcp dport"), emitted());
});

/* ── objects ─────────────────────────────────────────────────────────────── */

/* An object body is held verbatim because nothing here models it. That is the
   whole promise of preserve-by-default, and the panel is where it is easiest
   to break. */
test("selecting an object changes nothing about it", async () => {
  await load("sets");
  const before = emitted();
  await pick("ftp-standard");
  assert.equal(emitted(), before);
});

test("an object body comes back line for line", async () => {
  await load("sets");
  await pick("ftp-standard");
  setValue("#obj-name", "ftp-standard", "change");
  await settle(80);
  assert.ok(emitted().includes('type "ftp" protocol tcp'), emitted());
  assert.ok(emitted().includes("l3proto ip"), emitted());
});

test("a counter object keeps the figures it arrived with", async () => {
  await load("sets");
  const before = emitted();
  await pick("http_hits");
  assert.equal(emitted(), before);
  assert.ok(emitted().includes("packets 12 bytes 900"), emitted());
});

/* ── tables ──────────────────────────────────────────────────────────────── */

const chip = (name) => $$(".tbl-chip[data-table]").find((b) => b.dataset.table === name);

test("opening a table and saving it unchanged changes nothing", async () => {
  await load("editor");
  const name = tableNames(MODEL).find((n) => n.startsWith("ip parked"));
  assert.ok(name, tableNames(MODEL).join(" | "));
  const before = emitted();

  click(chip(name));
  await settle(60);
  click("#tbl-save");
  await settle(120);

  assert.equal(emitted(), before,
    `the table panel rewrote it:\n--- before\n${before}\n--- after\n${emitted()}`);
});

test("the comment field holds the comment, not the line it came from", async () => {
  await load("editor");
  const name = tableNames(MODEL).find((n) => n.startsWith("ip parked"));
  click(chip(name));
  await settle(60);
  assert.equal($("#tbl-comment").value, "kept for the migration");
  assert.ok($("#tbl-dormant").classList.contains("on"), "the table is parked and the switch says not");
});

test("and it survives being saved twice", async () => {
  await load("editor");
  const name = tableNames(MODEL).find((n) => n.startsWith("ip parked"));
  for (let i = 0; i < 2; i++) {
    click(chip(name));
    await settle(60);
    click("#tbl-save");
    await settle(120);
  }
  const info = readTable(MODEL, name);
  assert.equal(info.comment, "kept for the migration");
  assert.equal(info.dormant, true);
});

/* ── rules ───────────────────────────────────────────────────────────────── */

/* The busiest panel of all, and the one with the most statements it cannot
   show. A rule carrying a `limit rate` and a `log prefix` has both held in the
   expression verbatim; selecting it paints half a dozen controls off that
   text, and every one of them is a chance to write back a tidied version. */
const RICH = `table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ip saddr @blocked tcp dport 22 tcp flags syn / fin,syn,rst,ack log prefix "ssh " level info limit rate 3/minute burst 3 packets counter accept
		iifname "lo" counter accept comment "loopback"
	}
	set blocked {
		type ipv4_addr
		elements = { 203.0.113.7 }
	}
}`;

async function loadRules() {
  await boot();
  await newRuleset();
  const area = $("#imp-text");
  area.value = RICH;
  area.dispatchEvent(new globalThis.window.Event("input", { bubbles: true }));
  click("#imp-go");
  await settle(90);
  click('.rb[data-go="editor"]');
  await settle(120);
}

test("selecting a rule changes nothing about it", async () => {
  await loadRules();
  const before = emitted();
  click($$("#chains .rule")[0]);
  await settle(90);
  assert.equal(emitted(), before, "selecting it rewrote it");
});

test("and every statement it carries is still there afterwards", async () => {
  await loadRules();
  click($$("#chains .rule")[0]);
  await settle(90);
  for (const part of ['tcp flags syn / fin,syn,rst,ack', 'log prefix "ssh " level info',
                      "limit rate 3/minute burst 3 packets", "ip saddr @blocked"])
    assert.ok(emitted().includes(part), `${part} did not survive:\n${emitted()}`);
});

test("a comment on a rule survives being selected", async () => {
  await loadRules();
  const before = emitted();
  click($$("#chains .rule")[1]);
  await settle(90);
  assert.equal(emitted(), before);
  assert.ok(emitted().includes('comment "loopback"'), emitted());
});
