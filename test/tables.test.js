/* The table level: two properties, and what the rest of the tool does once it
 * can read them.
 *
 * `flags dormant` was the thing that made this worth doing. It round-tripped
 * invisibly, so a parked ruleset — every base chain unregistered, not one
 * packet filtered — looked identical on every screen to one that was running. */
import test from "node:test";
import assert from "node:assert/strict";

import { parseNft } from "../src/core/parse.js";
import { generate } from "../src/core/generate.js";
import {
  splitTable, joinTable, tableNames, flagsOf, readTable, writeTable,
  isDormant, dormantTables, renameTable, removeTable,
} from "../src/core/tables.js";

const emit = (m) => generate(m).join("\n");

const SRC = `table inet fw {
	flags dormant
	comment "parked while we migrate"

	set admin {
		type ipv4_addr
		elements = { 10.0.0.1 }
	}

	chain input {
		type filter hook input priority filter; policy drop;
		ip saddr @admin accept
		tcp dport 22 accept
	}
}
table ip nat {
	chain post {
		type nat hook postrouting priority srcnat; policy accept;
		masquerade
	}
}`;

test("a family and a name, however the source spelled it", () => {
  assert.deepEqual(splitTable("inet fw"), { family: "inet", name: "fw" });
  /* nft's own default when a table declares no family */
  assert.deepEqual(splitTable("filter"), { family: "ip", name: "filter" });
  assert.deepEqual(splitTable("netdev on_wire"), { family: "netdev", name: "on_wire" });
  assert.equal(joinTable("ip6", "fw"), "ip6 fw");
});

test("both properties are read off the table they arrived on", () => {
  const m = parseNft(SRC);
  const fw = readTable(m, "inet fw");
  assert.equal(fw.dormant, true);
  assert.equal(fw.comment, "parked while we migrate");
  assert.equal(fw.family, "inet");
  assert.equal(fw.chains, 1);
  assert.equal(fw.rules, 2);
  assert.equal(fw.sets, 1);

  const nat = readTable(m, "ip nat");
  assert.equal(nat.dormant, false);
  assert.equal(nat.comment, "");
});

test("every table is found, not only the ones holding a chain", () => {
  const m = parseNft(SRC);
  assert.deepEqual(tableNames(m), ["inet fw", "ip nat"]);

  /* a table that exists to carry a flag and nothing else */
  writeTable(m, "inet spare", { dormant: true });
  assert.ok(tableNames(m).includes("inet spare"));
  assert.equal(readTable(m, "inet spare").chains, 0);
});

test("waking a table up leaves everything else it said alone", () => {
  const m = parseNft(SRC);
  writeTable(m, "inet fw", { dormant: false, comment: "parked while we migrate" });
  const fw = readTable(m, "inet fw");
  assert.equal(fw.dormant, false);
  assert.equal(fw.comment, "parked while we migrate", "the comment is not collateral");
  assert.ok(!emit(m).includes("dormant"));
});

/* nftables takes more than one table flag, and `owner` is not ours to drop. */
test("the toggle owns the word dormant, not the flags line", () => {
  const m = parseNft(SRC.replace("flags dormant", "flags dormant,owner"));
  assert.deepEqual(flagsOf(readTable(m, "inet fw").extra), ["dormant", "owner"]);
  writeTable(m, "inet fw", { dormant: false });
  assert.deepEqual(flagsOf(readTable(m, "inet fw").extra), ["owner"]);
  assert.match(emit(m), /flags owner/);
});

test("a line nothing here models stays where it sat", () => {
  const m = parseNft(SRC.replace("\tflags dormant", "\tflags dormant\n\tsomething we have never heard of"));
  writeTable(m, "inet fw", { dormant: false, comment: "still here" });
  const extra = readTable(m, "inet fw").extra;
  assert.ok(extra.includes("something we have never heard of"));
  /* it arrived above the comment and it is still above the comment: the two
     lines we understand are rewritten where they sat, not appended */
  assert.ok(extra.indexOf("something we have never heard of")
            < extra.findIndex((l) => l.startsWith("comment ")),
    "preserve by default means preserving the order too");
});

test("what is written comes back out, and only once", () => {
  const m = parseNft(SRC);
  writeTable(m, "inet fw", { dormant: true, comment: "still parked" });
  const src = emit(m);
  assert.equal((src.match(/flags dormant/g) || []).length, 1);
  assert.equal((src.match(/comment "still parked"/g) || []).length, 1);
  /* and it reads back as what it was written as */
  assert.equal(readTable(parseNft(src), "inet fw").comment, "still parked");
});

test("renaming moves everything filed under the old name", () => {
  const m = parseNft(SRC);
  const moved = renameTable(m, "inet fw", "inet edge");
  assert.ok(moved >= 3, "a chain, a set and the table's own entry");
  assert.deepEqual(m.chains.map((c) => c.table), ["inet edge", "ip nat"]);
  assert.equal(m.sets[0].table, "inet edge");
  assert.equal(readTable(m, "inet edge").dormant, true);
  assert.ok(!tableNames(m).includes("inet fw"));
});

/* Two tables' flags cannot both survive one block, and picking a winner
   quietly is the class of thing this file exists to stop. */
test("renaming onto a table that exists is refused, not merged", () => {
  const m = parseNft(SRC);
  assert.equal(renameTable(m, "inet fw", "ip nat"), 0);
  assert.deepEqual(tableNames(m), ["inet fw", "ip nat"]);
  assert.equal(readTable(m, "inet fw").dormant, true);
});

test("deleting one says what went with it", () => {
  const m = parseNft(SRC);
  const gone = removeTable(m, "inet fw");
  assert.deepEqual(gone, { chains: 1, rules: 2, sets: 1, objects: 0 });
  assert.deepEqual(tableNames(m), ["ip nat"]);
  assert.ok(!emit(m).includes("inet fw"));
});

test("dormant is answered about the model, not about a string", () => {
  const m = parseNft(SRC);
  assert.equal(isDormant(m, "inet fw"), true);
  assert.equal(isDormant(m, "ip nat"), false);
  assert.equal(isDormant(m, "no such table"), false);
  assert.deepEqual(dormantTables(m), ["inet fw"]);
});
