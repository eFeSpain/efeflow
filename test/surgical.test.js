/* Sending the changes instead of sending the ruleset.
 *
 * The apply this application has always done is `delete table X` and put it
 * back, which costs every counter in that table — including the rules nobody
 * edited. Change one line of a firewall that has been up a month and a month
 * of numbers goes with it.
 *
 * Four things were measured on nft 1.1.3 on a live kernel before any of this
 * was written, because each decides whether the idea is safe at all:
 *
 *   a file of replace/delete/insert/add commands is ONE transaction — one bad
 *   line among three good ones left the ruleset byte for byte as it was;
 *   `nft -c -f -` refuses a handle that no longer exists, before anything is
 *   written; a rule nobody touched keeps its handle AND its counter, while a
 *   replaced one keeps its handle and loses its counter even when replaced
 *   with identical text; and `insert ... position H` lands immediately before
 *   H, several of them in the order they were issued.
 *
 * Then the whole thing was run against a real five-rule chain that had been
 * counting: one rule changed, one deleted, one inserted mid-chain and one
 * appended. The chain came back reading exactly what the editor said, in
 * order, and 34 packets of history were still standing where the whole-table
 * apply would have left none.
 *
 * What is tested here is the part that decides what to send — and, at least as
 * important, the cases where it must decline and let the apply that always
 * works do the job. */
import test from "node:test";
import assert from "node:assert/strict";
import { parseNft } from "../src/core/parse.js";
import { surgicalPlan } from "../src/core/surgical.js";

const LIVE = `table inet t {
	chain input {
		type filter hook input priority filter; policy accept;
		iif "lo" counter packets 34 bytes 2108 accept # handle 2
		tcp dport 22 counter packets 0 bytes 0 accept # handle 3
		tcp dport 80 counter packets 0 bytes 0 accept # handle 4
		tcp dport 8080 counter packets 0 bytes 0 accept # handle 5
		tcp dport 443 counter packets 0 bytes 0 accept # handle 6
	}
}`;
const OURS = ["inet t"];
const host = () => parseNft(LIVE);
const plan = (edit) => {
  const m = parseNft(LIVE);
  edit(m, m.chains[0]);
  return surgicalPlan(m, host(), { tables: OURS });
};
const rule = (expr) => ({ expr, ctr: true, verdict: "accept", on: true });

/* ── the four kinds of change, and the shape of each command ─────────────── */

test("an edited rule is replaced at its own handle", () => {
  const p = plan((m, ch) => { ch.rules[1].verdict = "drop"; });
  assert.equal(p.ok, true, p.why);
  assert.deepEqual(p.commands, ["replace rule inet t input handle 3 tcp dport 22 counter drop"]);
  assert.equal(p.replaced, 1);
  assert.equal(p.kept, 4, "the other four are not mentioned, which is the point");
});

test("a rule switched off is deleted by handle", () => {
  const p = plan((m, ch) => { ch.rules[3].on = false; });
  assert.deepEqual(p.commands, ["delete rule inet t input handle 5"]);
  assert.equal(p.deleted, 1);
});

test("a new rule mid-chain is inserted before the one it precedes", () => {
  const p = plan((m, ch) => ch.rules.splice(1, 0, rule("tcp dport 25")));
  assert.deepEqual(p.commands,
    ["insert rule inet t input position 3 tcp dport 25 counter accept"]);
});

test("a new rule at the end is appended, because there is nothing to precede", () => {
  const p = plan((m, ch) => ch.rules.push(rule("tcp dport 9090")));
  assert.deepEqual(p.commands, ["add rule inet t input tcp dport 9090 counter accept"]);
});

test("several new rules keep the order they were written in", () => {
  /* measured: consecutive inserts against one anchor come out in issue order */
  const p = plan((m, ch) => ch.rules.splice(1, 0, rule("tcp dport 1"), rule("tcp dport 2")));
  assert.deepEqual(p.commands, [
    "insert rule inet t input position 3 tcp dport 1 counter accept",
    "insert rule inet t input position 3 tcp dport 2 counter accept",
  ]);
});

test("all four at once, and nothing about the rules between them", () => {
  const p = plan((m, ch) => {
    ch.rules[1].verdict = "drop";
    ch.rules[3].on = false;
    ch.rules.splice(1, 0, rule("tcp dport 25"));
    ch.rules.push(rule("tcp dport 9090"));
  });
  assert.equal(p.ok, true, p.why);
  assert.deepEqual(p.commands, [
    "replace rule inet t input handle 3 tcp dport 22 counter drop",
    "delete rule inet t input handle 5",
    "insert rule inet t input position 3 tcp dport 25 counter accept",
    "add rule inet t input tcp dport 9090 counter accept",
  ]);
  assert.equal(p.kept, 3);
  assert.equal(p.keptCounters, 1, "and one of those three is still counting");
});

/* ── where it has to decline ─────────────────────────────────────────────── */

test("nothing to do is not a plan", () => {
  assert.deepEqual(surgicalPlan(parseNft(LIVE), host(), { tables: OURS }),
    { ok: false, why: "nothing-to-do", detail: undefined });
});

/* Pairing is by handle and says nothing about order, so the same rules moved
   around read as every one of them unchanged. Sending nothing while the order
   differs is the worst answer available: the firewall would stay as it was and
   the screen would say it had been updated. */
test("rules put in a different order are handed back, not silently ignored", () => {
  const p = plan((m, ch) => { const r = ch.rules; [r[1], r[3]] = [r[3], r[1]]; });
  assert.equal(p.ok, false);
  assert.equal(p.why, "reordered");
});

test("a chain that is not there yet needs the other apply", () => {
  const p = plan((m) => m.chains.push({
    table: "inet t", id: "output", uid: "u1", rules: [], extra: [],
    type: "filter", hook: "output", prio: "filter", policy: "accept",
  }));
  assert.equal(p.why, "chain-new");
});

test("and so does a chain that has gone", () => {
  const m = parseNft(LIVE);
  m.chains = [];
  assert.equal(surgicalPlan(m, host(), { tables: OURS }).why, "chain-gone");
});

test("what a chain IS cannot be changed by a rule command", () => {
  for (const [field, to] of [["policy", "drop"], ["prio", "raw"], ["hook", "forward"]]) {
    const p = plan((m, ch) => { ch[field] = to; ch.rules[1].verdict = "drop"; });
    assert.equal(p.why, "chain-changed", `${field} went unnoticed`);
  }
});

/* The elements of a set are what the set is, and they live in `el`. Comparing
   `body` — which only lists which lines the declaration has — missed an
   elements list changing from end to end, which is precisely the silence this
   guard exists to prevent. Found by this test failing on its own fixture. */
test("a set whose elements moved is not a rule change", () => {
  const withSet = LIVE.replace("\tchain input", `\tset blocked {
		type ipv4_addr
		elements = { 10.0.0.1 }
	}

	chain input`);
  const m = parseNft(withSet);
  m.sets[0].el = ["10.0.0.2"];
  m.chains[0].rules[1].verdict = "drop";
  assert.equal(surgicalPlan(m, parseNft(withSet), { tables: OURS }).why, "sets-differ");
});

test("and neither is one that has grown a size or a timeout", () => {
  const withSet = LIVE.replace("\tchain input", `\tset blocked {
		type ipv4_addr
		elements = { 10.0.0.1 }
	}

	chain input`);
  const m = parseNft(withSet);
  m.sets[0].attr = { ...(m.sets[0].attr || {}), size: "65535" };
  m.chains[0].rules[1].verdict = "drop";
  assert.equal(surgicalPlan(m, parseNft(withSet), { tables: OURS }).why, "sets-differ");
});

test("a table this would have to create is not one to be surgical about", () => {
  const m = parseNft(LIVE);
  m.chains.push({ ...m.chains[0], table: "ip nat", uid: "u2", id: "postrouting", rules: [] });
  /* in scope, or it would not be being applied at all */
  assert.equal(surgicalPlan(m, host(), { tables: ["inet t", "ip nat"] }).why, "table-new");
});

/* ── scope ───────────────────────────────────────────────────────────────── */

test("a table outside the scope is not compared at all", () => {
  const other = LIVE + `
table ip other {
	chain c {
		type filter hook input priority filter; policy accept;
		tcp dport 99 counter accept # handle 2
	}
}`;
  const m = parseNft(other);
  m.chains.find((c) => c.table === "inet t").rules[1].verdict = "drop";
  /* the host has both tables; only ours is being replaced */
  const p = surgicalPlan(m, parseNft(other), { tables: OURS });
  assert.equal(p.ok, true, p.why);
  assert.deepEqual(p.commands, ["replace rule inet t input handle 3 tcp dport 22 counter drop"]);
});
