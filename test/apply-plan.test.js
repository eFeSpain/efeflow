/* What pressing Apply does, as opposed to how two texts differ.
 *
 * The dialog used to show one line: "3 it has that you have not, 1 that
 * differs". Three things were wrong with that and only the first is obvious.
 *
 * It counted every table on the host. A scoped apply emits `delete table` for
 * the project's own tables and leaves the rest standing, so on any machine
 * running Docker the box reported drift before every single apply, for ever,
 * about chains it was never going to touch. A warning that is always on is a
 * warning nobody reads, and this one sits in front of the button that can lock
 * you out of a firewall.
 *
 * It gave a direction that reads backwards. "3 it has that you have not"
 * sounds like something missing from your document. They are rules running on
 * that machine right now — fail2ban's bans, a colleague's hotfix — and what
 * the apply does to them is delete them.
 *
 * And it said nothing about the part that has no text. Measured on nft 1.1.6,
 * on a live kernel, not reasoned about:
 *
 *   before  tcp dport 22 handle 2     tcp dport 80  packets 5  handle 3
 *   after   tcp dport 25 handle 2     tcp dport 80  packets 0  handle 4
 *
 * One rule inserted at the top moved every handle under it and zeroed every
 * counter in the table, including rules nobody edited. Appending at the end
 * instead left the handles reading 2 and 3 exactly as before — reassigned from
 * scratch and coincidentally equal — while the counter still went 7 to 0.
 * Inferring "handles unchanged, nothing disturbed" from that is a lie about
 * the commonest case there is. */
import test from "node:test";
import assert from "node:assert/strict";
import { parseNft } from "../src/core/parse.js";
import { applyPlan, syncReport } from "../src/core/sync.js";

/* The real shape of this: you read the firewall, so your rules carry the
   host's handles, and then you changed one. Handles are what makes a rule the
   same rule, and without them an edit is indistinguishable from a delete and
   an unrelated insert — which is its own test, further down. */
const MINE = `table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		iif lo counter accept # handle 4
		tcp dport 22 counter accept # handle 5
	}
}`;

/* the same firewall as it is now: 22 still says drop, because your change has
   not been applied — and fail2ban has banned somebody since you read it */
const HOST = `table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		iif lo counter packets 12 bytes 800 accept # handle 4
		tcp dport 22 counter packets 3 bytes 180 drop # handle 5
		ip saddr 10.0.0.9 counter packets 40 bytes 2400 drop # handle 9
	}
}`;

const DOCKER = `
table ip docker {
	chain DOCKER {
		type nat hook prerouting priority dstnat; policy accept;
		iif "docker0" counter packets 7 bytes 400 return # handle 3
		tcp dport 8080 counter packets 2 bytes 120 dnat to 172.17.0.2:80 # handle 4
	}
	chain DOCKER-USER {
		type filter hook forward priority filter; policy accept;
		counter packets 55 bytes 3000 return # handle 5
	}
}`;

const model = () => parseNft(MINE);
const live = (extra = "") => parseNft(HOST + extra);
const OURS = ["inet filter"];

/* ── the false alarm ─────────────────────────────────────────────────────── */

test("a table the apply never touches is not drift", () => {
  const bare = syncReport(model(), live(), { tables: OURS });
  const withDocker = syncReport(model(), live(DOCKER), { tables: OURS });

  assert.equal(withDocker.added, bare.added,
    "Docker's chains counted as drift, on every apply, for ever");
  assert.equal(withDocker.inSync, bare.inSync);
});

/* Two fates, and calling both "rebuilt" flatters the worse one. Our own table
   is deleted and put back — the rules survive as text and lose their handles
   and counters. Docker's, under `flush ruleset`, is deleted and not put back. */
test("a table that is not rebuilt is not counted as rebuilt", () => {
  const p = applyPlan(model(), live(DOCKER));   // no scope: the whole ruleset

  assert.equal(p.recreated, 3, "only our own table's rules come back");
  assert.equal(p.dropped, 3, "Docker's three rules stop existing");
  assert.deepEqual(p.droppedTables, ["ip docker"]);
  assert.deepEqual(p.tables, ["inet filter"],
    "the tables being rebuilt may not include one that is only being deleted");
});

test("and with the scoped apply there is nothing dropped at all", () => {
  const p = applyPlan(model(), live(DOCKER), { tables: OURS });
  assert.equal(p.dropped, 0);
  assert.deepEqual(p.droppedTables, []);
});

test("but `flush ruleset` really does replace everything, and says so", () => {
  /* no scope given is the unscoped apply, and there every table is in play */
  const all = syncReport(model(), live(DOCKER));
  const ours = syncReport(model(), live(DOCKER), { tables: OURS });
  assert.ok(all.added > ours.added,
    "the whole-ruleset apply deletes Docker's tables and must count them");
});

test("the plan leaves out of scope what the apply leaves alone", () => {
  const p = applyPlan(model(), live(DOCKER), { tables: OURS });
  assert.deepEqual(p.tables, ["inet filter"]);
  assert.ok(!p.chains.some((c) => c.table === "ip docker"),
    "a chain that will still be running afterwards is in the plan of what changes");
});

/* ── the direction ───────────────────────────────────────────────────────── */

test("a rule only the host has is one this destroys, not one you are missing", () => {
  const p = applyPlan(model(), live(), { tables: OURS });
  const input = p.chains.find((c) => c.chain === "input");

  assert.equal(input.destroy.length, 1, "the rule fail2ban added while you were editing");
  assert.match(JSON.stringify(input.destroy[0]), /10\.0\.0\.9/);
  assert.equal(input.create.length, 0);
  assert.equal(input.change.length, 1, "dport 22 goes from drop to accept");
  assert.equal(input.change[0].from.pkts, 3, "and the plan carries what it is now, not only what it becomes");
  assert.equal(input.keep, 1, "iif lo is the same on both sides");
});

test("a chain the host has inside a table being replaced goes with the table", () => {
  /* a whole chain of theirs, in our table, that we know nothing about — it is
     deleted with the table and has to be shown, not quietly dropped */
  const withExtra = HOST.replace(/\n\}$/, `
	chain extra {
		type filter hook forward priority filter; policy drop;
		counter packets 1 bytes 60 drop # handle 7
	}
}`);
  const p = applyPlan(parseNft(MINE), parseNft(withExtra), { tables: OURS });

  const extra = p.chains.find((c) => c.chain === "extra");
  assert.ok(extra, "a whole chain of theirs vanished from the plan silently");
  assert.equal(extra.isGone, true);
  assert.equal(extra.destroy.length, 1);
});

/* Without handles there is nothing that says this line and that line are the
   same rule, so an edit reads as a removal and an addition. That is honest —
   the pairing genuinely does not know — but it is a different screen, and
   somebody who typed their ruleset here rather than reading it gets it. */
test("a ruleset typed here rather than read shows an edit as two lines", () => {
  const typed = MINE.replace(/ # handle \d+/g, "");
  const p = applyPlan(parseNft(typed), parseNft(HOST), { tables: OURS });
  const input = p.chains.find((c) => c.chain === "input");

  assert.equal(input.change.length, 0, "nothing can be paired, so nothing is a change");
  assert.equal(input.create.length, 1, "your dport 22 accept");
  assert.equal(input.destroy.length, 2, "their dport 22 drop, and the ban");
  assert.equal(input.keep, 1, "iif lo lines up by text and is identical");
});

/* ── the part with no text ───────────────────────────────────────────────── */

test("every rule in a replaced table is recreated, changed or not", () => {
  const p = applyPlan(model(), live(), { tables: OURS });
  assert.equal(p.recreated, 3, "all three rules of the table are rebuilt");
  const input = p.chains.find((c) => c.chain === "input");
  assert.equal(input.keep, 1);
  assert.ok(p.recreated > input.change.length + input.destroy.length,
    "the rule nobody edited is destroyed and rebuilt like the rest, and that is the point");
});

test("and the counters it costs are counted, in packets", () => {
  const p = applyPlan(model(), live(), { tables: OURS });
  assert.equal(p.counting, 3, "three rules on the host carry a counter");
  assert.equal(p.packets, 12 + 3 + 40, "the traffic those counters have seen, all of it lost");
});

test("a ruleset identical to the host still costs its counters", () => {
  /* the case that has no diff at all and is still not free */
  const same = parseNft(HOST);
  const p = applyPlan(same, parseNft(HOST), { tables: OURS });
  assert.equal(p.identical, true, "nothing differs");
  assert.equal(p.recreated, 3);
  assert.equal(p.packets, 55, "and applying it anyway would still zero 55 packets");
});

/* ── an empty host ───────────────────────────────────────────────────────── */

test("a firewall with nothing on it costs nothing and creates everything", () => {
  const p = applyPlan(model(), parseNft(""), { tables: OURS });
  assert.equal(p.recreated, 0);
  assert.equal(p.packets, 0);
  assert.equal(p.identical, false);
  const input = p.chains.find((c) => c.chain === "input");
  assert.equal(input.isNew, true);
  assert.equal(input.create.length, 2);
  assert.equal(input.destroy.length, 0);
});
