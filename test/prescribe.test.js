/* The inverse simulator, held to the forward one.
 *
 * The claim is "add this rule and the packet is accepted". A claim like that
 * has a consequence the forward evaluator can be held to: insert the rule where
 * it says, run the same simulation again, and the verdict must be accept. So
 * that is the test — derive, insert, re-run — the same propose-then-prove the
 * feature does in the UI, done to every case here.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { MODEL, R } from "../src/core/model.js";
import { parseNft } from "../src/core/parse.js";
import { evaluate, PRESETS } from "../src/core/simulate.js";
import { prescribe } from "../src/core/prescribe.js";

const load = (nft) => {
  const p = parseNft(nft);
  MODEL.chains = p.chains; MODEL.sets = p.sets;
  MODEL.objects = p.objects; MODEL.tables = p.tables; MODEL.prelude = p.prelude;
};

/* Apply a prescription to MODEL the way the UI would, then say what happens. */
function applyAndRerun(rx, packet) {
  const ch = MODEL.chains.find((c) => c === rx.chain);
  const [expr, verdict] = [rx.rule.replace(/\s+accept$/, ""), "accept"];
  ch.rules.splice(rx.at, 0, R(expr, verdict));
  return evaluate(packet).final.v;
}

const FILTER = `table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		iif "lo" accept
		tcp dport 22 accept
	}
}`;

test("a packet dropped by policy gets a rule that makes it accepted", () => {
  load(FILTER);
  const packet = { ...PRESETS.https, flags: [...PRESETS.https.flags] }; // dport 443, dropped by policy
  assert.equal(evaluate(packet).final.v, "drop", "the fixture must drop it to begin with");

  const rx = prescribe(packet);
  assert.equal(rx.already, undefined);
  assert.equal(rx.chain.id, "input", "the chain that decides it");
  assert.ok(rx.blocker.policy, "nothing matched — it fell through to the policy");
  assert.match(rx.rule, /tcp dport 443/, "the rule pins the packet's service");
  assert.match(rx.rule, /accept$/);

  assert.equal(applyAndRerun(rx, packet), "accept", "and inserting it makes the packet accepted");
});

test("a packet dropped by a specific rule gets the fix in front of that rule", () => {
  load(`table inet filter {
	chain input {
		type filter hook input priority filter; policy accept;
		ip saddr 203.0.113.0/24 drop
		tcp dport 22 accept
	}
}`);
  const packet = { ...PRESETS.ssh, saddr: "203.0.113.47", flags: [...PRESETS.ssh.flags] };
  assert.equal(evaluate(packet).final.v, "drop", "the blocklist rule drops it");

  const rx = prescribe(packet);
  assert.equal(rx.blocker.policy, undefined, "a rule stopped it, not the policy");
  assert.equal(rx.at, 0, "the fix goes before the rule that drops it");
  assert.equal(applyAndRerun(rx, packet), "accept");
});

test("a packet already accepted needs nothing", () => {
  load(FILTER);
  const packet = { ...PRESETS.ssh, flags: [...PRESETS.ssh.flags] }; // dport 22, accepted
  assert.equal(evaluate(packet).final.v, "accept");
  assert.deepEqual(prescribe(packet), { already: true });
});

test("a ruleset with no chains accepts everything, so there is nothing to add", () => {
  /* an empty ruleset stops nothing — every packet is accepted, and the honest
     answer is that no rule is needed, not that one is impossible */
  load(`table inet filter { }`);
  const packet = { ...PRESETS.ssh, flags: [...PRESETS.ssh.flags] };
  assert.equal(evaluate(packet).final.v, "accept");
  assert.deepEqual(prescribe(packet), { already: true });
});

test("the prescription carries the trace's own uncertainty", () => {
  /* A non-terminal rule the evaluator cannot read fully makes the forward run
     unsure on its way to the policy drop. The prescription must not claim more
     certainty than the run it came from. */
  load(`table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		meta mark 0x1 counter
		tcp dport 22 accept
	}
}`);
  const packet = { ...PRESETS.https, flags: [...PRESETS.https.flags] };
  const forward = evaluate(packet);
  assert.equal(forward.final.v, "drop");
  assert.equal(forward.sure, false, "the meta mark rule was assumed, not read");
  assert.equal(prescribe(packet).sure, false, "and the prescription inherits that");
});

test("an egress packet is pinned by where it is going, not where it is from", () => {
  load(`table inet filter {
	chain output {
		type filter hook output priority filter; policy drop;
	}
}`);
  const packet = { ...PRESETS.egress, flags: [...PRESETS.egress.flags] };
  const rx = prescribe(packet);
  assert.match(rx.rule, /oifname|daddr/, "the rule matches the output side of the packet");
  assert.equal(applyAndRerun(rx, packet), "accept");
});
