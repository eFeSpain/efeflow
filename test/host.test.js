/* Three conversations with a running host, and the refusals that matter.
 *
 * No host here and none needed: what is being tested is the ordering and the
 * conditions under which each of them declines. */
import test from "node:test";
import assert from "node:assert/strict";

import { parseNft } from "../src/core/parse.js";
import { refreshCounters, checkDrift, pushRule } from "../src/host.js";

const LIVE = `table inet filter {
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related counter packets 900 bytes 70000 accept # handle 4
		iif lo counter packets 12 bytes 800 accept # handle 5
		tcp dport 22 counter packets 3 bytes 180 accept # handle 6
	}
}`;
const COLD = LIVE.replace(/packets \d+ bytes \d+/g, "packets 0 bytes 0");
const TARGET = { kind: "ssh", host: "fw1" };

function fake(answers = {}) {
  const calls = [];
  const reply = (name, ...args) => {
    calls.push({ name, args });
    const a = answers[name];
    return Promise.resolve(typeof a === "function" ? a(...args) : (a ?? { ok: true, stdout: LIVE, stderr: "", code: 0 }));
  };
  return {
    calls,
    nftList: (...a) => reply("list", ...a),
    nftRuleOp: (...a) => reply("op", ...a),
  };
}

test("counters come back from the host and land on their rules", async () => {
  const model = parseNft(COLD);
  const r = await refreshCounters({ model, target: TARGET, api: fake() });
  assert.equal(r.ok, true);
  assert.equal(r.updated, 3);
  assert.deepEqual(model.chains[0].rules.map((x) => x.pkts), [900, 12, 3]);
});

test("a host that will not answer changes nothing and says why", async () => {
  const model = parseNft(COLD);
  const api = fake({ list: { ok: false, stdout: "", stderr: "no route to host", code: 1 } });
  const r = await refreshCounters({ model, target: TARGET, api });
  assert.equal(r.ok, false);
  assert.match(r.error, /no route/);
  assert.equal(model.chains[0].rules[0].pkts, 0, "nothing was written on a failed read");
});

test("a ruleset that matches the host reports no drift", async () => {
  const r = await checkDrift({ model: parseNft(LIVE), target: TARGET, api: fake() });
  assert.equal(r.inSync, true);
  assert.equal(r.added, 0);
  assert.equal(r.missing, 0);
});

/* The case the scoped apply cannot see: something else editing your own table
   while you work. */
test("rules something else added on the host are counted", async () => {
  const withBan = LIVE.replace(
    "\t\ttcp dport 22 counter",
    "\t\tip saddr 203.0.113.9 counter packets 4 bytes 200 drop # handle 8\n\t\ttcp dport 22 counter",
  );
  const api = fake({ list: { ok: true, stdout: withBan, stderr: "", code: 0 } });
  const r = await checkDrift({ model: parseNft(LIVE), target: TARGET, api });
  assert.equal(r.added, 1);
  assert.equal(r.inSync, false);
});

test("one rule can be pushed by its handle", async () => {
  const model = parseNft(LIVE);
  const api = fake();
  const r = await pushRule({ model, chain: model.chains[0], index: 2,
                             op: "replace", target: TARGET, api });
  assert.equal(r.ok, true);
  assert.equal(r.handle, 6);

  const op = api.calls.find((c) => c.name === "op").args[0];
  assert.equal(op.op, "replace");
  assert.equal(op.table, "inet filter");
  assert.equal(op.chain, "input");
  assert.equal(op.handle, 6);
  assert.match(op.rule, /tcp dport 22/);
});

test("it reads the host first, and only then acts", async () => {
  const model = parseNft(LIVE);
  const api = fake();
  await pushRule({ model, chain: model.chains[0], index: 2, op: "delete", target: TARGET, api });
  assert.deepEqual(api.calls.map((c) => c.name), ["list", "op"]);
});

/* The refusal that the whole of core/sync.js exists for. */
test("it refuses when the host no longer agrees about the chain", async () => {
  const withBan = LIVE.replace(
    "\t\ttcp dport 22 counter",
    "\t\tip saddr 203.0.113.9 counter packets 4 bytes 200 drop # handle 8\n\t\ttcp dport 22 counter",
  );
  const api = fake({ list: { ok: true, stdout: withBan, stderr: "", code: 0 } });
  const model = parseNft(LIVE);
  const r = await pushRule({ model, chain: model.chains[0], index: 2,
                             op: "delete", target: TARGET, api });
  assert.equal(r.ok, false);
  assert.equal(r.error, "unaddressable");
  assert.deepEqual(api.calls.map((c) => c.name), ["list"], "nothing was sent");
});

test("a rule edited here cannot be pushed until the host has it", async () => {
  const model = parseNft(LIVE);
  model.chains[0].rules[2].expr = "tcp dport 2222";
  const api = fake();
  const r = await pushRule({ model, chain: model.chains[0], index: 2,
                             op: "delete", target: TARGET, api });
  assert.equal(r.ok, false);
  assert.deepEqual(api.calls.map((c) => c.name), ["list"]);
});

test("a rule with no handle is never pushed", async () => {
  const model = parseNft(LIVE.replace(/ # handle \d+/g, ""));
  const api = fake();
  const r = await pushRule({ model, chain: model.chains[0], index: 2,
                             op: "delete", target: TARGET, api });
  assert.equal(r.ok, false);
  assert.deepEqual(api.calls.map((c) => c.name), ["list"]);
});

test("nft refusing the change is reported as nft said it", async () => {
  const model = parseNft(LIVE);
  const api = fake({ op: { ok: false, stdout: "", stderr: "Error: Could not process rule", code: 1 } });
  const r = await pushRule({ model, chain: model.chains[0], index: 2,
                             op: "delete", target: TARGET, api });
  assert.equal(r.ok, false);
  assert.match(r.error, /Could not process/);
});
