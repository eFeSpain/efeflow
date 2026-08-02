/* The order of operations is the safety net, so it is the thing to test.
 *
 * There is no host here and there does not need to be one: what matters is
 * that nothing is applied before there is a way back, and that a way back is
 * never left armed over a ruleset that was never applied — which would restore
 * the old one on top of whatever the user did in the next minute. */
import test from "node:test";
import assert from "node:assert/strict";

import { applyWithNet, keep, rollBackNow, pendingRollback } from "../src/apply.js";

const ok = (stdout = "") => ({ ok: true, stdout, stderr: "", code: 0 });
const no = (stderr) => ({ ok: false, stdout: "", stderr, code: 1 });

/* records every call in order, and answers whatever the test tells it to */
function fake(answers = {}) {
  const calls = [];
  const reply = (name, ...args) => {
    calls.push(name);
    const a = answers[name];
    return Promise.resolve(typeof a === "function" ? a(...args) : (a ?? ok()));
  };
  return {
    calls,
    nftArm: (...a) => reply("arm", ...a),
    nftApply: (...a) => reply("apply", ...a),
    nftDisarm: (...a) => reply("disarm", ...a),
    nftArmed: (...a) => reply("armed", ...a),
    nftRollback: (...a) => reply("rollback", ...a),
  };
}

const TARGET = { kind: "ssh", host: "fw1" };

test("nothing is applied before there is a way back", async () => {
  const api = fake({ arm: ok("table inet filter {\n}\n") });
  const r = await applyWithNet({ ruleset: "table inet filter {}", target: TARGET, seconds: 60, api });

  assert.deepEqual(api.calls, ["arm", "apply"]);
  assert.equal(r.ok, true);
  assert.equal(r.armed, true);
  assert.equal(r.backup, "table inet filter {\n}\n", "the ruleset it would go back to");
});

test("a host that cannot be armed is a host that is not touched", async () => {
  const api = fake({ arm: no("sudo: a password is required") });
  const r = await applyWithNet({ ruleset: "x", target: TARGET, seconds: 60, api });

  assert.deepEqual(api.calls, ["arm"], "the apply must not have been attempted");
  assert.equal(r.ok, false);
  assert.equal(r.stage, "arm");
  assert.match(r.error, /password/);
});

/* An armed rollback over a ruleset that was never applied is worse than no net
   at all: a minute later it restores the old ruleset over whatever came next. */
test("an apply that fails takes the net down with it", async () => {
  const api = fake({ apply: no("Error: syntax error, unexpected string") });
  const r = await applyWithNet({ ruleset: "nonsense", target: TARGET, seconds: 60, api });

  assert.deepEqual(api.calls, ["arm", "apply", "disarm"]);
  assert.equal(r.ok, false);
  assert.equal(r.stage, "apply");
  assert.equal(r.armed, false, "nothing is pending on the host");
});

test("turning the net off arms nothing, and says nothing was armed", async () => {
  const api = fake();
  const r = await applyWithNet({ ruleset: "x", target: TARGET, seconds: 0, api });

  assert.deepEqual(api.calls, ["apply"]);
  assert.equal(r.ok, true);
  assert.equal(r.armed, false);
});

test("a failed apply with no net does not disarm what was never armed", async () => {
  const api = fake({ apply: no("nope") });
  await applyWithNet({ ruleset: "x", target: TARGET, seconds: 0, api });
  assert.deepEqual(api.calls, ["apply"]);
});

test("the apply is always confirmed, because the far side refuses otherwise", async () => {
  let seen = null;
  const api = fake({ apply: (ruleset, target, confirmed) => { seen = confirmed; return ok(); } });
  await applyWithNet({ ruleset: "x", target: TARGET, seconds: 30, api });
  assert.equal(seen, true);
});

test("keeping a ruleset is the act that disarms", async () => {
  const api = fake();
  assert.deepEqual(await keep({ target: TARGET, api }), { ok: true, error: "" });
  assert.deepEqual(api.calls, ["disarm"]);
});

test("rolling back early does not wait for the timer", async () => {
  const api = fake();
  assert.equal((await rollBackNow({ target: TARGET, api })).ok, true);
  assert.deepEqual(api.calls, ["rollback"]);
});

/* A window closed mid-countdown leaves a host with a rollback pending on it,
   and the next session has no way to know unless it asks. */
test("a rollback left pending by an earlier session is discoverable", async () => {
  assert.equal(await pendingRollback({ target: TARGET, api: fake({ armed: ok("armed\n") }) }), true);
  assert.equal(await pendingRollback({ target: TARGET, api: fake({ armed: ok("clear\n") }) }), false);
  assert.equal(await pendingRollback({ target: TARGET, api: fake({ armed: no("no route to host") }) }), false);
});
