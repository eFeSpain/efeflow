/* A rule the analyser cannot read whole is a rule it cannot reason about.
 *
 * criteria() extracts the ten things it knows and ignores the rest, so a rule
 * reading `meta mark 0x1 counter drop` came back with no criteria at all —
 * which is how this file spells "matches every packet". Everything below it
 * was reported shadowed by it, each with a one-click Delete.
 *
 * That is the same defect as `ip protocol` being unread, and fixing that one
 * instance did not fix the class. The class is fixed by refusing to reason,
 * which is what the file already does for a rate limit and a negation: a rule
 * that might match far less than it appears to cannot be said to cover
 * anything.
 *
 * The direction matters and is not symmetric. If A carries something unread, A
 * may match less than it looks and cannot be claimed to cover B. If B does, B
 * matches less than it looks, and a rule covering the looser reading of B
 * covers the tighter one too — so that stays reportable. */
import test, { after } from "node:test";
import assert from "node:assert/strict";

import { boot, shutdown, importFixture, $, click, settle } from "./harness.js";
import { MODEL } from "../src/core/model.js";
import { criteria, subsumes, overlaps, analyse } from "../src/core/analyse.js";

/* the last test boots the interface, and every file that does tears it down */
after(shutdown);

const c = (e) => criteria(e);

test("a rule it reads whole is not marked unreadable", () => {
  for (const e of [
    "tcp dport 22 ip saddr 10.0.0.1",
    "ct state established,related",
    'iifname "wan0" tcp dport { 80, 443 }',
    "ip protocol icmp",
    "tcp dport 22 counter",
    'ip saddr 10.0.0.1 log prefix "x " counter',
  ])
    assert.equal(c(e)._opaque, false, e);
});

test("a rule carrying something it cannot read says so", () => {
  for (const e of ["meta mark 0x1", "ct mark 0x9", "vlan id 30", "meta skuid 1000",
                   "fib saddr . iif oif missing", "tcp dport 22 meta mark 0x1"])
    assert.equal(c(e)._opaque, true, e);
});

/* Read as an interface constraint, `fib saddr . iif oif missing` did not come
   back with nothing — it came back with iif "oif" and oif "missing", criteria
   invented out of the middle of a lookup. */
test("a fib lookup is not mistaken for an interface constraint", () => {
  const f = c("fib saddr . iif oif missing");
  assert.equal(f.iif, undefined);
  assert.equal(f.oif, undefined);
});

test("a rule that might match less than it looks covers nothing", () => {
  assert.ok(!subsumes(c("meta mark 0x1"), c("tcp dport 22")));
  assert.ok(!subsumes(c("fib saddr . iif oif missing"), c("tcp dport 443")));
});

/* The other direction stays reportable: a genuinely broad rule above a narrow
   one still shadows it, whatever else the narrow one carries. */
test("something unread in the lower rule does not silence the finding", () => {
  assert.ok(subsumes(c("tcp dport 22"), c("tcp dport 22 meta mark 0x1")));
});

test("an overlap nobody can be sure of is not asserted", () => {
  assert.ok(!overlaps(c("tcp dport 8443 meta mark 0x1"), c("tcp dport 8443")));
  assert.ok(overlaps(c("tcp dport 8443"), c("tcp dport 8443 ip saddr 10.0.0.1")));
});

test("the rules under an unreadable one are not called dead", (t) => {
  const saved = { chains: MODEL.chains, sets: MODEL.sets };
  t.after(() => { MODEL.chains = saved.chains; MODEL.sets = saved.sets; });

  MODEL.sets = [];
  MODEL.chains = [{
    id: "input", table: "inet filter", hook: "input", prio: 0, type: "filter",
    policy: "drop", rules: [
      { expr: "meta mark 0x1", verdict: "drop", on: true, pkts: 0, bytes: 0 },
      { expr: "tcp dport 22 ip saddr 10.0.0.1", verdict: "accept", on: true, pkts: 0, bytes: 0 },
      { expr: "tcp dport 443", verdict: "accept", on: true, pkts: 0, bytes: 0 },
    ],
  }];
  assert.deepEqual(analyse().filter((f) => f.kind === "shadowed").map((f) => f.i + 1), []);
});

/* Refusing to reason is only honest if it is said out loud: a list with
   nothing in it, over a ruleset half of which was never read, is a clean bill
   of health that was never issued. */
test("the validation screen says how many rules it left alone", async () => {
  await boot();
  await importFixture();
  click('.rb[data-go="validate"]');
  await settle(150);
  /* the fixture has one: `meta iifname "wan0" ip saddr 10.0.0.0/8` is read,
     but its `ct status dnat` sibling and the icmp type rule are not */
  assert.match($("#val-sub").textContent, /cannot read|no sabe leer/);
});

/* Refusing to reason must not turn the analyser off. A rule it reads whole,
   above one it reads whole, is still a finding. */
test("it still finds what it could always find", (t) => {
  const saved = { chains: MODEL.chains, sets: MODEL.sets };
  t.after(() => { MODEL.chains = saved.chains; MODEL.sets = saved.sets; });

  MODEL.sets = [];
  MODEL.chains = [{
    id: "input", table: "inet filter", hook: "input", prio: 0, type: "filter",
    policy: "drop", rules: [
      { expr: "ip saddr 10.0.0.0/8", verdict: "drop", on: true, pkts: 0, bytes: 0 },
      { expr: "ip saddr 10.1.0.0/16 tcp dport 22", verdict: "accept", on: true, pkts: 0, bytes: 0 },
    ],
  }];
  assert.deepEqual(analyse().filter((f) => f.kind === "shadowed").map((f) => f.i + 1), [2]);
});
