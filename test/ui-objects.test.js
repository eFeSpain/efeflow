/* Making, changing and removing the things a table holds besides chains.
 *
 * Flowtables, named counters and quotas, ct helpers: all carried verbatim
 * through an import for a while, all impossible to touch. You could look at
 * your offload flowtable and not add a device to it. */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, newRuleset, $, $$, click, setValue, settle } from "./harness.js";
import { MODEL } from "../src/core/model.js";
import { generate } from "../src/core/generate.js";
import { readObject } from "../src/core/objects.js";

after(shutdown);

const code = () => generate(MODEL).join("\n");
const RULESET = `table inet filter {
	flowtable ft {
		hook ingress priority filter
		devices = { eth0 }
	}

	counter http_hits {
		packets 12 bytes 900
	}

	ct timeout aggressive {
		protocol tcp
		policy = { established: 100 }
	}

	chain forward {
		type filter hook forward priority filter; policy drop;
		ip protocol { tcp, udp } flow add @ft
		tcp dport 80 counter name "http_hits" accept
	}
}`;

async function load() {
  await newRuleset();
  const area = $("#imp-text");
  area.value = RULESET;
  area.dispatchEvent(new globalThis.window.Event("input", { bubbles: true }));
  click("#imp-go");
  await settle(100);
  click('.rb[data-go="sets"]');
  await settle(80);
}

const pick = (name) => {
  const i = MODEL.sets.length + MODEL.objects.findIndex((o) => o.name === name);
  click($$(".set-item")[i]);
  return settle(60);
};

test("objects share the list with sets and maps", async () => {
  await boot();
  await load();
  const names = $$(".set-item .nm").map((n) => n.textContent);
  for (const n of ["ft", "http_hits", "aggressive"])
    assert.ok(names.includes(n), `${n} is not in the list`);
});

test("a flowtable's devices are a field, and the source follows", async () => {
  await boot();
  await load();
  await pick("ft");

  assert.ok($("#obj-devices"), "no devices field");
  assert.equal($("#obj-devices").value, "eth0");

  setValue("#obj-devices", "eth0, eth1", "change");
  await settle(60);
  assert.match(code(), /devices = \{ eth0, eth1 \}/);
  assert.match(code(), /hook ingress priority filter/, "the line beside it was left alone");
});

/* A kind with no fields is the reason the body is what is kept. */
test("a kind nothing models is edited as the source it is", async () => {
  await boot();
  await load();
  await pick("aggressive");

  assert.equal($("#obj-protocol"), null, "ct timeout has no typed fields here");
  assert.ok($("#obj-body"), "and must therefore have its source");

  setValue("#obj-body", "protocol tcp\npolicy = { established: 7200, close: 4 }", "change");
  await settle(60);
  assert.match(code(), /established: 7200, close: 4/);
});

test("renaming one takes the rules that name it along", async () => {
  await boot();
  await load();
  await pick("http_hits");

  setValue("#obj-name", "web_hits", "change");
  await settle(80);
  assert.match(code(), /counter web_hits \{/);
  assert.match(code(), /counter name "web_hits"/, "the rule still reaches it");
});

test("one that a rule names cannot be deleted out from under it", async () => {
  await boot();
  await load();
  await pick("ft");
  assert.equal($("#obj-del").disabled, true);
  assert.match($("#obj-del").title, /1/);
});

test("one nothing names can be, and says it is unused until then", async () => {
  await boot();
  await load();
  await pick("aggressive");
  assert.equal($("#obj-del").disabled, false);

  const before = MODEL.objects.length;
  click("#obj-del");
  await settle(80);
  assert.equal(MODEL.objects.length, before - 1);
  assert.doesNotMatch(code(), /ct timeout aggressive/);
});

/* A flowtable with no device is a ruleset nft refuses, and the template ships
   without one on purpose rather than inventing a device name. */
test("a new flowtable says what it is still missing", async () => {
  await boot();
  await newRuleset();
  click('.rb[data-go="sets"]');
  await settle(60);
  click("#obj-new");
  await settle(60);
  click('.ctx [data-act="flowtable"]');
  await settle(80);

  assert.equal(MODEL.objects.at(-1).kind, "flowtable");
  assert.equal(readObject(MODEL.objects.at(-1)).devices, "");
  assert.match($("#obj-warn").textContent, /device|dispositivo/i);
});
