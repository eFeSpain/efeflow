import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, $, $$, click, setValue, until } from "./harness.js";

after(shutdown);

/* The simulator shipped broken because the suite covered evaluate() — the pure
   evaluator — and nothing covered runSim(), the part that draws it. These
   assertions exercise the drawing. */

const traceRows = () => $$("#trace .tr");
const enterSim = () => click('.rb[data-go="sim"]');

test("the screen arrives already run", async () => {
  await boot();
  enterSim();
  await until(() => $$("#lane .hop").length > 0);
  assert.ok($$("#lane .hop").length >= 2, "the packet path should be laid out");
  assert.ok($$("#lane .ev").length > 5, "rules should be listed");
});

test("the first trace row appears synchronously", async () => {
  await boot();
  enterSim();
  await until(() => traceRows().length > 0);
  const header = traceRows()[0];
  assert.match(header.textContent, /tcp|udp/, "the header should describe the packet");
  assert.match(header.textContent, /203\.0\.113\.47/);
});

test("the run reaches a verdict", async () => {
  await boot();
  enterSim();
  await until(() => $("#vb").classList.contains("show"), { timeout: 8000 });
  const verdict = $("#vb-txt").textContent.trim();
  assert.ok(["ACCEPT", "DROP", "REJECT"].includes(verdict), `unexpected verdict ${verdict}`);
  assert.ok($("#vb-why").textContent.trim().length > 10, "the verdict should explain itself");
});

test("the step counter is written, which is where the shadowed helper threw", async () => {
  await boot();
  enterSim();
  await until(() => /\d/.test($("#tr-count").textContent));
  assert.match($("#tr-count").textContent, /\d+\s*(steps|pasos)/);
});

test("changing a control re-runs and can change the verdict", async () => {
  await boot();
  enterSim();
  await until(() => $("#vb").classList.contains("show"), { timeout: 8000 });

  click('[data-preset="dnat"]');
  await until(() => $("#vb").classList.contains("show"), { timeout: 8000 });
  const withNat = $("#vb-txt").textContent.trim();

  click("#opt-nat"); // skip the nat hooks
  await until(() => $("#vb").classList.contains("show"), { timeout: 8000 });
  const withoutNat = $("#vb-txt").textContent.trim();

  assert.equal(withNat, "ACCEPT");
  assert.equal(withoutNat, "DROP", "without DNAT the packet has nothing to accept it");
  click("#opt-nat");
});

test("direction rewrites the path through the hooks", async () => {
  await boot();
  enterSim();
  click('#sim-dir [data-dir="out"]');
  await until(() => $$("#lane .hop").length > 0);
  const chains = $$("#lane .hop .c").map((n) => n.textContent.trim());
  assert.ok(chains.includes("output"), `egress should traverse output, got ${chains}`);
  assert.ok(!chains.includes("input"), "egress must not traverse input");
  click('#sim-dir [data-dir="in"]');
});

test("leaving the screen stops the animation", async () => {
  await boot();
  enterSim();
  await until(() => traceRows().length > 1);
  click('.rb[data-go="dash"]');
  const frozen = traceRows().length;
  await new Promise((r) => setTimeout(r, 400));
  assert.equal(traceRows().length, frozen, "the trace kept filling after navigating away");
});
