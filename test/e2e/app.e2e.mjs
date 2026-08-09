/* The application, running, driven.
 *
 * Every scenario here is a defect that got through the other 986 tests and was
 * found by hand. That is the entry requirement: this file is slow and it is
 * Windows-only, so it earns its place by covering what jsdom cannot reach —
 * the Tauri bridge, the real webview, and the moment a screen is first drawn.
 */
import test, { before, after } from "node:test";
import assert from "node:assert/strict";
import { launch, shutdown, reset, unavailable, SSH, SCREENS, goTo, visible, text }
  from "./harness.mjs";

const why = unavailable();
if (why) {
  console.log(`\n  the end-to-end run was skipped: ${why}\n`);
  process.exit(0);
}

let page, errors;
before(async () => { ({ page, errors } = await launch()); }, { timeout: 90000 });
after(shutdown);

const noErrors = (what) => {
  const real = errors.filter((e) => !/favicon|ERR_FILE_NOT_FOUND/i.test(e));
  assert.deepEqual(real, [], `${what} put errors in the console`);
};

/* ── a project with nothing in it ────────────────────────────────────────
   The state the application opens in, and the one every test and every smoke
   run skipped past by importing something first. Opening the simulator on it
   threw: the verdict named a chain that did not exist and the banner
   dereferenced it. */
test("every screen draws on a blank project", async () => {
  await reset(page);
  errors.length = 0;

  for (const id of SCREENS) {
    await goTo(page, id);
    assert.equal(await page.evaluate((i) => document.querySelector("#s-" + i)?.classList.contains("on"), id),
      true, `${id} did not come up`);
  }
  noErrors("walking every screen with nothing loaded");
});

test("and the simulator says why rather than showing nothing", async () => {
  await goTo(page, "sim");
  const why = await text(page, "#vb-why");
  assert.match(why ?? "", /no chains|ninguna cadena/i,
    "an empty ruleset needs a sentence, not a blank panel");
});

/* ── nothing is contacted until somebody asks ────────────────────────────
   Boot used to probe, which is two ssh connections and sixteen seconds of
   timeout on a host that is away, before the window had settled. */
test("boot contacts no host, and says it has not", async () => {
  await reset(page, SSH);
  assert.match(await text(page, "#tb-target-t") ?? "", /not connected|sin conectar/i,
    "the chip claims a connection nobody asked for");
  assert.match(await page.evaluate(() => document.querySelector("#tb-target").title), /fw\.example/,
    "and the destination has to still be visible somewhere");
});

test("opening the target dialog is asking, so it asks", async () => {
  await page.evaluate(() => document.querySelector("#tb-target").click());
  await page.waitForTimeout(2500);
  assert.equal(await visible(page, "#scrim-target"), true);
  assert.match(await text(page, "#tb-target-t") ?? "", /netops@fw\.example/,
    "a host that answered may be named; this one did");
  await page.evaluate(() => document.querySelectorAll("#scrim-target [data-close]").forEach((b) => b.click()));
  await page.waitForTimeout(300);
});

/* ── reading a firewall, and what applying to it would do ────────────────── */

test("Read from host brings back what the host says", async () => {
  await page.evaluate(() => document.querySelector("#scrim-import").classList.add("on"));
  await page.waitForTimeout(300);
  await page.click("#imp-host");
  await page.waitForTimeout(3000);

  const read = await page.evaluate(() => document.querySelector("#imp-text").value);
  assert.match(read, /efeflow_live/, "the ruleset the stand-in serves did not arrive");
  assert.match(read, /handle 5/, "the handles came back — a rule cannot be replaced without one");
  assert.equal(await page.evaluate(() => document.querySelector("#imp-go").disabled), false);

  await page.click("#imp-go");
  await page.waitForTimeout(1500);
  /* Reading a host reads all of it — the firewall's own table and Docker's,
     which is the point of the scoped apply existing at all. */
  const chains = await page.evaluate(() =>
    [...new Set([...document.querySelectorAll(".rule[data-chain]")].map((e) => e.dataset.chain))]);
  assert.deepEqual(chains.sort(), ["inet efeflow_live/input", "ip docker/DOCKER"],
    "both of the host's tables should have come in");
});

/* The apply dialog is the screen in front of the one operation that can lock
   somebody out, and it has to be right about three separate things: what it
   will do, what that costs, and that Docker is not its business. */
test("editing a rule keeps its handle, so the apply is a replacement", async () => {
  await page.evaluate(() => {
    [...document.querySelectorAll(".rule[data-chain]")].find((e) => /dport 443/.test(e.textContent))?.click();
  });
  await page.waitForTimeout(600);
  assert.match(await text(page, "#f-raw") ?? "", /dport 443/, "the inspector is on the wrong rule");

  await page.focus("#f-raw");
  await page.waitForTimeout(200);
  await page.evaluate(() => {
    const el = document.querySelector("#f-raw");
    el.textContent = "tcp dport 8443 counter accept";
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.blur();
  });
  await page.waitForTimeout(800);

  await page.evaluate(() => document.querySelector("#val-apply").click());
  await page.waitForTimeout(4000);

  const cost = await text(page, "#ap-plan-cost");
  assert.match(cost ?? "", /1 reemplazada|1 replaced/,
    "an edit that keeps its handle is one replace, not a delete and an insert");
  assert.match(cost ?? "", /conservan sus handles|keep their handles/);

  /* the drift warning is about somebody else's rules, and there are none */
  assert.equal(await visible(page, "#ap-drift"), false,
    "it read a rule the user had just edited as drift on the host");

  /* Docker came in with the read, so it is one of the project's tables now and
     matches the host exactly. Nothing about it differs, so nothing about it is
     drawn — the panel is what changes, not what exists. */
  const panel = await page.evaluate(() =>
    [...document.querySelectorAll("#ap-plan .ch")].map((e) => e.textContent).join(" | "));
  assert.deepEqual(panel, "inet efeflow_live · input",
    "the panel should show the one chain that changed and nothing else");
  assert.equal(await page.evaluate(() => document.querySelector("#ap-go").disabled), false);

  /* and it has to read as a change rather than as a deletion followed by an
     unrelated addition, which is what `−` then `+` looks like */
  const lines = await page.evaluate(() =>
    [...document.querySelectorAll("#ap-plan .ln")].map((e) => ({
      mark: e.querySelector("i")?.textContent,
      cls: e.className.replace("ln ", ""),
      rule: e.querySelector("span")?.textContent,
    })));
  assert.deepEqual(lines.map((l) => l.mark), ["~", "~"],
    "one rule changed, so two lines and one mark");
  assert.deepEqual(lines.map((l) => l.cls), ["was", "now"]);
  assert.match(lines[0].rule, /dport 443/);
  assert.match(lines[1].rule, /dport 8443/);
});

/* The scope decides what the apply replaces, so it decides what the screen has
   to warn about — and switching between them is a question about the reading
   already in hand, not a reason to go back to the host. */
test("switching the scope redraws from the reading already taken", async () => {
  const before = await text(page, "#ap-plan-cost");
  await page.evaluate(() => document.querySelector('#ap-scope [data-scope="ruleset"]').click());
  await page.waitForTimeout(600);
  const after = await text(page, "#ap-plan-cost");

  assert.notEqual(before, after, "the cost of the two scopes cannot be the same sentence");
  assert.match(after ?? "", /reconstruyen|rebuilt/,
    "`flush ruleset` rebuilds every table it replaces, and has to say so");
  assert.match(before ?? "", /conservan sus handles|keep their handles/,
    "where the scoped apply is surgical, that is what it should have said");

  /* it read the host once, on the way in */
  assert.match(await text(page, "#ap-plan-cost") ?? "", /leído hace|read \d+s ago/);
  noErrors("the apply dialog");
});

/* ── a host that answers and refuses to be read ──────────────────────────
   Silence here was the defect: `could not read` and `nothing has changed`
   left by the same door, in front of the button that can lock you out. */
test("a host that will not be read is said out loud, and Apply still works", async () => {
  await shutdown();
  ({ page, errors } = await launch({ EFEFLOW_FAKE_FAIL: "read" }));
  await reset(page, SSH);

  await page.evaluate(() => document.querySelector("#val-apply").click());
  await page.waitForTimeout(5000);

  assert.equal(await visible(page, "#ap-plan-fld"), false,
    "an empty diff is a claim that nothing changes");
  assert.equal(await visible(page, "#ap-drift"), true, "and it said nothing at all");
  assert.match(await text(page, "#ap-drift") ?? "", /No se ha podido leer|Could not read/);
  assert.equal(await page.evaluate(() => document.querySelector("#ap-go").disabled), false,
    "blocking the urgent operation teaches people to apply blind");
});
