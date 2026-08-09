/* Names out of a file are text, not markup.
 *
 * eFeFlow's whole job is to take in a ruleset somebody else wrote — pasted
 * from a host, opened from a file a colleague sent. Chain and table names went
 * from there straight into innerHTML, and esc() escaped `&`, `<` and `>` but
 * not the quote that closes an attribute. Opening a project with a crafted
 * chain name ran script: verified in a browser, not inferred.
 *
 * The desktop app has a strict CSP and was never the exposed half. The browser
 * path the README documents had none at all. */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, $, $$, click, settle } from "./harness.js";
import { MODEL } from "../src/core/model.js";

after(shutdown);

const PAYLOAD = 'a"><img src=x onerror=window.__pwned=1>';

/* app.js wants a document, so it is reached the way the other UI tests reach
   it: after boot, not at the top of the file. */
test("esc closes the attribute it is used inside", async () => {
  await boot();
  const { esc } = await import("../src/app.js");
  assert.equal(esc('a"b'), "a&quot;b");
  assert.equal(esc("a'b"), "a&#39;b");
  assert.equal(esc("<script>"), "&lt;script&gt;");
  assert.equal(esc("a&b"), "a&amp;b");
  assert.equal(esc('<a href="x">'), "&lt;a href=&quot;x&quot;&gt;");
});

async function openHostileProject(chainId) {
  const win = globalThis.window;
  const input = $('input[type="file"]');
  const text = JSON.stringify({
    app: "eFeFlow", v: 1, name: "shared-by-a-colleague",
    scratch: { ifaces: [], networks: [] },
    chains: [{ id: chainId, table: "inet filter", hook: "input", prio: 0,
               type: "filter", policy: "drop",
               rules: [{ expr: "tcp dport 22", verdict: "accept", on: true }] }],
    sets: [],
  });
  const file = new win.File([text], "shared.efeflow.json", { type: "application/json" });
  Object.defineProperty(input, "files", { value: [file], configurable: true });
  input.dispatchEvent(new win.Event("change", { bubbles: true }));
  await settle(200);
}

/* Every screen, because a name reaches most of them: the canvas card, the
   properties path, the findings, the topology, the dashboard hook map, the
   simulator trace and the verdict banner. Five of those were still writing it
   as markup after the obvious three were fixed. */
const SCREENS = ["editor", "validate", "sets", "topo", "code", "dash", "sim"];
const injected = () => $$('img[src="x"], [onerror]').length;

test("a chain name from a project file cannot bring an element with it", async () => {
  await boot();
  await openHostileProject(PAYLOAD);

  assert.equal(MODEL.chains[0].id, PAYLOAD, "the name is kept as it was written");
  for (const id of SCREENS) {
    click(`.rb[data-go="${id}"]`);
    await settle(120);
    assert.equal(injected(), 0, `the name became markup on the ${id} screen`);
  }

  click('.rb[data-go="editor"]');
  await settle(120);
  const card = $(".chain .cn");
  assert.ok(card, "the chain should still render");
  assert.equal(card.textContent, PAYLOAD, "and read as the text it is");
});

test("the same name in a table cannot either", async () => {
  await boot();
  await openHostileProject("input");
  MODEL.chains[0].table = `inet ${PAYLOAD}`;
  click('.rb[data-go="editor"]');
  click($$("#chains .rule")[0]);
  await settle(200);

  assert.equal($$("#chains img, .props img").length, 0);
  assert.equal($$('[onerror]').length, 0);
});

/* A set name reaches the rule list, the library and the back-reference panel. */
test("a set name cannot either", async () => {
  await boot();
  await openHostileProject("input");
  MODEL.sets = [{ n: PAYLOAD, t: "ipv4_addr", f: "", el: ["10.0.0.1"], kind: "set", table: "inet filter" }];
  click('.rb[data-go="sets"]');
  await settle(200);

  assert.equal($$("#s-sets img").length, 0);
  assert.equal($$('[onerror]').length, 0);
});

/* The desktop app is covered by the CSP in tauri.conf.json. `npm run dev` and
   anything served from the built files are not, and that is the path the
   README tells people to use. */
test("the browser path declares a content security policy of its own", async () => {
  const { readFileSync } = await import("node:fs");
  const html = readFileSync(new URL("../index.html", import.meta.url), "utf8");
  const meta = html.match(/<meta[^>]+http-equiv=["']Content-Security-Policy["'][^>]*>/i);
  assert.ok(meta, "index.html has no CSP, so the browser path has no floor under it");
  assert.match(meta[0], /script-src[^;"]*'self'/, "scripts must come from the app");
  assert.doesNotMatch(meta[0], /script-src[^;"]*'unsafe-inline'/,
    "an inline script is exactly what an injected name would be");

  /* and the policy has to be one the page can actually keep: an inline script
     in the markup would need unsafe-inline back, which is the whole hole */
  assert.doesNotMatch(html, /<script(?![^>]*\ssrc=)[^>]*>/i,
    "an inline <script> would force unsafe-inline back into the policy");
});

/* Two policies apply to this document in the desktop app — this one and the
 * one in tauri.conf.json — and a request has to pass both, so the strictest
 * wins. tauri.conf allows `ipc: http://ipc.localhost`, which is how the
 * frontend reaches Rust; the meta tag said `connect-src 'self'` and refused
 * it. Every call the application made logged a violation and fell back to the
 * slower transport. It worked, which is why it went unnoticed until a console
 * was watched during a smoke test.
 *
 * The two origins do not exist in a browser, so naming them costs the browser
 * path nothing. */
test("the two policies do not contradict each other about the bridge", async () => {
  const { readFileSync } = await import("node:fs");
  const html = readFileSync(new URL("../index.html", import.meta.url), "utf8");
  const conf = JSON.parse(readFileSync(new URL("../src-tauri/tauri.conf.json", import.meta.url), "utf8"));

  const connect = (csp) => (String(csp).match(/connect-src([^;"]*)/) || [, ""])[1];
  /* the attribute is delimited by one kind of quote and full of the other, so
     the delimiter has to be captured rather than guessed at */
  const meta = html.match(/<meta[^>]+http-equiv=["']Content-Security-Policy["'][^>]*content=(["'])([\s\S]*?)\1/i);
  assert.ok(meta, "no meta CSP to compare");

  const theirs = connect(conf.app?.security?.csp ?? "");
  assert.ok(theirs.trim(), "tauri.conf.json declares no connect-src to compare against");
  for (const origin of theirs.trim().split(/\s+/).filter((o) => o !== "'self'"))
    assert.ok(connect(meta[2]).includes(origin),
      `tauri.conf.json allows ${origin} for the bridge and this page refuses it, ` +
      `so every IPC call is a policy violation`);
});
