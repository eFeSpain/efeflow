/* What the interface says when reading the local machine needs a privilege it
 * cannot obtain.
 *
 * Reported from the running app: "me sale un mensaje que no me da tiempo a
 * leer bien, que necesita root, pero no me pide root". Both halves were real —
 * a 2.2s toast carrying a 180-character English sentence, and a sentence that
 * said root without saying why nothing asked for it. The native side names the
 * case now (src-tauri/src/nft.rs decides which); this is the half that turns a
 * code into something a person reads, in the language they are reading in.
 */
import test, { after } from "node:test";
import assert from "node:assert/strict";
import { boot, shutdown, $, click, settle } from "./harness.js";

after(shutdown);

const help = async (code) => {
  const { showRootHelp } = await import("../src/app.js");
  assert.ok(showRootHelp, "showRootHelp is exported for this test");
  const drew = showRootHelp(code);
  return { drew, text: $("#imp-side")?.textContent || "" };
};

test("a code it does not know draws nothing, so the caller can fall back", async () => {
  await boot();
  const { drew } = await help("something-else-entirely");
  assert.equal(drew, false);
  /* undefined is the ordinary case: every failure that is not about privilege
     arrives with no code at all */
  assert.equal((await help(undefined)).drew, false);
});

test("not being able to ask is explained, not just asserted", async () => {
  await boot();
  const { drew, text } = await help("needs-root-uninstalled");
  assert.equal(drew, true);
  /* the complaint was that it named root and stopped there. The panel has to
     say what would do the asking and why it is not here. */
  assert.match(text, /\.deb|\.rpm/, "it says what installs the missing piece");
  assert.match(text, /CAP_NET_ADMIN/, "it says which permission the kernel wants");
});

test("the two reasons it cannot ask are told apart", async () => {
  await boot();
  const uninstalled = (await help("needs-root-uninstalled")).text;
  const noPkexec = (await help("needs-root-no-pkexec")).text;
  assert.notEqual(uninstalled, noPkexec);
  assert.match(noPkexec, /pkexec/);
});

/* A workaround belongs where there is something to work around. A declined
   password dialog is answered by pressing the button again, and telling
   somebody to go and run sudo instead would be the wrong advice. */
test("the way round is offered only when there is one", async () => {
  await boot();
  assert.match((await help("needs-root-uninstalled")).text, /nft -a list ruleset/);
  assert.doesNotMatch((await help("declined")).text, /nft -a list ruleset/);
});

/* Everything else in this interface is bilingual and this was not: the text
   came from Rust, in English, whatever language the window was in. */
test("it is said in the language the interface is in", async () => {
  await boot();
  click('#lang [data-lang="en"]');
  await settle(60);
  const en = (await help("needs-root-uninstalled")).text;
  click('#lang [data-lang="es"]');
  await settle(60);
  const es = (await help("needs-root-uninstalled")).text;

  assert.notEqual(en, es, "the panel was not translated at all");
  assert.match(en, /permission/);
  assert.match(es, /permiso/);
});

/* The other half of the report. A toast that vanishes in 2.2 seconds is fine
   for "Exported fw.nft" and useless for a sentence about a permission. */
test("a long message stays up long enough to read, and can be dismissed", async () => {
  await boot();
  const { toast } = await import("../src/app.js");
  assert.ok(toast, "toast is exported for this test");

  toast("x".repeat(160));
  const n = $("#toast");
  assert.ok(n.classList.contains("on"));
  click("#toast");
  assert.equal(n.classList.contains("on"), false, "clicking it puts it away");
});
