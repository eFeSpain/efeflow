/* What the status bar is allowed to say about a machine.
 *
 * It said `nft 1.0.9 · kernel 6.8` — literal text in index.html, shown on
 * every machine, including one with no target configured and one that had
 * never been contacted. The validation screen went further and claimed the
 * ruleset was "verified against kernel 6.8". Both numbers now come from the
 * host, or neither is shown. */
import test from "node:test";
import assert from "node:assert/strict";

import { readProbe } from "../src/target.js";

test("a version and a kernel are read out of what the host said", () => {
  const r = readProbe("nft\tnftables v1.0.9 (Old Doc Yak)\nkernel\tLinux 6.8.0-45-generic\n");
  assert.equal(r.version, "1.0.9");
  assert.equal(r.kernel, "6.8.0-45-generic");
  assert.equal(r.banner, "nftables v1.0.9 (Old Doc Yak)");
  assert.equal(r.uname, "Linux 6.8.0-45-generic");
});

/* Newer nft prints a block of build details under the version line, so the
   kernel is not "the second line" on every host. Hence the tags. */
test("build details under the version line do not become the kernel", () => {
  const r = readProbe(
    "nft\tnftables v1.1.1 (Commodore Bullmoose)\nkernel\tLinux 6.11.0-9-generic\n",
  );
  assert.equal(r.version, "1.1.1");
  assert.equal(r.kernel, "6.11.0-9-generic");
});

test("a version banner we cannot parse is still shown as it came", () => {
  const r = readProbe("nft\tsome unfamiliar build\nkernel\tLinux 5.15\n");
  assert.equal(r.version, "some unfamiliar build");
  assert.equal(r.kernel, "5.15");
});

test("nothing said is nothing claimed", () => {
  for (const out of ["", "\n", "unexpected output"]) {
    const r = readProbe(out);
    assert.equal(r.version, "");
    assert.equal(r.kernel, "");
  }
});
