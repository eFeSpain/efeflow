/* What the project says it is, in the four places that say it.
 *
 * The version lived in three files that nothing held together, and it read
 * 1.0.0 on a tool whose own README tells you to treat its output as a draft you
 * review — while the release workflow published it as a stable release. The
 * badge said beta, the About panel said beta, and the number said finished. */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const read = (p) => readFileSync(new URL("../" + p, import.meta.url), "utf8");
const pkg = JSON.parse(read("package.json"));
const conf = JSON.parse(read("src-tauri/tauri.conf.json"));
const cargo = read("src-tauri/Cargo.toml");
const lock = read("src-tauri/Cargo.lock");
const workflow = read(".github/workflows/release.yml");
const readme = read("README.md");

const cargoVersion = cargo.match(/^version = "([^"]+)"/m)[1];

test("every file that carries the version carries the same one", () => {
  assert.equal(conf.version, pkg.version, "tauri.conf.json disagrees with package.json");
  assert.equal(cargoVersion, pkg.version, "Cargo.toml disagrees with package.json");
  /* the lockfile is what cargo actually builds, and it does not follow on its
     own — `cargo update -p efeflow` is the other half of a version bump */
  assert.match(lock, new RegExp(`name = "efeflow"\\nversion = "${pkg.version}"`),
    "Cargo.lock still names the old version");
});

/* Beta is a claim about stability, and semver has a way of making it. */
test("while it calls itself beta, it does not number itself finished", () => {
  const beta = /status-beta/.test(readme) && /##\s*⚠?\s*Beta/i.test(readme);
  assert.ok(beta, "if the beta badge and section have gone, replace this test");

  const [major] = pkg.version.split(".").map(Number);
  assert.equal(major, 0,
    `${pkg.version} claims a stable release of a tool that tells you to review its output`);
});

/* GitHub's "Latest release" — and everything downstream that reads it — takes
   a non-prerelease as a statement that this one is ready to depend on. */
test("a tag publishes a pre-release while that is what it is", () => {
  assert.match(workflow, /prerelease:\s*true/,
    "the release workflow publishes a beta as a stable release");
});

/* And the two halves of that decision have to be made together.
 *
 * v0.9.0 was built as a draft, which only its owner could see, so the one line
 * telling anybody how to install this pointed at nothing for the whole life of
 * the release. Publishing it fixes that — but /releases/latest leaves out
 * prereleases, so on its own it would have swapped an invisible release for an
 * invisible link. The list page shows it, prerelease and all. */
test("the install link points somewhere a pre-release actually appears", () => {
  const links = [...readme.matchAll(/github\.com\/eFeSpain\/efeflow\/releases[^\s)]*/g)].map((m) => m[0]);
  assert.ok(links.length, "the README no longer links to the releases at all");

  if (/prerelease:\s*true/.test(workflow))
    for (const l of links)
      assert.ok(!l.includes("/latest"),
        `${l} excludes prereleases, and every release this ships is one`);
});

test("the workflow publishes rather than drafting", () => {
  assert.match(workflow, /releaseDraft:\s*false/,
    "a draft release is visible to its owner and to nobody else");
});
