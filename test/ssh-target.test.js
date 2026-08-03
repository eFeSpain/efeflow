/* Where `ssh` is told to go, and what it is allowed to read that as.
 *
 * Nothing on the native side reaches a shell — every command is argv, which is
 * the whole reason `sh -s` exists in nft.rs — so the danger was never quoting.
 * It is that `ssh` parses its own destination with getopt: a host of
 * `-oProxyCommand=curl … | sh` is not a host at all, it is an option, and that
 * option runs a command on the machine eFeFlow is running on.
 *
 * The inventory lives in localStorage and deliberately not in a project file,
 * which is what kept this off the "open a colleague's file" path. It still had
 * no business being reachable by typing.
 *
 * Two things close it and both are checked here: `--` before the destination,
 * so nothing after it can be an option whatever it begins with, and a refusal
 * before that, because a hostname starting with a dash is a mistake or an
 * attack in every case and neither is worth a connection.
 *
 * These read the Rust source, in the same way test/capabilities.test.js does.
 * `cargo` is not a thing `npm test` can assume, and a guard that only runs
 * where the toolchain is installed is a guard nobody runs. */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const SRC = readFileSync(new URL("../src-tauri/src/nft.rs", import.meta.url), "utf8");

/** The body of a top-level `fn name(` … matching brace. */
function body(name) {
  const at = SRC.indexOf(`fn ${name}(`);
  assert.ok(at > 0, `nft.rs no longer declares ${name}`);
  const open = SRC.indexOf("{", SRC.indexOf(")", at));
  let depth = 0;
  for (let i = open; i < SRC.length; i++) {
    if (SRC[i] === "{") depth++;
    else if (SRC[i] === "}" && --depth === 0) return SRC.slice(open, i + 1);
  }
  throw new Error(`unterminated ${name}`);
}

test("the ssh destination is pushed after a `--`", () => {
  const argv = body("argv");
  const sep = argv.indexOf('args.push("--"');
  const dest = argv.indexOf("{u}@{host}");
  assert.ok(sep > 0, "argv() no longer separates options from the destination");
  assert.ok(dest > sep, "the destination is pushed before the `--` that protects it");
});

test("the `--` comes after the options it is meant to close", () => {
  const argv = body("argv");
  assert.ok(argv.indexOf('"BatchMode=yes"') < argv.indexOf('args.push("--"'),
    "a `--` before the -o options would make them the remote command");
  assert.ok(argv.indexOf('args.push("-p".into())') < argv.indexOf('args.push("--"'),
    "the port is an option and belongs before the separator");
});

test("a host or user beginning with a dash is refused outright", () => {
  const check = body("check");
  assert.match(check, /starts_with\('-'\)/, "nothing refuses a dash-leading destination");
  assert.match(check, /\bhost\b/, "the host is not among what is checked");
  assert.match(check, /\buser\b/, "the user is not among what is checked");
});

/* A validator nothing calls is a comment. Both places that spawn a process
   against a target have to run it — `run` for everything that collects output,
   and `nft_watch`, which is the one command that outlives its call. */
test("every path that spawns against a target validates it first", () => {
  for (const fn of ["run", "nft_watch"]) {
    const b = body(fn);
    const validated = b.indexOf("target.check()");
    assert.ok(validated > 0, `${fn}() spawns without validating its target`);
    assert.ok(validated < b.indexOf("argv("), `${fn}() builds its argv before validating`);
  }
});

/* Every #[tauri::command] that takes a Target reaches a process through one of
   those two, so the list is not allowed to grow a third way in silently. */
test("nothing else builds an argv of its own", () => {
  /* the comma is what tells a call from the declaration, which has a colon */
  const callers = [...SRC.matchAll(/\bargv\(&?target,/g)].length;
  assert.equal(callers, 2, "argv() has a new caller — does it validate its target?");
});
