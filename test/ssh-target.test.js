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

/* ── where nft lives, which is not where a login shell looks ─────────────
 *
 * `nft` is in /usr/sbin. A non-interactive ssh command gets
 * `/usr/local/bin:/usr/bin:/bin:/usr/games` on Debian — no sbin — so
 * `ssh fw nft list ruleset` answered "nft: command not found", which reads as
 * *nftables is not installed* on a host where it is installed and running.
 *
 * It only ever worked because sudo replaces PATH with its own `secure_path`.
 * So the sudo toggle in the target dialog, switched off by somebody who
 * already logs in as root, broke every command and blamed their firewall.
 *
 * Measured on Debian 13 with nft 1.1.3: `ssh … nft --version` failed, and
 * `ssh … env PATH=… nft --version` answered. */
const RS = readFileSync(new URL("../src-tauri/src/nft.rs", import.meta.url), "utf8");

test("the transport says where nft lives", () => {
  const m = RS.match(/const SBIN_PATH: &str = "([^"]*)"/);
  assert.ok(m, "nft.rs no longer declares SBIN_PATH");
  const dirs = m[1].split(":");
  for (const d of ["/usr/sbin", "/sbin"])
    assert.ok(dirs.includes(d), `${d} is where nft is, and it is not on the list`);
  for (const d of dirs) assert.match(d, /^\//, `${d} is not an absolute path`);
});

test("every remote command carries that PATH, with or without sudo", () => {
  const argv = RS.slice(RS.indexOf("fn argv("), RS.indexOf("fn run("));
  assert.match(argv, /args\.push\("env"\.into\(\)\);/,
    "the command is handed to the remote shell without a PATH of its own");
  assert.match(argv, /format!\("PATH=\{SBIN_PATH\}"\)/);
  /* after the sudo push, so `sudo env PATH=… nft` and not `env PATH=… sudo` —
     the second would hand sudo a PATH it discards anyway and lose the point */
  assert.ok(argv.indexOf('args.push("sudo".into());') < argv.indexOf('args.push("env".into());'),
    "env has to come after sudo, or sudo's secure_path replaces it again");
});

/* Windows and macOS have no nft at all; what the inherited PATH finds there is
   `ssh`, and replacing it would lose that. */
test("the local PATH is added to, never replaced", () => {
  const fn = RS.slice(RS.indexOf("fn local_path("), RS.indexOf("fn argv("));
  assert.match(fn, /std::env::var\("PATH"\)/, "it has to start from the inherited one");
  assert.match(fn, /format!\("\{p\}\{sep\}\{SBIN_PATH\}"\)/, "and append rather than overwrite");
  assert.match(fn, /cfg!\(windows\)/, "on Windows the sbin list means nothing and must not be added");
});

/* ── the windows nobody asked for ────────────────────────────────────────
 *
 * `windows_subsystem = "windows"` makes this process windowless and says
 * nothing about what it starts. `ssh.exe` is a console application, so Windows
 * builds it a console — and a conhost window flashes up behind the app on
 * every call. Two of them at launch, because the boot asks the host twice:
 * once whether it is reachable, once whether a rollback is pending.
 *
 * Reported as "it slows down and a couple of cmd windows open behind it".
 * Nothing was wrong with the firewall; the flashing was the tool talking to
 * it. Measured after the fix: zero console windows across a whole launch. */

test("nothing spawned gets a console window of its own", () => {
  assert.match(RS, /#\[cfg\(windows\)\]\s*\nfn no_console/,
    "nft.rs no longer has a windows-only console suppressor");
  assert.match(RS, /creation_flags\(0x0800_0000\)/,
    "CREATE_NO_WINDOW is what keeps conhost from drawing a window");
  assert.match(RS, /#\[cfg\(not\(windows\)\)\]\s*\nfn no_console/,
    "and it has to be a no-op elsewhere, or the crate stops building");
});

test("every spawn goes through it, not just the one that was noticed", () => {
  const spawns = [...RS.matchAll(/Command::new\(/g)].length;
  const guarded = [...RS.matchAll(/no_console\(&mut \w+\)/g)].length;
  assert.equal(guarded, spawns,
    `${spawns} places spawn a process and ${guarded} suppress the console`);
});

/* ── password auth, made optional without weakening the key path ────────────
 *
 * The transport ran ssh with BatchMode=yes, which never prompts — so a host
 * that only offered a password could not be reached, and a first connection to
 * any host failed on its unknown key with no way to accept it. A password is
 * optional now: given one, ssh runs under sshpass, which reads it from the
 * SSHPASS environment variable — never the argv, where `ps` could read it. */

test("a password goes through sshpass and its environment, not the argv", () => {
  const argv = body("argv");
  assert.match(argv, /"sshpass"/, "the password path no longer runs under sshpass");
  assert.match(argv, /"-e"\.into\(\)/, "sshpass -e is what reads the password from the environment");
  /* and it forces password auth: left to try keys first, ssh negotiates the
     agent under sshpass's pty and a key with a passphrase hangs there forever */
  assert.match(argv, /"PreferredAuthentications=password"/,
    "the password path still lets ssh try keys, which hangs under sshpass");
  assert.match(argv, /"PubkeyAuthentication=no"/, "pubkey is not turned off for the password path");
  assert.match(body("spawn_collect"), /\.env\("SSHPASS"/,
    "spawn_collect hands the password to sshpass some other way than the environment");
  assert.match(body("nft_watch"), /\.env\("SSHPASS"/,
    "the monitor stream hands the password to sshpass some other way than the environment");
});

test("BatchMode is for the key path only, never the password one", () => {
  /* BatchMode=yes suppresses the very prompt sshpass answers, so it must be
     guarded by the absence of a password — reintroducing it unconditionally
     would silently break password auth. */
  const argv = body("argv");
  const guard = argv.indexOf("pw.is_none()");
  const batch = argv.indexOf('"BatchMode=yes"');
  assert.ok(guard > 0, "argv() no longer decides BatchMode on whether there is a password");
  assert.ok(batch > guard, "BatchMode=yes is not inside the no-password branch");
});

test("an unknown host is trusted on first use, a changed one still refused", () => {
  assert.match(body("argv"), /"StrictHostKeyChecking=accept-new"/,
    "the first-connection wall (Host key verification failed) is back with no way past it");
});

test("a Target's Debug never prints the password", () => {
  /* A derived Debug would print it; a firewall tool holding a root password
     should not leak it the moment someone adds a `{:?}`. */
  const der = SRC.slice(SRC.lastIndexOf("#[derive", SRC.indexOf("pub enum Target")),
                        SRC.indexOf("pub enum Target"));
  assert.doesNotMatch(der, /Debug/, "Target still derives Debug, which would print the password");
  assert.match(SRC, /impl std::fmt::Debug for Target/, "Target has no hand-written Debug to redact through");
  assert.match(SRC, /"<redacted>"/, "the password is not redacted in the Debug that replaces it");
});

/* ── the password stays in the session, never on disk ──────────────────────
 * It authenticates a firewall; it is not a hostname to be remembered in a file
 * a colleague opens. It lives in memory and is stripped before the target is
 * written, so no future caller leaks it through saveTarget either. */
const TS = readFileSync(new URL("../src/target.js", import.meta.url), "utf8");

test("a session password is never written to disk", () => {
  assert.match(TS, /const passwords = new Map\(\)/, "there is no session-only store to keep it out of localStorage");
  assert.match(TS, /delete target\.pass/, "saveTarget does not strip the password before writing the target");
  assert.match(TS, /delete target\.password/, "the serialized field name is not stripped either");
  assert.match(TS, /pass: passwordFor/, "asTauriTarget does not attach the session password when it makes the call");
});
