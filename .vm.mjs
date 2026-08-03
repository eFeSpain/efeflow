/* The transport, against a real firewall.
 *
 * Nothing here restates what nft.rs does: argv() is mirrored from it and the
 * scripts are extracted from it, the same way test/rollback-script.test.js
 * does — a harness holding its own copy of the thing it tests proves the copy.
 *
 * Every command below is read-only or confined to a table of its own. Nothing
 * here can cut the connection; that test is separate and announced. */
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const HOST = "efe@192.168.109.137";
const KEY = join(homedir(), ".ssh", "efeflow_vm");
const RS = readFileSync("src-tauri/src/nft.rs", "utf8");

/* ── mirrored from argv() in nft.rs ───────────────────────────────────────── */
function argv(cmd, { sudo = true } = {}) {
  const args = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
                "-i", KEY, "-o", "StrictHostKeyChecking=accept-new", HOST];
  if (sudo) args.push("sudo");
  return ["ssh", [...args, ...cmd]];
}
function run(cmd, stdin, opts) {
  const [program, args] = argv(cmd, opts);
  const r = spawnSync(program, args, { input: stdin ?? undefined, encoding: "utf8" });
  return { ok: r.status === 0, stdout: r.stdout ?? "", stderr: r.stderr ?? "", code: r.status };
}
const shell = (script, opts) => run(["sh", "-s"], script, opts);

/* ── the scripts, taken out of nft.rs rather than restated ────────────────── */
function literalAfter(from) {
  const open = RS.indexOf('"', from);
  let out = "";
  for (let i = open + 1; i < RS.length; i++) {
    const c = RS[i];
    if (c === '"') return out;
    if (c !== "\\") { out += c; continue; }
    const n = RS[++i];
    if (n === "n") out += "\n";
    else if (n === "t") out += "\t";
    else if (n === '"' || n === "\\" || n === "'") out += n;
    else if (n === "\n") { while (/\s/.test(RS[i + 1] ?? "")) i++; }
    else out += n;
  }
  throw new Error("unterminated literal");
}
const constOf = (n) => RS.match(new RegExp(`const ${n}: &str = "([^"]*)"`))[1];
const scriptOf = (fn) => literalAfter(RS.indexOf(`pub fn ${fn}(`));

export { run, shell, scriptOf, constOf, argv, HOST, KEY };

/* ── the run ──────────────────────────────────────────────────────────────── */
const line = (s) => console.log(s);
const ok = (b) => (b ? "  ok  " : " FAIL ");
let failures = 0;
const check = (name, pass, detail = "") => {
  if (!pass) failures++;
  line(`  [${ok(pass)}] ${name.padEnd(46)} ${detail}`);
};

line("\n── 1 · read-only ──────────────────────────────────────────────");

/* host_probe, verbatim from nft.rs */
const probeScript = scriptOf("host_probe");
const probe = shell(probeScript);
check("host_probe returns", probe.ok, probe.ok ? "" : probe.stderr.trim().split("\n")[0]);
const field = (k) => (probe.stdout.split("\n").find((l) => l.startsWith(k + "\t")) || "").slice(k.length + 1).trim();
check("  it names nft", /^nftables v/.test(field("nft")), field("nft"));
check("  it names the kernel", /^Linux /.test(field("kernel")), field("kernel"));

/* the same probe with the sudo toggle off — the finding from setup */
const noSudo = shell(probeScript, { sudo: false });
check("with sudo off it still finds nft", noSudo.ok && /nftables v/.test(noSudo.stdout),
      noSudo.ok ? "" : "<- PATH: " + (noSudo.stderr.trim().split("\n")[0] || noSudo.stdout.trim().split("\n")[0]));

/* nft_list */
const list = run(["nft", "-a", "list", "ruleset"]);
check("nft_list reads the live ruleset", list.ok, `${list.stdout.split("\n").filter(Boolean).length} lines`);

/* nft_check, against something good and something bad */
const good = "table inet probe_ok {\n\tchain c { type filter hook input priority 0; policy accept; }\n}\n";
const bad = "table inet probe_bad {\n\tchain c { this is not nftables }\n}\n";
const cOk = run(["nft", "-c", "-f", "-"], good);
const cBad = run(["nft", "-c", "-f", "-"], bad);
check("nft_check accepts a good ruleset", cOk.ok);
check("nft_check refuses a bad one", !cBad.ok, (cBad.stderr.trim().split("\n")[0] || "").slice(0, 60));
check("  and says why", /Error/.test(cBad.stderr));

line(`\n${failures} failure${failures === 1 ? "" : "s"} so far\n`);
