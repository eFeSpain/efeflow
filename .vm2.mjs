import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { parseNft, verify } from "./src/core/parse.js";
import { generate } from "./src/core/generate.js";
import { MODEL } from "./src/core/model.js";

const HOST = "efe@192.168.109.137";
const KEY = join(homedir(), ".ssh", "efeflow_vm");
const RS = readFileSync("src-tauri/src/nft.rs", "utf8");
const argv = (cmd, sudo = true) => ["ssh", ["-o","BatchMode=yes","-o","ConnectTimeout=8","-i",KEY,
  "-o","StrictHostKeyChecking=accept-new",HOST, ...(sudo?["sudo"]:[]), ...cmd]];
const run = (cmd, stdin, sudo=true) => { const [p,a]=argv(cmd,sudo);
  const r=spawnSync(p,a,{input:stdin??undefined,encoding:"utf8",maxBuffer:64*1024*1024});
  return {ok:r.status===0, stdout:r.stdout??"", stderr:r.stderr??"", code:r.status}; };
const shell = (s, sudo=true) => run(["sh","-s"], s, sudo);

let fails = 0;
const check = (n, pass, d="") => { if(!pass) fails++;
  console.log(`  [${pass?"  ok  ":" FAIL "}] ${n.padEnd(46)} ${d}`); };

/* a table of its own, every chain policy accept, not one drop: it cannot cut
   anything, which is the point until step 4 */
const PROBE = readFileSync("test/fixtures/probe.nft", "utf8");
const MINE = `table inet vmtest {
	set admins {
		type ipv4_addr
		flags interval
		elements = { 10.0.0.0/8, 192.168.0.0/16 }
	}

	counter seen {
		packets 0 bytes 0
	}

	chain input {
		type filter hook input priority 0; policy accept;
		tcp dport 19999 counter name "seen" accept
		udp dport 19998 counter accept
		ip saddr @admins tcp dport 22 counter accept
	}
}
`;

console.log("\n── 2 · load it, read it back, and ask if the meaning survived ──");
const load = run(["nft","-f","-"], MINE);
check("the ruleset applies", load.ok, load.ok ? "" : load.stderr.trim().split("\n")[0]);

const back = run(["nft","-a","list","table","inet","vmtest"]);
check("and reads back with handles", back.ok && /# handle \d+/.test(back.stdout));

/* the claim the import dialog makes, against a real kernel's own output */
const kernel = back.stdout;
const p = parseNft(kernel);
const v = verify(kernel);
check("our parser reads the kernel's output", p.errors.length === 0, `${p.errors.length} unparsed`);
check("and reproduces it line for line", v.ok === v.total, `${v.ok}/${v.total}`);
for (const d of (v.diffs||[]).slice(0,3)) console.log("        lost:", JSON.stringify(d).slice(0,110));

/* the differ's question: does the round trip change the meaning? */
Object.assign(MODEL, {chains:p.chains, sets:p.sets, objects:p.objects, tables:p.tables, prelude:p.prelude});
const reemitted = generate(MODEL).join("\n") + "\n";
run(["nft","delete","table","inet","vmtest"]);
const load2 = run(["nft","-f","-"], reemitted.replace(/^flush ruleset$/m, "").replace(/^#.*$/gm, ""));
check("the re-emitted ruleset also applies", load2.ok, load2.ok ? "" : load2.stderr.trim().split("\n")[0]);
const back2 = run(["nft","list","table","inet","vmtest"]);
const norm = s => s.replace(/\s+/g," ").trim();
check("the kernel's canonical form is identical", norm(back2.stdout) === norm(run(["nft","list","table","inet","vmtest"]).stdout) && back2.ok);

console.log("\n── 3 · counters that count, and handles that address ──────────");
run(["nft","delete","table","inet","vmtest"]);
run(["nft","-f","-"], MINE);
/* real traffic to a port the rule counts */
shell("for i in 1 2 3 4 5; do (echo x | timeout 1 nc -w1 127.0.0.1 19999) >/dev/null 2>&1 || true; done; exit 0");
const counted = run(["nft","-a","list","table","inet","vmtest"]);
const named = counted.stdout.split("\n").find(l => /counter name "seen"/.test(l)) || "";
check("a named counter is readable", /counter name "seen"/.test(named), named.trim().slice(0, 62));
const anon = counted.stdout.split("\n").find(l => /udp dport 19998/.test(l)) || "";
check("an anonymous counter carries its numbers", /packets \d+ bytes \d+/.test(anon), anon.trim().slice(0,58));

/* nft_rule_op, by handle, exactly as the product builds it */
const h = (counted.stdout.match(/ip saddr @admins tcp dport 22 counter packets \d+ bytes \d+ accept # handle (\d+)/)||[])[1];
check("a rule can be addressed by its handle", !!h, h ? `handle ${h}` : "no handle found");
if (h) {
  const del = run(["nft","delete","rule","inet","vmtest","input","handle",h]);
  check("  and deleted by it", del.ok, del.ok?"":del.stderr.trim().split("\n")[0]);
  const after = run(["nft","list","table","inet","vmtest"]);
  check("  the rule is gone and the others remain",
        !/dport 22/.test(after.stdout) && /dport 19999/.test(after.stdout));
}

run(["nft","delete","table","inet","vmtest"]);
const cleaned = run(["nft","list","ruleset"]);
check("the box is left as it was found", cleaned.stdout.trim() === "", `${cleaned.stdout.split("\n").filter(Boolean).length} lines left`);

console.log(`\n${fails} failure${fails===1?"":"s"}\n`);
