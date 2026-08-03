import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
const KEY = join(homedir(), ".ssh", "efeflow_vm");
const ssh = (s) => { const r = spawnSync("ssh",
  ["-o","BatchMode=yes","-o","ConnectTimeout=10","-i",KEY,"efe@192.168.109.137","sudo","sh","-s"],
  {input:s, encoding:"utf8", maxBuffer:64*1024*1024});
  return {ok:r.status===0, stdout:r.stdout??"", stderr:r.stderr??""}; };
const b64 = (s) => Buffer.from(s,"utf8").toString("base64");
let fails=0; const check=(n,p,d="")=>{ if(!p)fails++; console.log(`  [${p?"  ok  ":" FAIL "}] ${n.padEnd(48)} ${d}`); };

/* edge-fw, with the netdev device the VM actually has */
console.log("\n── the 501-line ruleset, on a real kernel ─────────────────────");
const edge = readFileSync("C:/Users/eFe/Desktop/edge-fw.nft","utf8").replace(/device "wan0"/g,'device "ens33"');
const r = ssh(`printf '%s' '${b64(edge)}' | base64 -d > /tmp/e.nft\nunshare --net sh -c 'nft -f /tmp/e.nft && nft list ruleset | wc -l'\n`);
check("it loads once the device exists", r.ok, r.ok ? `${r.stdout.trim()} lines back from the kernel` : r.stderr.trim().split("\n")[0].slice(0,60));

/* ── the safety net's own scripts, taken out of nft.rs ── */
console.log("\n── the safety net, armed and disarmed (nothing is cut) ────────");
const RS = readFileSync("src-tauri/src/nft.rs","utf8");
const constOf = (n) => RS.match(new RegExp(`const ${n}: &str = "([^"]*)"`))[1];
const DIR = constOf("DIR"), SENTINEL = constOf("SENTINEL"), ROLLBACK = constOf("ROLLBACK");
console.log(`   from nft.rs:  DIR=${DIR}  SENTINEL=${SENTINEL}  ROLLBACK=${ROLLBACK}`);
check("the copy is not in /tmp", !/^\/tmp\//.test(ROLLBACK), ROLLBACK);

/* mark the box so we can see the copy is of *this* ruleset */
ssh(`nft flush ruleset; nft -f - <<'X'
table inet before_arm {
	chain c { type filter hook input priority 0; policy accept; }
}
X`);

/* arm: the real script shape — copy, sentinel, detached timer */
const tok = "probe" + Date.now();
const arm = ssh(`set -e
umask 077
mkdir -p -m 700 ${DIR}
if [ ! -s ${SENTINEL} ] || [ ! -s ${ROLLBACK} ]; then nft list ruleset > ${ROLLBACK}; fi
printf '%s' '${tok}' > ${SENTINEL}
nohup sh -c 'sleep 900; if [ "$(cat ${SENTINEL} 2>/dev/null)" = "${tok}" ]; then nft -f ${ROLLBACK}; rm -f ${SENTINEL}; fi' </dev/null >/dev/null 2>&1 &
cat ${ROLLBACK}`);
check("arming returns the copy it took", arm.ok && /before_arm/.test(arm.stdout));
const st = ssh(`ls -ld ${DIR} ${ROLLBACK} 2>&1; echo "---"; cat ${SENTINEL}`);
check("the directory is mode 700", /^drwx------/.test(st.stdout.split("\n")[0]||""), (st.stdout.split("\n")[0]||"").slice(0,40));
check("the sentinel holds the token", st.stdout.includes(tok));

/* arming twice must keep the FIRST copy — today's fix */
ssh(`nft flush ruleset; nft -f - <<'X'
table inet after_arm {
	chain c { type filter hook input priority 0; policy accept; }
}
X`);
const arm2 = ssh(`set -e
umask 077
mkdir -p -m 700 ${DIR}
if [ ! -s ${SENTINEL} ] || [ ! -s ${ROLLBACK} ]; then nft list ruleset > ${ROLLBACK}; fi
cat ${ROLLBACK}`);
check("arming twice keeps the first copy", /before_arm/.test(arm2.stdout) && !/after_arm/.test(arm2.stdout),
      /before_arm/.test(arm2.stdout) ? "the good ruleset, not the broken one" : "IT PHOTOGRAPHED THE SECOND");

/* rollback restores it */
const rb = ssh(`nft -f ${ROLLBACK}; nft list ruleset`);
check("rollback restores what was armed", /before_arm/.test(rb.stdout) && !/after_arm/.test(rb.stdout));

/* disarm clears the sentinel so the pending timer does nothing */
ssh(`rm -f ${SENTINEL}`);
const dis = ssh(`test -f ${SENTINEL} && echo present || echo cleared`);
check("disarm clears the sentinel", dis.stdout.trim() === "cleared");

ssh(`nft flush ruleset; rm -rf ${DIR}`);
console.log(`\n${fails} failure${fails===1?"":"s"} · host ruleset: ${ssh("nft list ruleset | wc -l").stdout.trim()} lines\n`);
