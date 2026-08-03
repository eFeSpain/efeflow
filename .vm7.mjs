import { spawnSync } from "node:child_process";
import { homedir } from "node:os";
import { join } from "node:path";
const KEY = join(homedir(), ".ssh", "efeflow_vm");
const ssh = (s) => { const r = spawnSync("ssh",
  ["-o","BatchMode=yes","-o","ConnectTimeout=10","-i",KEY,"efe@192.168.109.137","sudo","sh","-s"],
  {input:s, encoding:"utf8", maxBuffer:16*1024*1024});
  return {code:r.status, stdout:r.stdout??"", stderr:r.stderr??""}; };

const r = ssh(`
set -x
nft flush ruleset
printf '%s\n' 'table inet keepme {' '  chain c { type filter hook input priority 0; policy accept; tcp dport 22 accept }' '}' > /tmp/a.nft
nft -f /tmp/a.nft
mkdir -p -m 700 /run/efeflow
nft list ruleset > /run/efeflow/rollback.nft
echo "--- copy taken, it holds: ---"
cat /run/efeflow/rollback.nft
printf '%s\n' 'table inet keepme' 'delete table inet keepme' 'table inet keepme {' '  chain c { type filter hook input priority 0; policy drop; }' '}' 'table inet brandnew {' '  chain c { type filter hook input priority 0; policy drop; }' '}' > /tmp/b.nft
nft -f /tmp/b.nft
echo "--- after the apply ---"
nft list ruleset
nft -f /run/efeflow/rollback.nft
echo "--- after the rollback ---"
nft list ruleset
nft flush ruleset; rm -rf /run/efeflow /tmp/a.nft /tmp/b.nft
`);
console.log(r.stdout);
if (r.code !== 0) console.log("STDERR:\n" + r.stderr.split("\n").filter(l=>!/^\+/.test(l)).join("\n").trim());
