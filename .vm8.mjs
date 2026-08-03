import { spawnSync } from "node:child_process";
import { homedir } from "node:os";
import { join } from "node:path";
const KEY = join(homedir(), ".ssh", "efeflow_vm");
const ssh = (s) => { const r = spawnSync("ssh",
  ["-o","BatchMode=yes","-o","ConnectTimeout=10","-i",KEY,"efe@192.168.109.137","sudo","sh","-s"],
  {input:s, encoding:"utf8", maxBuffer:16*1024*1024});
  return {code:r.status, stdout:r.stdout??"", stderr:r.stderr??""}; };

console.log("\n══ A · a host whose firewall is empty, which is every new one ══\n");
console.log(ssh(`
nft flush ruleset
mkdir -p -m 700 /run/efeflow
# nft_arm, verbatim in shape: take the copy only if there is not one already
if [ ! -s /run/efeflow/armed ] || [ ! -s /run/efeflow/rollback.nft ]; then
  nft list ruleset > /run/efeflow/rollback.nft
fi
printf '%s' 'tok123' > /run/efeflow/armed
echo "copy exists : $([ -f /run/efeflow/rollback.nft ] && echo yes || echo no)"
echo "copy size   : $(wc -c < /run/efeflow/rollback.nft) bytes"
echo "guard -s    : $([ -s /run/efeflow/rollback.nft ] && echo 'sees a copy' || echo 'sees NO copy')"
echo
echo "now nft_rollback, verbatim:"
rm -f /run/efeflow/armed
if [ ! -s /run/efeflow/rollback.nft ]; then
  echo '  -> there is no rollback copy on this host to go back to' >&2
  echo "  RESULT: the net refuses to fire"
else
  nft -f /run/efeflow/rollback.nft; echo "  RESULT: restored"
fi
nft flush ruleset; rm -rf /run/efeflow
`).stdout);

console.log("══ B · does `nft -f <copy>` replace, or merge? ══════════════════\n");
console.log(ssh(`
nft flush ruleset
cat > /tmp/a.nft <<'X'
table inet keepme {
	chain c {
		type filter hook input priority 0; policy accept;
		tcp dport 22 accept
	}
}
X
nft -f /tmp/a.nft
mkdir -p -m 700 /run/efeflow
nft list ruleset > /run/efeflow/rollback.nft
echo "copy size   : $(wc -c < /run/efeflow/rollback.nft) bytes"
cat > /tmp/b.nft <<'X'
table inet keepme
delete table inet keepme
table inet keepme {
	chain c {
		type filter hook input priority 0; policy drop;
	}
}
table inet brandnew {
	chain c {
		type filter hook input priority 0; policy drop;
	}
}
X
nft -f /tmp/b.nft
echo "after apply : $(nft list ruleset | grep -c '^table') tables, keepme policy $(nft list ruleset | grep -A1 'chain c' | grep -m1 -o 'policy [a-z]*')"
nft -f /run/efeflow/rollback.nft
echo "after restore:"
nft list ruleset | grep -E '^table|policy|dport' | sed 's/^/    /'
nft flush ruleset; rm -rf /run/efeflow /tmp/a.nft /tmp/b.nft
`).stdout);
