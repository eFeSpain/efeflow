import { spawnSync } from "node:child_process";
import { homedir } from "node:os";
import { join } from "node:path";
const KEY = join(homedir(), ".ssh", "efeflow_vm");
const ssh = (s) => { const r = spawnSync("ssh",
  ["-o","BatchMode=yes","-o","ConnectTimeout=10","-i",KEY,"efe@192.168.109.137","sudo","sh","-s"],
  {input:s, encoding:"utf8", maxBuffer:16*1024*1024});
  return {ok:r.status===0, stdout:r.stdout??"", stderr:r.stderr??""}; };

/* Exactly the shape the product uses: the copy is `nft list ruleset`, and the
   restore is `nft -f <copy>` with nothing before it. Does that undo an apply? */
console.log("\n── what `nft -f <copy>` actually restores ─────────────────────\n");

const out = ssh(`
nft flush ruleset
# the ruleset as it was before anything was applied
nft -f - <<'X'
table inet keepme { chain c { type filter hook input priority 0; policy accept;
  tcp dport 22 accept
} }
X
mkdir -p -m 700 /run/efeflow
nft list ruleset > /run/efeflow/rollback.nft          # the copy, as nft_arm takes it

# now an apply, the way the product does it: replace my tables, add a new one
nft -f - <<'X'
table inet keepme
delete table inet keepme
table inet keepme { chain c { type filter hook input priority 0; policy drop;
} }
table inet brandnew { chain c { type filter hook input priority 0; policy drop;
} }
X
echo "=== after the apply ==="
nft list ruleset | grep -E "^table|policy"

nft -f /run/efeflow/rollback.nft                       # the restore, as nft_rollback does it
echo "=== after the rollback ==="
nft list ruleset | grep -E "^table|policy|dport"

nft flush ruleset; rm -rf /run/efeflow
`);
console.log(out.stdout.trim() || out.stderr.trim());
