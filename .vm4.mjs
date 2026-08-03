import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { parseNft } from "./src/core/parse.js";
import { generate } from "./src/core/generate.js";
import { MODEL } from "./src/core/model.js";

const KEY = join(homedir(), ".ssh", "efeflow_vm");
const ssh = (script) => { const r = spawnSync("ssh",
  ["-o","BatchMode=yes","-o","ConnectTimeout=10","-i",KEY,"efe@192.168.109.137","sudo","sh","-s"],
  {input:script, encoding:"utf8", maxBuffer:64*1024*1024});
  return {ok:r.status===0, stdout:r.stdout??"", stderr:r.stderr??""}; };

/* Every ruleset goes into a network namespace of its own and dies with it.
   A firewall sample carries `policy drop`; loading one into the stack I am
   arriving over is how the last attempt cut the connection. */
function canonical(src) {
  const b64 = Buffer.from(src, "utf8").toString("base64");
  const r = ssh(`printf '%s' '${b64}' | base64 -d > /tmp/probe.nft\n` +
                `unshare --net sh -c 'nft -f /tmp/probe.nft && nft list ruleset'\n`);
  return r.ok ? { ok:true, text:r.stdout } : { ok:false, why:(r.stderr.trim().split("\n")[0]||"") };
}
/* the same scrub the real differ does: counters move, handles are the kernel's */
const scrub = (t) => t.split("\n")
  .map(l => l.replace(/\s*#\s*handle\s+\d+\s*$/, "").replace(/counter packets \d+ bytes \d+/g, "counter").trimEnd())
  .filter(l => l.trim()).join("\n");

const { SAMPLES } = await import("./src/core/samples.js");
const cases = [
  ...SAMPLES.map(s => [s.id, s.nft]),
  ["fixture", readFileSync("test/fixtures/flawed.nft","utf8")],
  ["edge-fw (501 lines)", readFileSync("C:/Users/eFe/Desktop/edge-fw.nft","utf8")],
];

console.log("\n── N1 = kernel's form of the original · N2 = of what we re-emit ──\n");
let fails = 0, skipped = 0;
for (const [name, src] of cases) {
  const n1 = canonical(src);
  if (!n1.ok) { skipped++; console.log(`  [ skip ] ${name.padEnd(22)} kernel refuses the original: ${n1.why.slice(0,48)}`); continue; }
  const p = parseNft(n1.text);
  Object.assign(MODEL, {chains:p.chains, sets:p.sets, objects:p.objects, tables:p.tables, prelude:p.prelude});
  const n2 = canonical(generate(MODEL).join("\n") + "\n");
  if (!n2.ok) { fails++; console.log(`  [ FAIL ] ${name.padEnd(22)} our re-emission will not load: ${n2.why.slice(0,48)}`); continue; }
  const same = scrub(n1.text) === scrub(n2.text);
  if (!same) fails++;
  console.log(`  [${same?"  ok  ":" FAIL "}] ${name.padEnd(22)} ${same?"meaning identical":"the kernel disagrees"}   ${p.errors.length?`(${p.errors.length} unparsed)`:""}`);
  if (!same) {
    const a = scrub(n1.text).split("\n"), b = scrub(n2.text).split("\n");
    for (let i=0, shown=0; i<Math.max(a.length,b.length) && shown<3; i++)
      if (a[i]!==b[i]) { console.log(`          N1: ${JSON.stringify(a[i]??null)}`);
                         console.log(`          N2: ${JSON.stringify(b[i]??null)}`); shown++; }
  }
}
console.log(`\n${fails} failure${fails===1?"":"s"}, ${skipped} skipped — the host's own ruleset untouched\n`);
console.log("host ruleset now:", ssh("nft list ruleset | wc -l").stdout.trim(), "lines");
