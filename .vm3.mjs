import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { parseNft } from "./src/core/parse.js";
import { generate } from "./src/core/generate.js";
import { MODEL } from "./src/core/model.js";

const KEY = join(homedir(), ".ssh", "efeflow_vm");
const run = (cmd, stdin) => { const r = spawnSync("ssh",
  ["-o","BatchMode=yes","-o","ConnectTimeout=8","-i",KEY,"efe@192.168.109.137","sudo",...cmd],
  {input:stdin??undefined,encoding:"utf8",maxBuffer:64*1024*1024});
  return {ok:r.status===0, stdout:r.stdout??"", stderr:r.stderr??""}; };

const canonical = (src) => {
  run(["nft","flush","ruleset"]);
  const l = run(["nft","-f","-"], src);
  if (!l.ok) return { ok:false, why:(l.stderr.trim().split("\n")[0]||"") };
  return { ok:true, text: run(["nft","list","ruleset"]).stdout.trim() };
};

/* every ruleset this project ships, plus the big one on the desktop */
const { SAMPLES } = await import("./src/core/samples.js");
const cases = [
  ...SAMPLES.map(s => [s.id, s.nft]),
  ["edge-fw (501 lines)", readFileSync("C:/Users/eFe/Desktop/edge-fw.nft","utf8")],
];

console.log("\n── the differ's question, on a real kernel ────────────────────");
console.log("   N1 = the kernel's form of the original");
console.log("   N2 = the kernel's form of what we re-emit from it\n");
let fails = 0;
for (const [name, src] of cases) {
  const n1 = canonical(src);
  if (!n1.ok) { console.log(`  [ skip ] ${name.padEnd(22)} the kernel will not take the original: ${n1.why.slice(0,44)}`); continue; }
  const p = parseNft(n1.text);
  Object.assign(MODEL, {chains:p.chains, sets:p.sets, objects:p.objects, tables:p.tables, prelude:p.prelude});
  const n2 = canonical(generate(MODEL).join("\n") + "\n");
  if (!n2.ok) { fails++; console.log(`  [ FAIL ] ${name.padEnd(22)} our re-emission does not load: ${n2.why.slice(0,44)}`); continue; }
  const same = n1.text === n2.text;
  if (!same) fails++;
  console.log(`  [${same?"  ok  ":" FAIL "}] ${name.padEnd(22)} ${same ? "meaning identical" : "the kernel disagrees"}`);
  if (!same) {
    const a = n1.text.split("\n"), b = n2.text.split("\n");
    for (let i=0, shown=0; i<Math.max(a.length,b.length) && shown<3; i++)
      if (a[i]!==b[i]) { console.log(`          N1: ${JSON.stringify(a[i]??null)}`);
                         console.log(`          N2: ${JSON.stringify(b[i]??null)}`); shown++; }
  }
}
run(["nft","flush","ruleset"]);
console.log(`\n${fails} failure${fails===1?"":"s"}\n`);
