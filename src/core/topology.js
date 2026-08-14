/* The shape of the ruleset as a graph, with no opinion about how it is drawn.
 *
 * canvas.js turns this into cards and wires; this file decides what connects to
 * what, and what a packet can reach, from the model alone — so both can be
 * checked without a DOM. The one rule it exists to keep is that a wire is a path
 * a packet actually takes: an `ip` chain and an `ip6` chain share no packet, and
 * a line between them is a lie the canvas told until this was pulled out of it.
 */
import { UID } from "./model.js";
import { PATHS } from "./simulate.js";

/* A jump resolves within the same table, against the set of chains being drawn
   — not a global, so this can be reasoned about on its own. `model.jumpTarget`
   searches MODEL and would read empty here. */
const targetIn = (chains, ch, name) =>
  chains.find(c => c.table === ch.table && c.id === name);

/* Which traffic a chain's family can carry. A v4 packet meets ip and inet
   chains, a v6 packet meets ip6 and inet, and the two never share one. A netdev
   chain runs on a device before the family is decided, so it feeds both. arp
   and bridge keep to themselves. */
const FAM_CLASS = { ip:["v4"], ip6:["v6"], inet:["v4","v6"], netdev:["v4","v6"],
                    arp:["arp"], bridge:["bridge"] };
export const famOf = ch => String(ch.table||"").split(" ")[0];
export const classesOf = ch => FAM_CLASS[famOf(ch)] || [famOf(ch) || "other"];

/* Chains of one traffic class at one hook, grouped by priority, ascending. */
function prioGroups(chains, cls, hook){
  const here = chains.filter(c => c.hook===hook && classesOf(c).includes(cls));
  const by = new Map();
  for(const c of here){ if(!by.has(c.prio)) by.set(c.prio, []); by.get(c.prio).push(c); }
  return [...by.keys()].sort((a,b)=>a-b).map(k=>by.get(k));
}

/* The wires. Each entry is [fromUid, toUid, isJump].
 *
 * Within a hook, chains of one class run in priority order; two at the same
 * priority have no order nftables guarantees, so they fan from their
 * predecessor rather than being strung one after another in whatever order the
 * model held them. Between hooks, only the L3 classes have a modelled packet
 * path (PATHS, the same one core/simulate.js walks); arp and bridge inter-hook
 * flow is not modelled, so it is left undrawn rather than guessed. Jumps and
 * gotos are calls, marked isJump so the canvas can dash them. */
export function wirePlan(chains){
  const edges = new Map();
  const solid = (a,b)=>{ if(a && b && UID(a)!==UID(b)) edges.set(UID(a)+"→"+UID(b), [UID(a),UID(b),false]); };
  const hooked = chains.filter(c=>c.hook);
  const classes = new Set(hooked.flatMap(classesOf));
  const hooksUsed = [...new Set(hooked.map(c=>c.hook))];

  for(const cls of classes)
    for(const h of hooksUsed){
      const g = prioGroups(chains, cls, h);
      for(let i=1;i<g.length;i++) for(const a of g[i-1]) for(const b of g[i]) solid(a,b);
    }
  for(const cls of ["v4","v6"]){
    if(!classes.has(cls)) continue;
    for(const path of Object.values(PATHS)){
      const seq = path.flat().map(h=>prioGroups(chains, cls, h)).filter(g=>g.length);
      for(let i=1;i<seq.length;i++)
        for(const a of seq[i-1].at(-1)) for(const b of seq[i][0]) solid(a,b);
    }
  }
  chains.forEach(ch=>ch.rules.forEach(r=>{
    const tgt = (r.verdict==="jump"||r.verdict==="goto") && targetIn(chains, ch, r.to);
    if(tgt) edges.set(UID(ch)+"⇢"+UID(tgt), [UID(ch), UID(tgt), true]);
  }));
  return [...edges.values()];
}

/* Which chains a packet can reach at all: the base chains, and everything
   reachable from them by a jump or goto. A regular chain nobody lands on is
   loaded and never run. */
export function reachable(chains){
  const byUid = new Map(chains.map(c=>[UID(c), c]));
  const seen = new Set();
  const stack = chains.filter(c=>c.hook).map(UID);
  while(stack.length){
    const uid = stack.pop();
    if(seen.has(uid) || !byUid.has(uid)) continue;
    seen.add(uid);
    for(const r of byUid.get(uid).rules)
      if(r.verdict==="jump" || r.verdict==="goto"){
        const tgt = targetIn(chains, byUid.get(uid), r.to);
        if(tgt) stack.push(UID(tgt));
      }
  }
  return seen;
}
