/* What the rules mention: interfaces and addresses, derived, never declared.
 *
 * nftables has no inventory. An interface is a name inside a rule, an address
 * is a literal inside a match, and the only truthful list of either is the one
 * read out of the ruleset itself. Four screens want that list — the simulator
 * offers interfaces for a packet, the object library counts what is in use,
 * the topology draws who talks to whom, the palette searches across all of it
 * — and while they all lived in one file they could share a function without
 * anyone writing down that they did. They do not any more, so this is the
 * address the sharing happens at.
 *
 * Everything here reads MODEL and decides nothing, which is the core/ rule.
 */
import { MODEL } from "./model.js";
import { project } from "./project.js";

/** Every interface the enabled rules name, with how they use it. */
export function interfaces(){
  const map = new Map();
  MODEL.chains.forEach(ch=> ch.rules.forEach(r=>{
    if(!r.on) return;
    for(const m of r.expr.matchAll(/\b(iif|oif|iifname|oifname)\s+"?([\w.@-]+)"?/g)){
      const dir = m[1].startsWith("i") ? "in" : "out", name = m[2];
      if(name==="lo") continue;
      const e = map.get(name) || {name, in:0, out:0, rules:0, verdicts:{}, chains:new Set()};
      e[dir]++; e.rules++;
      e.verdicts[r.verdict] = (e.verdicts[r.verdict]||0)+1;
      e.chains.add(ch.id);
      map.set(name, e);
    }
  }));
  return [...map.values()].sort((a,b)=>b.rules-a.rules);
}

/* The literal addresses the rules carry, so the Networks palette shows your
   ruleset instead of five numbers I made up. Set references are excluded —
   they belong to the Sets category and have their own editor. */
export function addresses(){
  const m = new Map();
  MODEL.chains.forEach(ch=> ch.rules.forEach(r=>{
    if(!r.on) return;
    for(const x of r.expr.matchAll(/\bip6?\s+[sd]addr\s+(?:!=\s*)?([0-9a-fA-F.:]+(?:\/\d+)?)/g)){
      const text = x[1];
      m.set(text, {text, n:(m.get(text)?.n || 0) + 1});
    }
  }));
  return [...m.values()].sort((a,b)=>b.n-a.n);
}

/* Both halves, exactly as the Interfaces palette shows them: the names your
   rules already mention, and the ones you wrote down for the box you are
   working on. Keeping a name and then not being offered it — in the simulator
   or on a rule — makes the act of keeping it pointless. */
export function ifaceNames(){
  return [...new Set([
    ...interfaces().map(e=>e.name),
    ...project.scratch.ifaces,
    "lo",
  ])].sort();
}
