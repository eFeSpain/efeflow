/* nftables source → model. The expression is kept verbatim minus the
   counter and comment, which is what makes the round-trip faithful. */
import { ruleLine } from './model.js';
import { PRIO_NAME } from './priority.js';
export function parseNft(text){
  const chains = [], sets = [], errors = [];
  let table = null, cur = null, curSet = null, depth = 0;

  text.split("\n").forEach((raw, ln)=>{
    let line = raw.replace(/#\s*handle\s+\d+\s*$/,"").trim();
    if(!line || line.startsWith("#")) return;

    if(line === "}"){
      depth--;
      if(curSet){ sets.push(curSet); curSet = null; }
      else if(cur){ cur = null; }
      else table = null;
      return;
    }

    let m;
    if((m = line.match(/^table\s+(\w+)\s+(\S+)\s*\{$/))){
      table = `${m[1]} ${m[2]}`; depth++; return;
    }
    if((m = line.match(/^(set|map)\s+(\S+)\s*\{$/))){
      curSet = {n:m[2], t:"", f:"", el:[], kind:m[1], table:table||"inet fw"}; depth++; return;
    }
    if(curSet){
      if((m = line.match(/^type\s+(.+?);?$/)))     curSet.t = m[1].replace(/\s*;$/,"");
      else if((m = line.match(/^flags\s+(.+?);?$/))) curSet.f = m[1].replace(/\s*;$/,"");
      else if((m = line.match(/^elements\s*=\s*\{(.*)\}\s*$/)))
        curSet.el = m[1].split(",").map(s=>s.trim()).filter(Boolean);
      return;
    }
    if((m = line.match(/^chain\s+(\S+)\s*\{$/))){
      cur = {id:m[1], table:table||"inet fw", hook:null, prio:null,
             type:"regular", policy:null, rules:[]};
      chains.push(cur); depth++; return;
    }
    if(!cur){ return; }

    /* chain header: type filter hook input priority filter; policy drop; */
    if((m = line.match(/^type\s+(\w+)\s+hook\s+(\w+)\s+(?:device\s+"\S+"\s+)?priority\s+(-?\w+)\s*;(?:\s*policy\s+(\w+)\s*;)?/))){
      cur.type = m[1]; cur.hook = m[2];
      const p = m[3];
      cur.prio = /^-?\d+$/.test(p) ? +p : (PRIO_NAME[p] ?? 0);
      cur.prioName = /^-?\d+$/.test(p) ? null : p;
      cur.policy = m[4] || "accept";
      return;
    }
    if((m = line.match(/^policy\s+(\w+)\s*;?$/))){ cur.policy = m[1]; return; }

    /* a rule */
    const rule = parseRule(line);
    if(rule) cur.rules.push(rule);
    else errors.push({ln:ln+1, line:raw.trim()});
  });

  return {chains, sets, errors};
}

/* verdict scanners, longest form first so `dnat to` beats a bare token */
/* (?:^|\s+) — a rule may be nothing but its verdict, e.g. `counter drop` */
const VERDICT_RE = [
  [/(?:^|\s+)masquerade$/,                    ()=>({verdict:"snat", to:"masquerade"})],
  [/(?:^|\s+)(dnat|snat)\s+to\s+(.+)$/,       m=>({verdict:m[1], to:m[2]})],
  [/(?:^|\s+)redirect\s+to\s+(.+)$/,          m=>({verdict:"dnat", to:m[1]})],
  [/(?:^|\s+)(jump|goto)\s+(\S+)$/,           m=>({verdict:m[1], to:m[2]})],
  [/(?:^|\s+)reject\s+with\s+(.+)$/,          m=>({verdict:"reject", to:m[1]})],
  [/(?:^|\s+)reject$/,                        ()=>({verdict:"reject"})],
  [/(?:^|\s+)(accept|drop|return|continue)$/, m=>({verdict:m[1]})],
];

export function parseRule(line){
  let expr = line.replace(/;$/,"").trim();
  let pkts = 0, bytes = 0, cmt = null;

  const c = expr.match(/\bcomment\s+"((?:[^"\\]|\\.)*)"\s*$/);
  if(c){ cmt = c[1]; expr = expr.slice(0, c.index).trim(); }

  const k = expr.match(/\bcounter(?:\s+packets\s+(\d+)\s+bytes\s+(\d+))?/);
  if(k){
    pkts = +(k[1]||0); bytes = +(k[2]||0);
    if(!k[1]) pkts = 1;                    /* bare `counter`, no statistics yet */
    expr = (expr.slice(0,k.index) + expr.slice(k.index + k[0].length)).replace(/\s{2,}/g," ").trim();
  }

  for(const [re, make] of VERDICT_RE){
    const m = expr.match(re);
    if(!m) continue;
    const v = make(m);
    return Object.assign({expr: expr.slice(0, m.index).trim(), on:true, pkts, bytes},
                         v, cmt?{cmt}:{});
  }
  /* no terminal verdict — a counting or logging rule that falls through.
     A bare `counter` is a legal rule, so an empty expr is not an error. */
  if(!expr && !pkts) return null;
  return {expr, verdict:"continue", implicit:true, on:true, pkts, bytes, ...(cmt?{cmt}:{})};
}

/* ── round-trip proof: re-emit each rule and compare to its source ── */
export const normalise = s => s.replace(/#\s*handle\s+\d+\s*$/,"")
                        .replace(/\bcounter\s+packets\s+\d+\s+bytes\s+\d+/,"counter")
                        .replace(/\s+/g," ").replace(/;$/,"").trim();

export function roundTrip(text, parsed){
  const srcRules = [];
  let inChain = false, inSet = false;
  text.split("\n").forEach(raw=>{
    const line = raw.trim();
    if(/^(set|map)\s+\S+\s*\{$/.test(line)){ inSet = true; return; }
    if(/^chain\s+\S+\s*\{$/.test(line)){ inChain = true; return; }
    if(line === "}"){ if(inSet) inSet = false; else inChain = false; return; }
    if(!inChain || inSet || !line || line.startsWith("#")) return;
    if(/^(type|policy)\s/.test(line)) return;
    srcRules.push(normalise(line));
  });

  const emitted = parsed.chains.flatMap(ch=>ch.rules.map(r=>
    normalise(ruleLine(r) + (r.cmt ? ` comment "${r.cmt}"` : ""))));

  const diffs = [];
  const n = Math.max(srcRules.length, emitted.length);
  for(let i=0;i<n;i++)
    if(srcRules[i] !== emitted[i]) diffs.push({i, src:srcRules[i]??"—", out:emitted[i]??"—"});
  return {total:srcRules.length, ok:srcRules.length-diffs.length, diffs};
}
