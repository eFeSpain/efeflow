/* Evaluates a synthetic packet against the same model the code is
   emitted from, so a verdict here is the verdict the export produces. */
import { MODEL, UID, chainOf, jumpTarget } from './model.js';
export const ip2n = ip => ip.split(".").reduce((a,o)=>(a<<8)+(+o),0)>>>0;
export function inCidr(ip,c){
  if(!c.includes("/")) return ip===c;
  const [net,bits] = c.split("/"), m = bits==="0"?0:(~0<<(32-+bits))>>>0;
  return (ip2n(ip)&m)===(ip2n(net)&m);
}
const setOf = n => (MODEL.sets.find(s=>s.n===n)||{el:[]}).el;
export function inSet(v,name){
  const el = setOf(name);
  return el.some(e=> /^\d+$/.test(e) ? e===String(v) : (e.includes(".") ? inCidr(String(v),e) : e===String(v)));
}
export function matchVal(v, tok){
  if(!v && v!==0) return false;
  if(tok.startsWith("@")) return inSet(v, tok.slice(1));
  if(tok.startsWith("{")) return tok.slice(1,-1).split(",").map(s=>s.trim()).includes(String(v));
  if(tok.includes("/"))  return inCidr(String(v),tok);
  return String(v)===tok;
}

export function matches(r,p){
  const e = r.expr;
  if(!e) return true;
  let m;
  /* an untracked packet has no conntrack entry: `ct state` can only match it
     through the untracked keyword, and `ct status` never matches */
  if((m=e.match(/ct state ([\w,]+)/))){
    const want = m[1].split(",");
    if(!p.tracked) { if(!want.includes("untracked")) return false; }
    else if(!want.includes(p.state)) return false;
  }
  if(/ct status \w+/.test(e) && (!p.tracked || !p.dnat)) return false;
  /* tcp flags syn / tcp flags & (syn|ack) == syn */
  if((m=e.match(/tcp flags\s+(!=\s*)?&?\s*\(?([\w|,]+)\)?(?:\s*==\s*\(?([\w|,]+)\)?)?/))){
    const has = f => (p.flags||[]).includes(f);
    const want = (m[3]||m[2]).split(/[|,]/).map(s=>s.trim()).filter(Boolean);
    const hit = m[3]
      ? want.every(has) && (p.flags||[]).every(f=>!m[2].includes(f) || want.includes(f))
      : want.every(has);
    if(m[1] ? hit : !hit) return false;
  }
  if((m=e.match(/\biif lo\b/)) && p.iif!=="lo") return false;
  if((m=e.match(/\boif lo\b/)) && p.oif!=="lo") return false;
  if((m=e.match(/iifname "([^"]+)"/)) && m[1]!==p.iif) return false;
  if((m=e.match(/oifname "([^"]+)"/)) && m[1]!==p.oif) return false;
  if((m=e.match(/ip saddr (!= )?(\S+)/))){ const hit = matchVal(p.saddr,m[2]); if(m[1]?hit:!hit) return false; }
  if((m=e.match(/ip daddr (!= )?(\S+)/))){ const hit = matchVal(p.daddr,m[2]); if(m[1]?hit:!hit) return false; }
  if((m=e.match(/meta l4proto \{([^}]*)\}/)) && !m[1].split(",").map(s=>s.trim()).includes(p.proto)) return false;
  if((m=e.match(/\b(tcp|udp)\b/)) && m[1]!==p.proto) return false;
  if((m=e.match(/dport ((?:\{[^}]*\})|\S+)/)) && !matchVal(p.dport,m[1])) return false;
  if((m=e.match(/sport ((?:\{[^}]*\})|\S+)/)) && !matchVal(p.sport,m[1])) return false;
  return true;
}

export const BASE = {dir:"in", oif:"", flags:["syn"], tracked:true, nat:true, step:false};
export const PRESETS = {
  ssh:     {...BASE, iif:"wan0", saddr:"203.0.113.47", daddr:"198.51.100.10", sport:49812, dport:22,   proto:"tcp", state:"new"},
  https:   {...BASE, iif:"wan0", saddr:"81.2.69.144",  daddr:"198.51.100.10", sport:51233, dport:443,  proto:"tcp", state:"new"},
  dnat:    {...BASE, iif:"wan0", saddr:"198.51.100.7", daddr:"198.51.100.10", sport:44120, dport:8443, proto:"tcp", state:"new"},
  invalid: {...BASE, iif:"wan0", saddr:"203.0.113.9",  daddr:"198.51.100.10", sport:1337,  dport:80,   proto:"tcp", state:"invalid"},
  fwd:     {...BASE, dir:"fwd", iif:"br-lan", oif:"wan0", saddr:"10.10.0.44", daddr:"93.184.216.34",
            sport:52110, dport:443, proto:"tcp", state:"new"},
  egress:  {...BASE, dir:"out", iif:"", oif:"wan0", saddr:"198.51.100.10", daddr:"1.1.1.1",
            sport:33344, dport:53, proto:"udp", state:"new"},
};
/* The packet under test. A live object rather than a reassignable binding, so
   the UI can mutate it in place and every reader sees the same one. */
export const packet = { ...PRESETS.ssh, flags: [...PRESETS.ssh.flags] };

/* the direction the user picked is the path the packet takes — the kernel's
   own routing decision, not something we infer from the address */
export const PATHS = {
  in:  [["prerouting"],["input"]],
  fwd: [["prerouting"],["forward"],["postrouting"]],
  out: [["output"],["postrouting"]],
};

export function evaluate(p){
  const steps = [];
  const walk = (chainId, depth=0) => {
    const ch = chainOf(chainId);
    const hop = {chain:ch, evs:[], depth};
    steps.push(hop);
    for(let i=0;i<ch.rules.length;i++){
      const r = ch.rules[i];
      if(!r.on){ hop.evs.push({r,i,st:"miss",note:"disabled"}); continue; }
      const hit = matches(r,p);
      if(!hit){ hop.evs.push({r,i,st:"miss"}); continue; }
      hop.evs.push({r,i,st:"match"});
      /* nftables terminality: `accept` ends this chain but the packet carries
         on to the next hook. Only drop/reject end the packet outright. */
      if(r.verdict==="dnat"){ p.dnat = true; p.daddr = r.to.split(":")[0]; p.dport = +r.to.split(":")[1]; hop.nat = r.to; return {stop:"chain"}; }
      if(r.verdict==="snat"){ hop.nat = r.to; return {stop:"chain"}; }
      if(r.verdict==="jump"){ const tgt = jumpTarget(ch, r.to);
        if(tgt){ const v = walk(UID(tgt), depth+1); if(v) return v; } continue; }
      if(r.verdict==="accept"){ accepted = {v:"accept", chain:ch, r, i}; return {stop:"chain"}; }
      if(r.verdict==="drop" || r.verdict==="reject")
        return {stop:"packet", v:r.verdict, chain:ch, r, i};
    }
    if(ch.policy && ch.policy!=="accept"){
      hop.policy = ch.policy;
      return {stop:"packet", v:ch.policy, chain:ch, policy:true};
    }
    if(ch.policy==="accept" && depth===0 && ch.hook){
      hop.policy = "accept";
      accepted = {v:"accept", chain:ch, policy:true};
    }
    return {stop:"chain"};
  };
  let accepted = null;
  /* nat chains can be skipped entirely, which is how you see what the filter
     path alone decides */
  const byHook = h => MODEL.chains
    .filter(c=>c.hook===h && (p.nat || c.type!=="nat"))
    .sort((a,b)=>a.prio-b.prio).map(c=>UID(c));

  const stages = (PATHS[p.dir] || PATHS.in).flatMap(([h])=>byHook(h));
  let final = null, last = stages[0] || (MODEL.chains[0] && UID(MODEL.chains[0]));
  for(const c of stages){
    last = c;
    const out = walk(c);
    if(out && out.stop==="packet"){ final = out; break; }   /* dropped: done */
  }
  /* survived every hook — the verdict is whatever last accepted it */
  return {steps, final: final || accepted || {v:"accept", chain:chainOf(last), policy:true}};
}

export const setPacket = p => Object.assign(packet, p);
