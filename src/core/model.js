/* The ruleset itself, plus the vocabulary every other module shares. */
export const HOOKS = ["prerouting","input","forward","output","postrouting"];

export const R = (expr,verdict,o={}) => Object.assign({expr,verdict,on:true,pkts:0,bytes:0},o);

/* What the application opens on: a blank stateful skeleton, not somebody
   else's firewall. Three filter hooks, default-deny on the two that face the
   network, and the conntrack fast path — the shape almost every nftables
   ruleset starts from, and every line of it the user's own from the first
   second.
   The demo ruleset that used to live here is a test fixture now
   (test/fixtures/flawed.nft). An application must never open on a firewall
   its user did not write. */
export function blankRuleset(){
  const chain = (hook, policy, rules) =>
    ({id:hook, table:"inet filter", hook, prio:0, type:"filter", policy, rules});
  return {
    chains: [
      chain("input", "drop", [
        R("ct state established,related", "accept"),
        R("iif lo", "accept"),
      ]),
      chain("forward", "drop", [
        R("ct state established,related", "accept"),
      ]),
      chain("output", "accept", []),
    ],
    sets: [],
  };
}

/* Nothing is open until someone opens something. The application used to boot
   holding a ruleset called "untitled" that the user had not asked for, which
   is a small lie about what state you are in — and the one state where it
   matters, because every screen describes a ruleset. blankRuleset() is what
   New produces; this is what no project looks like. */
export const MODEL = { chains: [], sets: [] };

export const VCOLOR = {accept:"--v-accept",drop:"--v-drop",reject:"--v-reject",jump:"--v-jump",dnat:"--v-dnat",snat:"--v-snat",log:"--v-log"};
export const VNAME  = {accept:"ACCEPT",drop:"DROP",reject:"REJECT",jump:"JUMP",dnat:"DNAT",snat:"SNAT",log:"LOG"};
export const fmtN = n => n>=1e9?(n/1e9).toFixed(1)+"G":n>=1e6?(n/1e6).toFixed(1)+"M":n>=1e3?(n/1e3).toFixed(1)+"k":String(n);
export const fmtB = n => n>=1e9?(n/1e9).toFixed(1)+" GB":n>=1e6?(n/1e6).toFixed(1)+" MB":n>=1e3?(n/1e3).toFixed(1)+" kB":n+" B";

/* verdict phrase as it appears in real nft syntax */
export function verdictText(r){
  if(r.implicit)           return "";   /* imported rule that falls through */
  if(r.verdict==="jump")   return "jump "+r.to;
  if(r.verdict==="dnat")   return "dnat to "+r.to;
  if(r.verdict==="snat")   return r.to==="masquerade" ? "masquerade" : "snat to "+r.to;
  if(r.verdict==="reject") return r.to ? "reject with "+r.to : "reject";
  return r.verdict;
}
/* `ctr` is whether the rule counts; `pkts` is what it has counted so far. A
   rule imported with `counter packets 0 bytes 0` has the first and not the
   second, and must still emit its counter. `pkts` is honoured too so that
   rules built before the distinction existed keep theirs. */
export function ruleLine(r){ return ((r.expr ? r.expr+" " : "") + (r.ctr || r.pkts ? "counter ":"") + verdictText(r)).trim(); }

export const UID = ch => ch.table + '/' + ch.id;
export const jumpTarget = (ch, name) =>
  MODEL.chains.find(c => c.table === ch.table && c.id === name);
export const chainOf = uid => MODEL.chains.find(c => UID(c) === uid);
