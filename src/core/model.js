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
/* `objects`, `tables` and `prelude` are where preserve-by-default puts what it
   keeps: the flowtables and ct helpers, the table flags, and the `define` and
   `include` lines above the first table. The last of those were dropped while
   the rules using `$wan` were kept, so an imported script came back out
   referencing a variable nothing defined. */
export const MODEL = { chains: [], sets: [], objects: [], tables: [], prelude: [],
                       preludeAt: [] };

/* Every verdict the parser can produce needs an entry in both, because the
   canvas paints a pill from them per rule. `goto` shares the colour of `jump`
   and `redirect` that of `dnat` — they are the same thing to a packet, and the
   pill text is what tells them apart. A rule that decides nothing (`return`,
   or the implicit `continue` of a log-only rule) is grey, like `log`: nothing
   was settled here. */
export const VCOLOR = {accept:"--v-accept",drop:"--v-drop",reject:"--v-reject",
  jump:"--v-jump",goto:"--v-jump",dnat:"--v-dnat",redirect:"--v-dnat",snat:"--v-snat",
  log:"--v-log",return:"--v-log",continue:"--v-log"};
export const VNAME  = {accept:"ACCEPT",drop:"DROP",reject:"REJECT",
  jump:"JUMP",goto:"GOTO",dnat:"DNAT",redirect:"REDIRECT",snat:"SNAT",
  log:"LOG",return:"RETURN",continue:"CONTINUE"};
export const fmtN = n => n>=1e9?(n/1e9).toFixed(1)+"G":n>=1e6?(n/1e6).toFixed(1)+"M":n>=1e3?(n/1e3).toFixed(1)+"k":String(n);
export const fmtB = n => n>=1e9?(n/1e9).toFixed(1)+" GB":n>=1e6?(n/1e6).toFixed(1)+" MB":n>=1e3?(n/1e3).toFixed(1)+" kB":n+" B";

/* verdict phrase as it appears in real nft syntax */
export function verdictText(r){
  if(r.implicit)           return "";   /* imported rule that falls through */
  /* jump and goto both name a chain, and a `goto` written without one is a
     syntax error rather than a default — which is what this used to emit.
     A missing target stays missing: `jump undefined` reads like a chain
     somebody called undefined, and core/lint.js can see a bare `jump`. */
  const to = r.to ?? "";
  if(r.verdict==="jump" || r.verdict==="goto") return (r.verdict+" "+to).trim();
  if(r.verdict==="dnat")   return ("dnat to "+to).trim();
  if(r.verdict==="snat")   return r.to==="masquerade" ? "masquerade" : ("snat to "+to).trim();
  /* `redirect` takes an optional port; bare, it redirects to the same one. */
  if(r.verdict==="redirect") return r.to ? "redirect to "+r.to : "redirect";
  if(r.verdict==="reject") return r.to ? "reject with "+r.to : "reject";
  return r.verdict;
}
/* `ctr` is whether the rule counts; `pkts` is what it has counted so far. A
   rule imported with `counter packets 0 bytes 0` has the first and not the
   second, and must still emit its counter. `pkts` is honoured too so that
   rules built before the distinction existed keep theirs. */
/* `ctrAt` says the counter did not sit just before the verdict, and it is the
   word of the expression it went in front of. Only rules that arrived that way
   carry it; everything else takes the path below, unchanged.
   Split on the separators rather than through them, so a `log prefix "two
   spaces"` keeps its own spacing instead of being tidied into a different
   rule. */
function withCounter(expr, at){
  const bits = expr.split(/(\s+)/);
  const i = at * 2;
  if(i >= bits.length) return null;      /* the expression has since got shorter */
  bits.splice(i, 0, "counter", " ");
  return bits.join("");
}
export function ruleLine(r){
  const ctr = r.ctr || r.pkts;
  if(ctr && r.ctrAt != null && r.expr){
    const placed = withCounter(String(r.expr), r.ctrAt);
    if(placed !== null) return (placed + " " + verdictText(r)).trim();
  }
  return ((r.expr ? r.expr+" " : "") + (ctr ? "counter ":"") + verdictText(r)).trim();
}

/* `define WAN = wan0` above the first table, and `$WAN` in fifty rules below.
 *
 * The parser keeps both, and deliberately: the definitions in `prelude`, the
 * references verbatim in the rules, which is what makes the round-trip exact
 * and what lets the file come back out looking like the file that went in.
 * Nothing resolved them, so the evaluator compared a packet arriving on wan0
 * against the string "$WAN" and missed — and so did every other matcher, on
 * every rule of a ruleset written the way most of them are written.
 *
 * A rule that cannot match for a reason that is not a reason is the worst
 * shape this can fail in: silent, and confident. So the text stays as it was
 * and the reasoning happens on the expansion. */
export function defines(model = MODEL){
  const out = new Map();
  for(const line of model.prelude || []){
    const m = String(line).match(/^define\s+([A-Za-z_]\w*)\s*=\s*(.+?)\s*;?$/);
    /* nft accepts a quoted value and an unquoted one for the same thing, and
       the rules below use them interchangeably: `iifname $WAN` wants wan0
       whether the define wrote it with quotes or without */
    if(m) out.set(m[1], m[2].replace(/^"([^"]*)"$/, "$1"));
  }
  return out;
}

/** An expression with its `$name` references replaced by what they name. */
export function expand(expr, model = MODEL){
  const e = String(expr ?? "");
  if(!e.includes("$")) return e;                  /* the overwhelming majority */
  const map = defines(model);
  if(!map.size) return e;
  /* A define may name another one. The bound is here because a definition
     that names itself must not hang the canvas — nft rejects that, we just
     stop. A name with no definition is left as it was written: `include` can
     have provided it, and inventing a value would be worse than saying so. */
  let out = e;
  for(let i = 0; i < 8 && out.includes("$"); i++){
    const next = out.replace(/\$([A-Za-z_]\w*)/g, (all, n) => map.has(n) ? map.get(n) : all);
    if(next === out) break;
    out = next;
  }
  return out;
}

export const UID = ch => ch.table + '/' + ch.id;
export const jumpTarget = (ch, name) =>
  MODEL.chains.find(c => c.table === ch.table && c.id === name);
export const chainOf = uid => MODEL.chains.find(c => UID(c) === uid);
