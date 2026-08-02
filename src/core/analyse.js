/* Findings are derived from the model, never authored. The core relation
   is subsumption: A subsumes B when every packet matching B matches A. */
import { MODEL, R, ruleLine, jumpTarget, UID, chainOf } from './model.js';

/* A finding describes the ruleset; applying it must act on the ruleset as
   it is now. Capturing object references looked fine until undo — which
   rebuilds every chain and rule from JSON — left the fixes pointing at
   orphans, so the button did nothing and said nothing. Resolve on apply. */
const at = (uid, i) => { const c = chainOf(uid); return c && c.rules[i] ? c : null; };
import { inSet, readable } from './simulate.js';
import { covers as addrCovers } from './addr.js';
import { lintRuleset } from './lint.js';
import { dormantTables, isDormant, readTable, writeTable } from './tables.js';
import { escape as esc } from './html.js';
import { t } from '../i18n.js';
const CRIT = [
  ["proto", /\b(tcp|udp|sctp)\b/],
  /* `meta l4proto icmp`, `ip protocol icmp` and `ip6 nexthdr icmpv6` are the
     same constraint spelled three ways. Reading only the first meant
     `ip protocol icmp counter drop` produced no criteria at all — which is how
     this file spells "matches every packet" — so every rule under it was
     reported dead, each with a one-click Delete offered above an Apply all. */
  ["l4",    /(?:meta l4proto|ip protocol|ip6 nexthdr) (\{[^}]*\}|\S+)/],
  ["state", /ct state ([\w,]+)/],
  ["ctst",  /ct status (\w+)/],
  ["iif",   /(?:iif|iifname) "?([\w.-]+)"?/],
  ["oif",   /(?:oif|oifname) "?([\w.-]+)"?/],
  ["saddr", /ip6? saddr (?!!=)(\S+)/],
  ["daddr", /ip6? daddr (?!!=)(\S+)/],
  ["sport", /sport (\{[^}]*\}|\S+)/],
  ["dport", /dport (\{[^}]*\}|\S+)/],
];
/* Statements that say what to do rather than what to match, so leaving one
   unread costs nothing. Everything else left over is a constraint this file
   did not see. */
const NOT_A_MATCH = [
  /\blog\b(?:\s+(?:prefix\s+"(?:[^"\\]|\\.)*"|level\s+\S+|group\s+\d+|snaplen\s+\d+|queue-threshold\s+\d+|flags\s+\S+))*/g,
  /\bcounter(?:\s+name\s+"[^"]*"|\s+packets\s+\d+\s+bytes\s+\d+)?/g,
  /\bcomment\s+"(?:[^"\\]|\\.)*"/g,
  /\blimit rate\s+(?:over\s+)?\d+\/\w+(?:\s+burst\s+\d+\s+\w+)?/g,
];

export function criteria(expr){
  /* against the masked expression: `fib saddr . iif oif missing` names iif and
     oif as keys of a lookup, and reading them as constraints did not produce
     nothing — it produced iif "oif" and oif "missing", invented out of thin
     air and then reasoned with */
  const e = readable(expr);
  const c = {};
  const read = [];
  /* Which criteria this rule constrains, as one integer. Shadowing asks the
     same question of every pair — does A constrain anything B leaves open —
     and asking it ten string comparisons at a time is what made the analyser
     quadratic in wall-clock as well as in pairs. See subsumes(). */
  let bits = 0;
  CRIT.forEach(([k,re],i)=>{
    const m = e.match(re);
    if(m){ c[k] = m[1]; bits |= 1 << i; read.push([m.index, m.index + m[0].length]); }
  });
  c._bits = bits;
  c._limit  = /limit rate/.test(e);         /* rate-limited ⇒ non-deterministic */
  c._log    = /\blog\b/.test(e);
  c._negate = /!=/.test(e);

  /* What is left once everything read has been taken out. A rule carrying one
     of those matches far fewer packets than its criteria suggest, and the
     whole of this file's reasoning is about how many packets a rule matches. */
  for(const re of NOT_A_MATCH)
    for(const m of e.matchAll(re)) read.push([m.index, m.index + m[0].length]);
  read.sort((a,b)=>a[0]-b[0]);
  let at = 0, rest = "";
  for(const [x,y] of read){ if(x > at) rest += e.slice(at, x); at = Math.max(at, y); }
  rest += e.slice(at);
  c._opaque = /\S/.test(rest) || readable(expr) !== String(expr || "");
  return c;
}
const listOf = v => v.startsWith("{") ? v.slice(1,-1).split(",").map(s=>s.trim()) : [v];

/* Is this token in that set? The same question, over and over.
 *
 * `ip saddr @blocked` against a set of 200 prefixes walks all 200, and
 * shadowing asks it for every pair of rules that names the set — which on a
 * real ruleset is most of them. The tokens repeat; the set does not change
 * while the analysis runs. So the answers are remembered for exactly the
 * length of one analyse() and thrown away at the end of it.
 *
 * Null outside a run, deliberately. subsumes() and overlaps() are exported and
 * a caller may have edited a set since the last analysis, so away from the one
 * place that controls the lifetime, the uncached path is the only honest one. */
let SETMEMO = null;

function memberOf(token, name){
  if(!SETMEMO) return inSet(token, name);
  let seen = SETMEMO.get(name);
  if(!seen) SETMEMO.set(name, seen = new Map());
  let hit = seen.get(token);
  if(hit === undefined) seen.set(token, hit = inSet(token, name));
  return hit;
}

/* does criterion value A cover value B? */
function covers(a,b){
  if(a===b) return true;
  const A = listOf(a), B = listOf(b);
  if(B.every(x=>A.includes(x))) return true;
  if(a.startsWith("@")) return B.every(x=>memberOf(x, a.slice(1)));
  /* Addresses and prefixes, in either family. This was gated behind a regex
     only IPv4 could pass, so a v6 rule shadowed by a broader v6 rule went
     unreported — and it compared network addresses without their prefix
     lengths, which had 10.1.0.0/16 covering 10.1.0.0/8. addrCovers answers
     false for anything that is not an address, so ports and interface names
     can go through it untested. */
  return B.every(x => addrCovers(a, x));
}
/* every packet matching b also matches a
 *
 * `a._opaque` and not `b._opaque`, and the asymmetry is the point. If A
 * carries a match nothing read, A may fire far less often than its criteria
 * suggest, so it cannot be claimed to cover anything. If B does, B fires less
 * often than it looks — and a rule covering the looser reading of B covers the
 * tighter one too, so that finding still stands. */
export function subsumes(a,b){
  if(a._limit || a._negate || b._negate) return false;   /* can't reason safely */
  if(a._opaque) return false;
  /* One integer instead of up to ten string comparisons, and exactly the same
     question the loop below used to ask first: if A constrains anything B
     leaves open, B is the broader rule and A cannot cover it. Most pairs in a
     real ruleset die here, which is the difference between an analyser that
     runs while you type and one that does not. */
  if((a._bits & ~b._bits) !== 0) return false;
  return CRIT.every(([k])=>{
    if(a[k]===undefined) return true;      /* a is wildcard here */
    if(b[k]===undefined) return false;     /* b is broader than a */
    return covers(a[k], b[k]);
  });
}
/* some packet matches both — and here either side being unread is fatal, since
   an unread constraint on either can be the very thing that keeps them apart */
export function overlaps(a,b){
  if(a._negate || b._negate) return false;
  if(a._opaque || b._opaque) return false;
  return CRIT.every(([k])=>{
    if(a[k]===undefined || b[k]===undefined) return true;
    return covers(a[k],b[k]) || covers(b[k],a[k]);
  });
}
const TERMINAL = v => v==="accept" || v==="drop" || v==="reject";

/* `at` is what the finding is about, which is not always one rule. A chain
   that never drops invalid, a set nothing references, a whole table parked —
   each carries a chain and an index so "Go to rule" lands somewhere sensible,
   and quoting that rule underneath the title reads as an accusation against a
   line that did nothing wrong. Anything not said otherwise is about its rule. */
const F = (sev,kind,o) => Object.assign({sev,kind,at:"rule"},o);

export function analyse(){
  const out = [], live = ch => ch.rules.map((r,i)=>({r,i})).filter(x=>x.r.on);
  /* set membership is fixed for the length of this call, and only for it */
  SETMEMO = new Map();
  try{

  MODEL.chains.forEach(ch=>{
    const rs = live(ch).map(x=>({...x, c:criteria(x.r.expr)}));

    /* ── shadowed / dead rules ── */
    rs.forEach((b,bi)=>{
      for(let ai=0; ai<bi; ai++){
        const a = rs[ai];
        if(!TERMINAL(a.r.verdict)) continue;
        if(!subsumes(a.c, b.c)) continue;
        out.push(F("warn","shadowed",{
          chain:ch, i:b.i, ref:a.i,
          title:[`Rule ${b.i+1} is shadowed by rule ${a.i+1} and can never match`,
                 `La regla ${b.i+1} está eclipsada por la ${a.i+1} y nunca puede coincidir`],
          where:`${ch.table} / ${ch.id}`,
          detail:[`Rule ${a.i+1} already ${a.r.verdict}s every packet rule ${b.i+1} could match, and it comes first. Rule ${b.i+1} costs one evaluation on every packet that reaches it and changes nothing.`,
                  `La regla ${a.i+1} ya aplica ${a.r.verdict} a todo paquete que podría casar con la ${b.i+1}, y va antes. La regla ${b.i+1} cuesta una evaluación en cada paquete que llega hasta ella y no cambia nada.`],
          code:[[a.i+1, ruleLine(a.r), "neg"],[b.i+1, ruleLine(b.r), "dead"]],
          fix:{label:["Delete rule "+(b.i+1),"Eliminar la regla "+(b.i+1)],
               run:()=>{ const c = at(UID(ch), b.i); if(c) c.rules.splice(b.i,1); }},
        }));
        break;
      }
    });

    /* ── overlapping NAT with divergent targets ── */
    /* redirect is a DNAT too, and two redirects to different ports collide the
       same way — but a dnat and a redirect are not comparable targets, so only
       pairs of the same verdict are weighed against each other. */
    const nats = rs.filter(x=>x.r.verdict==="dnat" || x.r.verdict==="redirect");
    nats.forEach((a,k)=> nats.slice(k+1).forEach(b=>{
      if(a.r.verdict!==b.r.verdict) return;
      if(a.r.to===b.r.to || !overlaps(a.c,b.c)) return;
      out.push(F("error","conflict",{
        chain:ch, i:b.i, ref:a.i,
        title:[`Conflicting DNAT targets for the same destination port`,
               `Destinos DNAT en conflicto para el mismo puerto destino`],
        where:`${ch.table} / ${ch.id}`,
        detail:[`Rules ${a.i+1} and ${b.i+1} both match traffic to <code>${esc(a.c.dport||"?")}</code> but translate it to different hosts. nftables terminates the chain on the first NAT verdict, so rule ${a.i+1} silently wins for every packet matching both and rule ${b.i+1} never fires.`,
                `Las reglas ${a.i+1} y ${b.i+1} coinciden con tráfico a <code>${esc(a.c.dport||"?")}</code> pero lo traducen a hosts distintos. nftables termina la cadena en el primer veredicto NAT, así que la regla ${a.i+1} gana en silencio para todo paquete que case con ambas y la ${b.i+1} nunca se dispara.`],
        code:[[a.i+1, ruleLine(a.r), "neg"],[b.i+1, ruleLine(b.r), "dead"]],
        /* The narrowing comes from the other rule, never from a name we made
           up. This appended `ip saddr != @admin_nets` — a set from the demo
           ruleset, the same leftover as the jump to fwd_mgmt and the
           10.20.0.15 target. Written into a table that has no such set, it
           produced a rule nft refuses, so the fix broke the file it was
           offered to repair. With nothing to derive, there is no fix. */
        ...(b.c.saddr ? {fix:{
          label:["Narrow rule "+(a.i+1),"Restringir la regla "+(a.i+1)],
          run:()=>{ const c = at(UID(ch), a.i); if(!c) return;
                 const r = c.rules[a.i];
                 if(!/ip6? saddr/.test(r.expr)) r.expr += ` ip saddr != ${b.c.saddr}`; }},
        } : {}),
      }));
    }));

    /* ── mergeable siblings: same everything but one field ── */
    const seen = new Set();
    rs.forEach(a=>{
      if(seen.has(a.i) || !a.c.dport || listOf(a.c.dport).length>1) return;
      const key = k => CRIT.map(([n])=> n==="dport" ? "*" : (k[n]||"")).join("|");
      const sibs = rs.filter(b=> b.r.verdict===a.r.verdict && b.c.dport
                             && listOf(b.c.dport).length===1 && key(b.c)===key(a.c));
      if(sibs.length < 3) return;
      sibs.forEach(s=>seen.add(s.i));
      const ports = sibs.map(s=>s.c.dport);
      const match = MODEL.sets.find(s=> s.el.length===ports.length && s.el.every(e=>ports.includes(e)));
      out.push(F("hint","merge",{
        at:"rules", chain:ch, i:sibs[0].i,
        title:[`${sibs.length} rules differ only by destination port`,
               `${sibs.length} reglas solo difieren en el puerto destino`],
        where:`${ch.table} / ${ch.id} · ${t("rules","reglas")} ${sibs.map(s=>s.i+1).join(", ")}`,
        detail:match
          ? [`These ports are exactly the contents of the existing set <code>@${esc(match.n)}</code>. One set lookup is a single hash probe instead of ${sibs.length} linear comparisons, and leaves one place to edit.`,
             `Estos puertos son exactamente el contenido del set existente <code>@${esc(match.n)}</code>. Una consulta a set es un solo sondeo hash en vez de ${sibs.length} comparaciones lineales, y deja un único sitio que editar.`]
          : [`Collapsing them into an anonymous set costs one hash probe instead of ${sibs.length} comparisons.`,
             `Colapsarlas en un set anónimo cuesta un sondeo hash en vez de ${sibs.length} comparaciones.`],
        code:sibs.map(s=>[s.i+1, ruleLine(s.r), "neg"])
              .concat([["→", (a.c.proto||"tcp")+" dport @"+(match?match.n:"ports")+
                             (a.c.saddr?" ip saddr "+a.c.saddr:"")+" "+a.r.verdict, "pos"]]),
        fix:{label:match?["Merge into @"+match.n,"Fusionar en @"+match.n]:["Create set","Crear set"],
             run:()=>{
               const c = chainOf(UID(ch)); if(!c) return;
               const name = match ? match.n : "ports";
               if(!match) MODEL.sets.push({n:name, table:c.table, t:"inet_service", f:"", el:ports});
               /* indices, resolved now — the rule objects analysed may be gone */
               const idx = sibs.map(x=>x.i).filter(i=>c.rules[i]);
               if(!idx.length) return;
               const keep = c.rules[idx[0]];
               keep.expr = keep.expr.replace(/dport \S+/, "dport @"+name);
               keep.pkts = idx.reduce((n,i)=>n+c.rules[i].pkts, 0);
               keep.bytes = idx.reduce((n,i)=>n+c.rules[i].bytes, 0);
               idx.slice(1).sort((x,y)=>y-x).forEach(i=>c.rules.splice(i,1));
             }},
      }));
    });

    /* ── hardening: filter chain that trusts conntrack but never drops invalid ── */
    if(ch.type==="filter" && ch.hook && ch.policy==="drop"
       && rs.some(x=>/ct state established/.test(x.r.expr))
       && !rs.some(x=>/ct state[\w,]*invalid|ct state invalid/.test(x.r.expr))){
      out.push(F("warn","hardening",{
        at:"chain", chain:ch, i:0,
        title:[`${ch.id} chain has no invalid-state drop`,
               `La cadena ${ch.id} no descarta el estado invalid`],
        where:`${ch.table} / ${ch.id} · ${t("chain-level","nivel de cadena")}`,
        detail:[`This chain fast-paths <code>established</code> traffic but lets <code>invalid</code> packets traverse all ${rs.length} rules before falling through to the policy. Dropping them first is both safer and cheaper.`,
                `Esta cadena da vía rápida al tráfico <code>established</code> pero deja que los paquetes <code>invalid</code> recorran las ${rs.length} reglas antes de caer en la política. Descartarlos primero es más seguro y más barato.`],
        code:[["+", "ct state invalid counter drop", "pos"]],
        fix:{label:["Insert at position 1","Insertar en la posición 1"],
             run:()=>{ const c = chainOf(UID(ch));
                    if(c) c.rules.unshift(R("ct state invalid","drop",{pkts:0,bytes:0})); }},
      }));
    }

    /* ── an unrated log rule is a self-inflicted denial of service ── */
    rs.forEach(x=>{
      if(!x.c._log || x.c._limit) return;
      out.push(F("hint","resilience",{
        chain:ch, i:x.i,
        title:[`Log rule has no rate limit`,`La regla de log no tiene límite de tasa`],
        where:`${ch.table} / ${ch.id} · ${t("rule","regla")} ${x.i+1}`,
        detail:[`An unrated log rule will flood the kernel ring buffer under a scan or a flood, and dmesg pressure is how you lose the logs you actually needed.`,
                `Una regla de log sin límite inundará el ring buffer del kernel durante un escaneo o una avalancha, y la presión sobre dmesg es justo cómo se pierden los logs que hacían falta.`],
        code:[[x.i+1, ruleLine(x.r), "neg"],
              ["→", ruleLine(x.r).replace(/\blog\b/, "limit rate 5/second burst 10 packets log"), "pos"]],
        fix:{label:["Add rate limit","Añadir límite de tasa"],
             run:()=>{ const c = at(UID(ch), x.i); if(!c) return;
                    const r = c.rules[x.i];
                    r.expr = r.expr.replace(/\blog\b/, "limit rate 5/second burst 10 packets log"); }},
      }));
    });
  });

  /* ── sets loaded into the kernel that no rule consumes ── */
  const allExpr = MODEL.chains.flatMap(c=>c.rules.filter(r=>r.on).map(r=>r.expr)).join(" ");
  MODEL.sets.forEach(s=>{
    if(allExpr.includes("@"+s.n)) return;
    out.push(F("hint","unused",{
      at:"set", set:s.n,
      title:[`Set @${s.n} is declared but never referenced`,
             `El set @${s.n} se declara pero nunca se referencia`],
      where:`inet fw · set`,
      detail:[`Its ${s.el.length} element${s.el.length===1?"":"s"} are loaded into the kernel on every reload with no rule consuming them.`,
              `Sus ${s.el.length} elemento${s.el.length===1?"":"s"} se cargan en el kernel en cada recarga sin que ninguna regla los consuma.`],
      code:[["", `set ${s.n} { type ${s.t}${s.f?" ; flags "+s.f:""} }`, "neg"]],
      fix:{label:["Remove set","Eliminar el set"],
           run:()=>{ const i = MODEL.sets.findIndex(x=>x.n===s.n);
                  if(i>=0) MODEL.sets.splice(i,1); }},
      go:"sets",
    }));
  });

  /* ── tables that are loaded and not running ───────────────────────────
     `flags dormant` unregisters every base chain in the table. The ruleset
     applies, nft says nothing, and not one packet is filtered by it. Somebody
     parked it on purpose once; the risk is that nobody remembers. */
  dormantTables(MODEL).forEach(name=>{
    const info = readTable(MODEL, name);
    if(!info.chains) return;   /* an empty parked table is a note, not a risk */
    out.push(F("warn","dormant",{
      at:"table", table:name,
      title:[`Table ${name} is dormant — its ${info.rules} rule${info.rules===1?"":"s"} are not running`,
             `La tabla ${name} está dormant — sus ${info.rules} regla${info.rules===1?"":"s"} no se están aplicando`],
      where:`${name} · ${t("table","tabla")}`,
      detail:[`<code>flags dormant</code> unregisters every base chain in the table, so nothing in it ever sees a packet. The ruleset still loads and nft reports nothing wrong — this is the state a firewall is parked in, and it looks identical to a working one everywhere it is not read out loud.`,
              `<code>flags dormant</code> desregistra todas las cadenas base de la tabla, así que nada dentro de ella llega a ver un paquete. El ruleset sigue cargando y nft no informa de nada — es el estado en el que se aparca un firewall, y es idéntico a uno en marcha en todos los sitios donde no se dice en voz alta.`],
      code:[["", `table ${name} { flags dormant }`, "neg"]],
      fix:{label:["Wake the table up","Despertar la tabla"],
           run:()=>{ writeTable(MODEL, name, {dormant:false, comment:readTable(MODEL,name).comment}); }},
    }));
  });

  /* ── rules nft would refuse ──────────────────────────────────────────
     Everything above describes a ruleset that works. This one asks whether it
     works at all, and it belongs at the top: a shadowed rule costs you an
     evaluation, a rule that will not parse costs you the entire apply. */
  lintRuleset(MODEL).forEach(f=>{
    out.push(F("error","syntax",{
      chain:f.chain, i:f.i,
      title:f.title,
      where:`${f.chain.table} / ${f.chain.id} · ${t("rule","regla")} ${f.i+1}`,
      detail:[`nft rejects this line, and it rejects the whole file with it — a ruleset is applied entire or not at all, so one rule like this is the difference between your firewall changing and nothing happening.`,
              `nft rechaza esta línea, y con ella el fichero entero — un ruleset se aplica completo o no se aplica, así que una regla así es la diferencia entre que tu firewall cambie y que no pase nada.`],
      code:[[f.i+1, ruleLine(f.chain.rules[f.i]), "neg"]],
    }));
  });

  const rank = {error:0, warn:1, hint:2};
  /* Syntax first within the errors: it is the one that stops everything. And
     dormant first within the warnings — a shadowed rule costs an evaluation, a
     parked table means none of the rules below are running at all. */
  const kindRank = k => k==="syntax" || k==="dormant" ? 0 : 1;
  return out.sort((a,b)=> rank[a.sev]-rank[b.sev] || kindRank(a.kind)-kindRank(b.kind));
  } finally { SETMEMO = null; }
}

/* worst-case evaluations along the two real packet paths */
export function worstCase(){
  const live = ch => ch.rules.filter(r=>r.on).length;
  /* a parked table costs nothing: its chains are not attached to the hook */
  const inHook = h => MODEL.chains.filter(c=>c.hook===h && !isDormant(MODEL, c.table));
  const cost = h => inHook(h).reduce((a,c)=>a+live(c), 0);
  const jumpCost = h => inHook(h).reduce((max,c)=> Math.max(max,
    ...c.rules.filter(r=>r.on && (r.verdict==="jump"||r.verdict==="goto"))
      .map(r=>{ const tgt = jumpTarget(c, r.to); return tgt?live(tgt):0; }), 0), 0);

  const pre = cost("prerouting");
  return Math.max(
    pre + cost("input")   + jumpCost("input"),                         /* to the host */
    pre + cost("forward") + jumpCost("forward") + cost("postrouting"), /* through it  */
    cost("output") + jumpCost("output") + cost("postrouting"));        /* from it     */
}
