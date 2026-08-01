/* Findings are derived from the model, never authored. The core relation
   is subsumption: A subsumes B when every packet matching B matches A. */
import { MODEL, R, ruleLine, jumpTarget } from './model.js';
import { inSet, inCidr } from './simulate.js';
import { t } from '../i18n.js';
const CRIT = [
  ["proto", /\b(tcp|udp|sctp)\b/],
  ["l4",    /meta l4proto (\{[^}]*\}|\S+)/],
  ["state", /ct state ([\w,]+)/],
  ["ctst",  /ct status (\w+)/],
  ["iif",   /(?:iif|iifname) "?([\w.-]+)"?/],
  ["oif",   /(?:oif|oifname) "?([\w.-]+)"?/],
  ["saddr", /ip6? saddr (?!!=)(\S+)/],
  ["daddr", /ip6? daddr (?!!=)(\S+)/],
  ["sport", /sport (\{[^}]*\}|\S+)/],
  ["dport", /dport (\{[^}]*\}|\S+)/],
];
export function criteria(expr){
  const c = {};
  CRIT.forEach(([k,re])=>{ const m = expr.match(re); if(m) c[k] = m[1]; });
  c._limit  = /limit rate/.test(expr);      /* rate-limited ⇒ non-deterministic */
  c._log    = /\blog\b/.test(expr);
  c._negate = /!=/.test(expr);
  return c;
}
const listOf = v => v.startsWith("{") ? v.slice(1,-1).split(",").map(s=>s.trim()) : [v];

/* does criterion value A cover value B? */
function covers(a,b){
  if(a===b) return true;
  const A = listOf(a), B = listOf(b);
  if(B.every(x=>A.includes(x))) return true;
  if(a.startsWith("@")) return B.every(x=>inSet(x, a.slice(1)));
  if(a.includes("/") && B.every(x=>/^[\d.]+(\/\d+)?$/.test(x)))
    return B.every(x=>inCidr(x.split("/")[0], a));
  return false;
}
/* every packet matching b also matches a */
export function subsumes(a,b){
  if(a._limit || a._negate || b._negate) return false;   /* can't reason safely */
  return CRIT.every(([k])=>{
    if(a[k]===undefined) return true;      /* a is wildcard here */
    if(b[k]===undefined) return false;     /* b is broader than a */
    return covers(a[k], b[k]);
  });
}
/* some packet matches both */
export function overlaps(a,b){
  if(a._negate || b._negate) return false;
  return CRIT.every(([k])=>{
    if(a[k]===undefined || b[k]===undefined) return true;
    return covers(a[k],b[k]) || covers(b[k],a[k]);
  });
}
const TERMINAL = v => v==="accept" || v==="drop" || v==="reject";

const F = (sev,kind,o) => Object.assign({sev,kind},o);

export function analyse(){
  const out = [], live = ch => ch.rules.map((r,i)=>({r,i})).filter(x=>x.r.on);

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
               run:()=>{ ch.rules.splice(b.i,1); }},
        }));
        break;
      }
    });

    /* ── overlapping NAT with divergent targets ── */
    const nats = rs.filter(x=>x.r.verdict==="dnat");
    nats.forEach((a,k)=> nats.slice(k+1).forEach(b=>{
      if(a.r.to===b.r.to || !overlaps(a.c,b.c)) return;
      out.push(F("error","conflict",{
        chain:ch, i:b.i, ref:a.i,
        title:[`Conflicting DNAT targets for the same destination port`,
               `Destinos DNAT en conflicto para el mismo puerto destino`],
        where:`${ch.table} / ${ch.id}`,
        detail:[`Rules ${a.i+1} and ${b.i+1} both match traffic to <code>${a.c.dport||"?"}</code> but translate it to different hosts. nftables terminates the chain on the first NAT verdict, so rule ${a.i+1} silently wins for every packet matching both and rule ${b.i+1} never fires.`,
                `Las reglas ${a.i+1} y ${b.i+1} coinciden con tráfico a <code>${a.c.dport||"?"}</code> pero lo traducen a hosts distintos. nftables termina la cadena en el primer veredicto NAT, así que la regla ${a.i+1} gana en silencio para todo paquete que case con ambas y la ${b.i+1} nunca se dispara.`],
        code:[[a.i+1, ruleLine(a.r), "neg"],[b.i+1, ruleLine(b.r), "dead"]],
        fix:{label:["Narrow rule "+(a.i+1),"Restringir la regla "+(a.i+1)],
             run:()=>{ if(!/ip saddr/.test(a.r.expr)) a.r.expr += " ip saddr != @admin_nets"; }},
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
        chain:ch, i:sibs[0].i,
        title:[`${sibs.length} rules differ only by destination port`,
               `${sibs.length} reglas solo difieren en el puerto destino`],
        where:`${ch.table} / ${ch.id} · ${t("rules","reglas")} ${sibs.map(s=>s.i+1).join(", ")}`,
        detail:match
          ? [`These ports are exactly the contents of the existing set <code>@${match.n}</code>. One set lookup is a single hash probe instead of ${sibs.length} linear comparisons, and leaves one place to edit.`,
             `Estos puertos son exactamente el contenido del set existente <code>@${match.n}</code>. Una consulta a set es un solo sondeo hash en vez de ${sibs.length} comparaciones lineales, y deja un único sitio que editar.`]
          : [`Collapsing them into an anonymous set costs one hash probe instead of ${sibs.length} comparisons.`,
             `Colapsarlas en un set anónimo cuesta un sondeo hash en vez de ${sibs.length} comparaciones.`],
        code:sibs.map(s=>[s.i+1, ruleLine(s.r), "neg"])
              .concat([["→", (a.c.proto||"tcp")+" dport @"+(match?match.n:"ports")+
                             (a.c.saddr?" ip saddr "+a.c.saddr:"")+" "+a.r.verdict, "pos"]]),
        fix:{label:match?["Merge into @"+match.n,"Fusionar en @"+match.n]:["Create set","Crear set"],
             run:()=>{
               const name = match ? match.n : "ports";
               if(!match) MODEL.sets.push({n:name, table:ch.table, t:"inet_service", f:"", el:ports});
               const keep = sibs[0];
               keep.r.expr = keep.r.expr.replace(/dport \S+/, "dport @"+name);
               keep.r.pkts = sibs.reduce((s,x)=>s+x.r.pkts,0);
               keep.r.bytes = sibs.reduce((s,x)=>s+x.r.bytes,0);
               sibs.slice(1).map(s=>s.r).forEach(r=>{
                 const j = ch.rules.indexOf(r); if(j>=0) ch.rules.splice(j,1);
               });
             }},
      }));
    });

    /* ── hardening: filter chain that trusts conntrack but never drops invalid ── */
    if(ch.type==="filter" && ch.hook && ch.policy==="drop"
       && rs.some(x=>/ct state established/.test(x.r.expr))
       && !rs.some(x=>/ct state[\w,]*invalid|ct state invalid/.test(x.r.expr))){
      out.push(F("warn","hardening",{
        chain:ch, i:0,
        title:[`${ch.id} chain has no invalid-state drop`,
               `La cadena ${ch.id} no descarta el estado invalid`],
        where:`${ch.table} / ${ch.id} · ${t("chain-level","nivel de cadena")}`,
        detail:[`This chain fast-paths <code>established</code> traffic but lets <code>invalid</code> packets traverse all ${rs.length} rules before falling through to the policy. Dropping them first is both safer and cheaper.`,
                `Esta cadena da vía rápida al tráfico <code>established</code> pero deja que los paquetes <code>invalid</code> recorran las ${rs.length} reglas antes de caer en la política. Descartarlos primero es más seguro y más barato.`],
        code:[["+", "ct state invalid counter drop", "pos"]],
        fix:{label:["Insert at position 1","Insertar en la posición 1"],
             run:()=>{ ch.rules.unshift(R("ct state invalid","drop",{pkts:0,bytes:0})); }},
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
             run:()=>{ x.r.expr = x.r.expr.replace(/\blog\b/, "limit rate 5/second burst 10 packets log"); }},
      }));
    });
  });

  /* ── sets loaded into the kernel that no rule consumes ── */
  const allExpr = MODEL.chains.flatMap(c=>c.rules.filter(r=>r.on).map(r=>r.expr)).join(" ");
  MODEL.sets.forEach(s=>{
    if(allExpr.includes("@"+s.n)) return;
    out.push(F("hint","unused",{
      set:s.n,
      title:[`Set @${s.n} is declared but never referenced`,
             `El set @${s.n} se declara pero nunca se referencia`],
      where:`inet fw · set`,
      detail:[`Its ${s.el.length} element${s.el.length===1?"":"s"} are loaded into the kernel on every reload with no rule consuming them.`,
              `Sus ${s.el.length} elemento${s.el.length===1?"":"s"} se cargan en el kernel en cada recarga sin que ninguna regla los consuma.`],
      code:[["", `set ${s.n} { type ${s.t}${s.f?" ; flags "+s.f:""} }`, "neg"]],
      fix:{label:["Remove set","Eliminar el set"],
           run:()=>{ MODEL.sets.splice(MODEL.sets.indexOf(s),1); }},
      go:"sets",
    }));
  });

  const rank = {error:0, warn:1, hint:2};
  return out.sort((a,b)=> rank[a.sev]-rank[b.sev]);
}

/* worst-case evaluations along the two real packet paths */
export function worstCase(){
  const live = ch => ch.rules.filter(r=>r.on).length;
  const inHook = h => MODEL.chains.filter(c=>c.hook===h);
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
