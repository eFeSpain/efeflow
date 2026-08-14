/* Reading and editing an nftables match expression as text.
 *
 * The properties panel models nine things. An nftables rule says a great deal
 * more than nine things, and the panel used to rebuild the whole expression
 * from the nine it knew every time any of them changed. Typing a single
 * character into the comment box on
 *
 *   ip6 saddr @admins tcp dport 22 tcp flags syn / syn,ack \
 *     log prefix "ssh " limit rate 3/minute burst 3 packets accept
 *
 * left behind
 *
 *   ip saddr @admins tcp dport 22 limit rate 3/minute accept
 *
 * — an IPv6 rule quietly became an IPv4 one, and the flag match, the log
 * prefix and the burst were gone. No warning, no diff, and undo only helps
 * someone who noticed.
 *
 * So nothing here rebuilds. Each field finds its own fragment and rewrites
 * exactly that, which means every statement the panel has never heard of is
 * carried through untouched — and stays true for whatever nftables adds next. */

/* a matchable value: a set reference, a braced list, a quoted name, a token */
const VAL = String.raw`(?:\{[^}]*\}|"[^"]*"|\S+)`;
const NEG = String.raw`(!=\s*)?`;

const tidy = s => s.replace(/\s{2,}/g, " ").trim();

/* Replace a fragment, remove it, or add it if it was never there. `text` is
   the whole replacement fragment, or "" to take the match out. */
function splice(expr, re, text){
  const m = expr.match(re);
  if(!m) return text ? tidy(expr ? expr + " " + text : text) : expr;
  return tidy(expr.slice(0, m.index) + text + expr.slice(m.index + m[0].length));
}

const RE = {
  saddr:   new RegExp(String.raw`\b(ip6?)\s+saddr\s+${NEG}(${VAL})`),
  daddr:   new RegExp(String.raw`\b(ip6?)\s+daddr\s+${NEG}(${VAL})`),
  iif:     new RegExp(String.raw`\b(iifname|iif)\s+${NEG}(${VAL})`),
  oif:     new RegExp(String.raw`\b(oifname|oif)\s+${NEG}(${VAL})`),
  sport:   new RegExp(String.raw`\b(tcp|udp|sctp|dccp|udplite)\s+sport\s+${NEG}(${VAL})`),
  dport:   new RegExp(String.raw`\b(tcp|udp|sctp|dccp|udplite)\s+dport\s+${NEG}(${VAL})`),
  state:   /\bct state\s+(!=\s*)?([\w,]+)/,
  l4proto: new RegExp(String.raw`\bmeta l4proto\s+${NEG}(${VAL})`),
  netproto: new RegExp(String.raw`\b(ip6?)\s+(protocol|nexthdr)\s+${NEG}(${VAL})`),
  portpfx: /\b(tcp|udp|sctp|dccp|udplite)(\s+[sd]port\b)/g,
  limit:   /\blimit rate\s+(over\s+)?(\d+\/\w+)(?:\s+burst\s+(\d+)\s+(\w+))?/,
  /* `log` owns everything that follows it, and taking the keyword out while
     leaving `prefix "…"` behind produces a rule nft will not parse */
  log:     /\blog\b(?:\s+(?:prefix\s+"(?:[^"\\]|\\.)*"|level\s+\S+|group\s+\d+|snaplen\s+\d+|queue-threshold\s+\d+|flags\s+\S+))*/,
  /* Each of these matches one recognised shape and nothing else: an unfamiliar
     variant simply is not matched, so it is carried through rather than
     rewritten into something narrower. `icmp[v6] type X`, `tcp flags X[/Y]`,
     and `meta mark` used as a match — never `meta mark set`, never `meta mark`
     read as a value on the right of a `set`, never `meta mark map …`. */
  icmptype: /\b(icmp|icmpv6|icmpx)\s+type\s+(!=\s*)?(\{[^}]*\}|[\w-]+)/,
  tcpflags: /\btcp flags\s+(!=\s*)?(\{[^}]*\}|[a-z,]+(?:\s*\/\s*[a-z,]+)?)/i,
  metamark: /(?<!\bset )\bmeta mark\s+(?!set\b|map\b|vmap\b|and\b|or\b|xor\b)(!=\s*)?(\{[^}]*\}|0x[0-9a-fA-F]+(?:-0x[0-9a-fA-F]+)?|\d+(?:-\d+)?)/,
};

const unquote = s => String(s ?? "").replace(/^"([^"]*)"$/, "$1");

/* An address knows its own family; a set reference or a variable does not, and
   the rule it is written into keeps whatever it already said. */
function familyOf(v){
  const first = String(v).replace(/^[{\s]+/, "").split(/[,\s}]/)[0] || "";
  if(/^[@$]/.test(first)) return null;
  if(first.includes(":")) return "ip6";
  if(/^\d{1,3}(\.\d{1,3}){3}/.test(first)) return "ip";
  return null;
}
/* nft prints interface names quoted; a set reference or a list must not be */
const quoteIface = v => /^[@{]/.test(v) || /^".*"$/.test(v) ? v : `"${v}"`;

/* What the panel shows. Values come back unquoted, because that is how they
   are typed back in. */
export function readExpr(expr){
  const e = String(expr || "");
  const g = (re, i) => { const m = e.match(re); return m ? unquote(m[i]) : ""; };
  return {
    proto : readProto(e),
    saddr : g(RE.saddr, 3),
    daddr : g(RE.daddr, 3),
    sport : g(RE.sport, 3),
    dport : g(RE.dport, 3),
    state : g(RE.state, 2),
    iif   : g(RE.iif, 3),
    oif   : g(RE.oif, 3),
    icmptype: g(RE.icmptype, 3),
    tcpflags: g(RE.tcpflags, 2),
    metamark: g(RE.metamark, 2),
    limit : g(RE.limit, 2),
    burst : g(RE.limit, 3),
    over  : /\blimit rate\s+over\b/.test(e),
    log   : RE.log.test(e),
  };
}

/* The transport, wherever the rule happens to have said it. */
export function readProto(expr){
  const e = String(expr || "");
  let m;
  if((m = e.match(RE.l4proto)))  return unquote(m[2]);
  if((m = e.match(RE.netproto))) return unquote(m[4]);
  if((m = e.match(/\b(tcp|udp|sctp|dccp|udplite)\s+[sd]port\b/))) return m[1];
  if((m = e.match(/\b(tcp|udp|icmp|icmpv6|sctp|dccp|udplite|esp|ah)\b/))) return m[1];
  return "";
}

const setAddr = (expr, dir, v) => {
  if(v === null) return expr;
  const m = expr.match(RE[dir]);
  if(!v) return splice(expr, RE[dir], "");
  /* Writing an IPv6 address into a rule that said `ip saddr` used to leave it
     saying `ip`, which matches nothing and says nothing about why. */
  const fam = familyOf(v) || m?.[1] || "ip";
  return splice(expr, RE[dir], `${fam} ${dir} ${m?.[2] || ""}${v}`);
};

const setIface = (expr, dir, v) => {
  if(v === null) return expr;
  const key = dir === "iif" ? "iif" : "oif";
  const m = expr.match(RE[key]);
  if(!v) return splice(expr, RE[key], "");
  /* `iif` resolves to a device index and `iifname` compares the name. They are
     not the same rule, so an imported `iif lo` stays `iif lo`. */
  const kw = m ? m[1] : key + "name";
  const val = kw.endsWith("name") ? quoteIface(v) : v;
  return splice(expr, RE[key], `${kw} ${m?.[2] || ""}${val}`);
};

const setPort = (expr, dir, v, proto) => {
  if(v === null) return expr;
  const m = expr.match(RE[dir]);
  if(!v) return splice(expr, RE[dir], "");
  /* a port belongs to a transport; nftables has no protocol-less dport */
  const pfx = m ? m[1] : (["tcp","udp","sctp","dccp","udplite"].includes(proto) ? proto : "tcp");
  return splice(expr, RE[dir], `${pfx} ${dir} ${m?.[2] || ""}${v}`);
};

export function setProto(expr, v){
  if(v === null) return expr;
  let e = expr;
  if(!v){
    /* Cleared: drop the standalone protocol match. Never the transport in
       front of a port — that one is load-bearing. */
    e = splice(e, RE.l4proto, "");
    return splice(e, RE.netproto, "");
  }
  const hadPorts = new RegExp(RE.portpfx.source).test(e);
  if(hadPorts) e = e.replace(RE.portpfx, `${v}$2`);
  if(RE.l4proto.test(e))
    return e.replace(RE.l4proto, (_, neg, val) => `meta l4proto ${neg || ""}${v}`);
  if(RE.netproto.test(e))
    return e.replace(RE.netproto, (_, fam, kw, neg) => `${fam} ${kw} ${neg || ""}${v}`);
  if(hadPorts) return e;                       /* the port prefix already says it */
  return tidy(`meta l4proto ${v} ${e}`);
}

export function setState(expr, v){
  if(v === null) return expr;
  if(!v) return splice(expr, RE.state, "");
  const m = expr.match(RE.state);
  return splice(expr, RE.state, `ct state ${m?.[1] || ""}${v}`);
}

/* An ICMP type match belongs to a family; a rule that already named one keeps
   it, and one that did not takes the family of its protocol — `icmpv6 type` on
   an ip6 rule, `icmp type` otherwise. */
export function setIcmpType(expr, v){
  if(v === null) return expr;
  if(!v) return splice(expr, RE.icmptype, "");
  const m = expr.match(RE.icmptype);
  const fam = m?.[1] || (readProto(expr) === "icmpv6" ? "icmpv6" : "icmp");
  return splice(expr, RE.icmptype, `${fam} type ${m?.[2] || ""}${v}`);
}

export function setTcpFlags(expr, v){
  if(v === null) return expr;
  if(!v) return splice(expr, RE.tcpflags, "");
  const m = expr.match(RE.tcpflags);
  return splice(expr, RE.tcpflags, `tcp flags ${m?.[1] || ""}${v}`);
}

export function setMetaMark(expr, v){
  if(v === null) return expr;
  if(!v) return splice(expr, RE.metamark, "");
  const m = expr.match(RE.metamark);
  return splice(expr, RE.metamark, `meta mark ${m?.[1] || ""}${v}`);
}

export function setLimit(expr, { rate, burst, over } = {}){
  const m = expr.match(RE.limit);
  const cur = { rate: m?.[2] || "", burst: m?.[3] || "", unit: m?.[4] || "packets", over: !!m?.[1] };
  const next = {
    rate:  rate  === undefined ? cur.rate  : rate,
    burst: burst === undefined ? cur.burst : burst,
    over:  over  === undefined ? cur.over  : over,
  };
  if(!next.rate) return splice(expr, RE.limit, "");
  const b = next.burst ? ` burst ${next.burst} ${cur.unit}` : "";
  return splice(expr, RE.limit, `limit rate ${next.over ? "over " : ""}${next.rate}${b}`);
}

/* Turning logging off takes the prefix, level and flags with it; leaving them
   behind is a rule that does not load. Turning it on leaves any existing log
   statement exactly as it is. */
export function setLog(expr, on){
  if(on === null) return expr;
  if(!on) return splice(expr, RE.log, "");
  return RE.log.test(expr) ? expr : tidy(expr ? expr + " log" : "log");
}

/* The log levels nftables knows, most severe first; "" is none set. */
export const LOG_LEVELS = ["emerg", "alert", "crit", "err", "warn", "notice", "info", "debug"];

/* What the log statement says, if the rule has one. `group` marks the nflog
   form, whose level nftables will not let you set — the panel reads it so it
   can stop offering one. */
export function readLog(expr){
  const m = String(expr || "").match(RE.log);
  if(!m) return { on: false, prefix: "", level: "", group: "" };
  const run = m[0];
  const p = run.match(/\bprefix\s+"((?:[^"\\]|\\.)*)"/);
  const l = run.match(/\blevel\s+(\S+)/);
  const grp = run.match(/\bgroup\s+(\d+)/);
  return { on: true, prefix: p ? p[1].replace(/\\"/g, '"') : "",
           level: l ? l[1] : "", group: grp ? grp[1] : "" };
}

/* Set the prefix or level of a rule's log statement and touch nothing else in
   it — the group, snaplen and flags another author chose are kept. A rule with
   no log gains a bare `log` if something is being set, and stays as it was if
   the field is being cleared. `prefix`/`level` absent (undefined) means the
   panel is not offering that one. */
export function editLogParts(expr, { prefix, level } = {}){
  let e = String(expr || "");
  const adding = (prefix !== undefined && prefix) || (level !== undefined && level);
  if(!RE.log.test(e)){
    if(!adding) return e;
    e = tidy(e ? e + " log" : "log");
  }
  return e.replace(RE.log, run => {
    let s = run;
    if(prefix !== undefined)
      s = setLogOpt(s, "prefix", prefix ? `"${String(prefix).replace(/"/g, '\\"')}"` : "");
    if(level !== undefined){
      /* level (syslog) and group (nflog) are mutually exclusive in nftables; a
         rule already logging to a group is left as it is, not made invalid.
         Clearing the level is always fine. */
      if(!(level && /\bgroup\s+\d+/.test(s))) s = setLogOpt(s, "level", level || "");
    }
    return s;
  });
}

/* Replace `key value` inside a log run, remove it when the value is "", or add
   it at the end of the run when it was not there. Adding at the end keeps the
   prefix ahead of the level, which is the order nft prints. */
function setLogOpt(run, key, value){
  const re = new RegExp(String.raw`\s*\b${key}\s+(?:"(?:[^"\\]|\\.)*"|\S+)`);
  if(!value) return tidy(run.replace(re, ""));
  const piece = `${key} ${value}`;
  return re.test(run) ? tidy(run.replace(re, " " + piece)) : tidy(run + " " + piece);
}

/* Apply whatever the panel changed and nothing else. A key that is absent, or
   whose value is null, is a field the panel is not offering — leave it. */
export function editExpr(expr, patch = {}){
  const v = k => (patch[k] === undefined ? null : patch[k]);
  let e = String(expr || "");
  e = setProto(e, v("proto"));
  e = setState(e, v("state"));
  e = setIface(e, "iif", v("iif"));
  e = setIface(e, "oif", v("oif"));
  e = setIcmpType(e, v("icmptype"));
  e = setTcpFlags(e, v("tcpflags"));
  e = setMetaMark(e, v("metamark"));
  e = setAddr(e, "saddr", v("saddr"));
  e = setAddr(e, "daddr", v("daddr"));
  const proto = patch.proto || readProto(e);
  e = setPort(e, "sport", v("sport"), proto);
  e = setPort(e, "dport", v("dport"), proto);
  if(patch.limit !== undefined || patch.burst !== undefined || patch.over !== undefined)
    e = setLimit(e, { rate: patch.limit, burst: patch.burst, over: patch.over });
  if(patch.log !== undefined) e = setLog(e, patch.log);
  return e;
}
