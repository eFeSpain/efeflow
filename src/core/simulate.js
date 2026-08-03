/* Evaluates a synthetic packet against the same model the code is
   emitted from, so a verdict here is the verdict the export produces. */
import { MODEL, UID, chainOf, jumpTarget, expand } from './model.js';
import { inCidr, family, looksLikeAddr } from './addr.js';
import { isDormant } from './tables.js';
export { inCidr };

const setOf = n => (MODEL.sets.find(s=>s.n===n)||{el:[]}).el;
export function inSet(v,name){
  const el = setOf(name);
  /* an element is a port, an address or a prefix, or a name — and only the
     middle kind is a containment question */
  return el.some(e => looksLikeAddr(e) ? inCidr(String(v), e) : e === String(v));
}
export function matchVal(v, tok){
  if(!v && v!==0) return false;
  if(tok.startsWith("@")) return inSet(v, tok.slice(1));
  if(tok.startsWith("{"))
    return tok.slice(1,-1).split(",").map(s=>s.trim())
      .some(e => looksLikeAddr(e) ? inCidr(String(v), e) : e === String(v));
  if(tok.includes("/") || looksLikeAddr(tok)) return inCidr(String(v),tok);
  return String(v)===tok;
}

/* An interface constraint has four spellings and they all mean the same thing
   to a packet: `iif lo`, `iif "lo"`, `iifname "eth0"`, `iifname eth0`, each
   optionally negated or given a set. nft writes the quoted form when it lists a
   ruleset, so anything imported from a live host used the quoted one — and only
   the bare `iif lo` and the quoted `iifname` were recognised. The other two
   silently matched every packet, which is the worst way for a filter to fail.
   (iif resolves to a device index at load time and iifname compares the name;
   that changes what survives a device being recreated, not what matches.) */
/* The lookbehind keeps this off a concatenation: `fib saddr . iif oif missing`
   names iif as a key of the lookup, not as a constraint on the interface, and
   reading it as one compared the packet's iif against the string "oif". */
const IFACE_RE = dir => new RegExp(`(?<!\\.\\s)\\b(?:meta\\s+)?${dir}(?:name)?\\s+(!=\\s*)?("[^"]*"|\\{[^}]*\\}|@?\\S+)`);
const unquote = s => s.replace(/^"([^"]*)"$/, "$1");
function matchIface(v, tok){
  if(tok.startsWith("@")) return inSet(v, tok.slice(1));
  if(tok.startsWith("{"))
    return tok.slice(1,-1).split(",").map(s=>unquote(s.trim())).filter(Boolean).includes(String(v));
  return String(v ?? "") === unquote(tok);
}

const ADDR_RE = dir => new RegExp(`\\b(ip6?)\\s+${dir}\\s+(!=\\s*)?(\\{[^}]*\\}|\\S+)`);
/* A rule that names one family cannot match a packet of the other, whatever
   the address says — nftables resolves that at load time from the family
   keyword, not from the value. */
function matchAddr(m, value){
  if((m[1] === "ip6" ? 6 : 4) !== family(value)) return false;
  return negated(m[2], matchVal(value, m[3]));
}

/* Everything the evaluator reads, each fragment beside the question it
   answers. The two live together on purpose: unmodelled() is this same list
   subtracted from the expression, so what the evaluator reads and what it
   admits to reading cannot drift apart. */
const negated = (neg, hit) => (neg ? !hit : hit);
const inList = (tok, v) => tok.startsWith("{")
  ? tok.slice(1,-1).split(",").map(s=>s.trim()).includes(String(v))
  : String(v) === tok;

const MATCHERS = [
  /* an untracked packet has no conntrack entry: `ct state` can only match it
     through the untracked keyword, and `ct status` never matches */
  { re: /\bct\s+state\s+(!=\s*)?([\w,]+)/,
    ok: (m,p) => { const want = m[2].split(",");
                   return negated(m[1], p.tracked ? want.includes(p.state)
                                                  : want.includes("untracked")); } },
  { re: /\bct\s+status\s+(!=\s*)?\w+/, ok: (m,p) => negated(m[1], !!(p.tracked && p.dnat)) },
  /* tcp flags syn / tcp flags & (syn|ack) == syn */
  { re: /\btcp\s+flags\s+(!=\s*)?&?\s*\(?([\w|,]+)\)?(?:\s*==\s*\(?([\w|,]+)\)?)?/,
    ok: (m,p) => { const has = f => (p.flags||[]).includes(f);
                   const want = (m[3]||m[2]).split(/[|,]/).map(s=>s.trim()).filter(Boolean);
                   return negated(m[1], m[3]
                     ? want.every(has) && (p.flags||[]).every(f=>!m[2].includes(f) || want.includes(f))
                     : want.every(has)); } },
  { re: IFACE_RE("iif"), ok: (m,p) => negated(m[1], matchIface(p.iif, m[2])) },
  { re: IFACE_RE("oif"), ok: (m,p) => negated(m[1], matchIface(p.oif, m[2])) },
  /* `ip saddr` and `ip6 saddr` are different matches, and in an inet table
     that is the whole reason both exist. */
  { re: ADDR_RE("saddr"), ok: (m,p) => matchAddr(m, p.saddr) },
  { re: ADDR_RE("daddr"), ok: (m,p) => matchAddr(m, p.daddr) },
  /* both the braced list and the single value: only the first was read, so
     `meta l4proto sctp accept` matched a tcp packet */
  { re: /\bmeta\s+l4proto\s+(!=\s*)?(\{[^}]*\}|\S+)/,
    ok: (m,p) => negated(m[1], inList(m[2], p.proto)) },
  /* `ip protocol icmp` is how a v4 rule says it, and `ip6 nexthdr` the v6 one.
     Neither was read, so both matched every packet. */
  { re: /\b(ip|ip6)\s+(?:protocol|nexthdr)\s+(!=\s*)?(\{[^}]*\}|\S+)/,
    ok: (m,p) => (m[1] === "ip6" ? 6 : 4) === family(p.saddr ?? p.daddr)
                 && negated(m[2], inList(m[3], p.proto)) },
  { re: /\b(tcp|udp|sctp|dccp|udplite)\s+(sport|dport)\s+(!=\s*)?(\{[^}]*\}|\S+)/,
    ok: (m,p) => m[1] === p.proto
                 && negated(m[3], matchVal(m[2] === "dport" ? p.dport : p.sport, m[4])) },
  { re: /\b(tcp|udp|icmp|icmpv6|sctp|dccp)\b/, ok: (m,p) => m[1] === p.proto },
  { re: /\b(sport|dport)\s+(!=\s*)?(\{[^}]*\}|\S+)/,
    ok: (m,p) => negated(m[2], matchVal(m[1] === "dport" ? p.dport : p.sport, m[3])) },
];

/* Statements recognised by shape and not by meaning.
 *
 * Naming one is not a claim to understand it. It is to stop the matchers above
 * reading a fragment out of the middle of it: `fib saddr . iif oif missing` —
 * the standard anti-spoofing rule — names iif and oif as keys of a lookup, and
 * the interface matcher was comparing the packet's oif against the string
 * "missing". The rule was therefore a certain miss for a reason that was not a
 * reason, which is worse than the silence this whole change is about. */
const OPAQUE = [
  /\bfib\s+\w+(?:\s*\.\s*\w+)*\s+(?:oif(?:name)?|type|check)(?:\s+(?:!=\s*)?\S+)?/g,
  /* `icmp type echo-request` is a match on the message, not on the protocol.
     Left unmasked, the bare-protocol matcher took the `icmp` off the front and
     the leftover read as a headless `type echo-request`. */
  /\b(?:icmp|icmpv6|igmp)\s+(?:type|code)\s+(!=\s*)?(?:\{[^}]*\}|\S+)/g,
];

/* the expression with the opaque statements struck out, so nothing reads into
   one; the spans, so the caller can put them back */
/* The expression with the statements nothing reads into struck out. Shared
   with the analyser, which was making the same mistake this was written for:
   reading the `oif` out of the middle of a fib lookup. */
export const readable = e => mask(expand(e)).masked;

function mask(e){
  const chars = [...e];
  const spans = [];
  for(const re of OPAQUE)
    for(const m of e.matchAll(re)){
      spans.push([m.index, m.index + m[0].length]);
      for(let i = m.index; i < m.index + m[0].length; i++) chars[i] = " ";
    }
  return { masked: chars.join(""), spans };
}

/* Every occurrence, not the first. A rule saying `udp sport 67 udp dport 68`
   carries two port matches, and reading one of them meant the other was never
   checked: the rule matched a packet on any destination port at all. */
const allOf = (re, s) =>
  [...s.matchAll(re.global ? re : new RegExp(re.source, re.flags + "g"))];

export function matches(r,p){
  /* on the expansion, never on the text: `iifname $WAN` is a constraint on
     wan0, and comparing a packet against the dollar sign was a certain miss */
  const e = expand(r.expr);
  if(!e) return true;
  const { masked } = mask(e);
  for(const { re, ok } of MATCHERS)
    for(const m of allOf(re, masked))
      if(!ok(m, p)) return false;
  return true;
}

/* Statements that say what to do rather than what to match: whether the rule
   applies does not turn on them. */
const NOT_A_MATCH = [
  /\blog\b(?:\s+(?:prefix\s+"(?:[^"\\]|\\.)*"|level\s+\S+|group\s+\d+|snaplen\s+\d+|queue-threshold\s+\d+|flags\s+\S+))*/g,
  /\bcounter(?:\s+packets\s+\d+\s+bytes\s+\d+)?/g,
  /\bcomment\s+"(?:[^"\\]|\\.)*"/g,
];

/**
 * The parts of an expression nothing above looked at.
 *
 * This used to be nothing at all — an unrecognised match was skipped, so the
 * rule matched every packet and `meta mark 0x1 drop` dropped the lot. The
 * language is larger than any model of it and the rule editor can now write
 * all of it, so the answer is not to model more: it is to stop being silent
 * about the difference between a verdict that was evaluated and one that was
 * guessed at.
 */
/* Struck out with a marker rather than deleted, so a leftover keeps the
   spaces inside it: `meta mark 0x1` is one thing this cannot read, not three. */
export function unmodelled(expr){
  /* the same expansion the matchers saw, so the spans line up with what was
     actually read rather than with what was written */
  const e = expand(expr);
  if(!e.trim()) return [];

  const { masked } = mask(e);
  const read = [];
  for(const re of NOT_A_MATCH)
    for(const m of e.matchAll(re)) read.push([m.index, m.index + m[0].length]);
  /* against the masked expression, so a matcher cannot claim part of an opaque
     statement and leave the rest of it looking like the whole of it */
  for(const { re } of MATCHERS)
    for(const m of allOf(re, masked)) read.push([m.index, m.index + m[0].length]);
  read.sort((a, b) => a[0] - b[0]);

  /* whatever lies between the fragments something did look at, kept whole:
     `meta mark 0x1` is one thing this cannot read, not three words */
  const out = [];
  let at = 0;
  for(const [a, b] of read){
    if(a > at) out.push(e.slice(at, a));
    at = Math.max(at, b);
  }
  out.push(e.slice(at));
  return out.map(s => s.trim()).filter(Boolean);
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
  /* An inet ruleset filters both families and they take different rules. A
     simulator that could only describe an IPv4 packet could only ever answer
     half the question. Documentation space, RFC 3849. */
  v6:      {...BASE, iif:"wan0", saddr:"2001:db8:1::47", daddr:"2001:db8::10",
            sport:49812, dport:443, proto:"tcp", state:"new"},
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

/* Where a NAT verdict sends the packet. The target is an address, a port, or
   both — `10.0.0.5`, `10.0.0.5:8080`, `:8080`, `[2001:db8::1]:80` — and an
   unbracketed IPv6 address is all colons and no port at all, which is why the
   port is only read when the address is bracketed or holds no colon of its
   own. Splitting on ":" unconditionally set the port to NaN for every
   `dnat to <address>`, and a packet with no port matches nothing downstream. */
export function natTarget(spec){
  const s = String(spec ?? "").trim();
  const m = s.match(/^(\[[^\]]*\]|[^:]*)(?::(\d+)(?:-\d+)?)?$/);
  if(!m) return {host:s, port:null};
  return {host:m[1] || "", port:m[2] ? +m[2] : null};
}

export function evaluate(p){
  const steps = [];
  let accepted = null;
  /* the matches that were assumed rather than evaluated on the way to a verdict */
  const guessed = [];

  /* How a chain ended:
       {stop:"packet", …}         the packet is finished, and here is why
       {stop:"chain", settled:b}  the chain is finished; `settled` says whether
                                  it reached a verdict — which is what decides
                                  both whether a jump carries on afterwards and
                                  whether a base chain's policy still applies. */
  const walk = (chainId, depth=0) => {
    const ch = chainOf(chainId);
    const hop = {chain:ch, evs:[], depth};
    steps.push(hop);
    for(let i=0;i<ch.rules.length;i++){
      const r = ch.rules[i];
      if(!r.on){ hop.evs.push({r,i,st:"miss",note:"disabled"}); continue; }
      if(!matches(r,p)){ hop.evs.push({r,i,st:"miss"}); continue; }
      /* A rule that missed for a reason the evaluator understood is a certain
         miss whatever else it carries. A rule taken as matching, when part of
         why it matched was never read, is where the trace stops being a
         statement and starts being a guess — and it was making no distinction
         between the two. */
      const un = unmodelled(r.expr);
      hop.evs.push({r, i, st:"match", ...(un.length ? {unsure:un} : {})});
      guessed.push(...un);

      /* NAT terminates the chain, and the packet that walks on to the next
         hook is the translated one. */
      if(r.verdict==="dnat" || r.verdict==="redirect"){
        const {host, port} = natTarget(r.to);
        p.dnat = true;
        if(host) p.daddr = host;
        if(port !== null) p.dport = port;
        hop.nat = r.to || r.verdict;
        return {stop:"chain", settled:true};
      }
      if(r.verdict==="snat"){ hop.nat = r.to; return {stop:"chain", settled:true}; }

      /* jump remembers where it came from and goto does not — which is the
         whole reason nftables has both. A goto whose target settles nothing
         leaves the base chain's policy to decide, never the rules below it. */
      if(r.verdict==="jump" || r.verdict==="goto"){
        const tgt = jumpTarget(ch, r.to);
        if(!tgt) continue;              /* a chain that is not there decides nothing */
        const v = walk(UID(tgt), depth+1);
        if(v.stop==="packet") return v;
        if(r.verdict==="goto" || v.settled) return {stop:"chain", settled:v.settled};
        continue;
      }

      /* `return` leaves this chain having decided nothing: back to the caller,
         or to the policy if this chain is the base one. */
      if(r.verdict==="return") return {stop:"chain", settled:false};

      /* nftables terminality: `accept` ends this chain but the packet carries
         on to the next hook. Only drop/reject end the packet outright. */
      if(r.verdict==="accept"){ accepted = {v:"accept", chain:ch, r, i}; return {stop:"chain", settled:true}; }
      if(r.verdict==="drop" || r.verdict==="reject")
        return {stop:"packet", v:r.verdict, chain:ch, r, i};
    }
    return {stop:"chain", settled:false};
  };

  /* A dormant table's base chains are never registered with netfilter, so no
     packet enters them. Walking them anyway made a parked firewall trace
     exactly like a live one — the one case where the whole screen is wrong. */
  const parked = new Set();

  /* nat chains can be skipped entirely, which is how you see what the filter
     path alone decides */
  const byHook = h => MODEL.chains
    .filter(c=>c.hook===h && (p.nat || c.type!=="nat"))
    .filter(c=>{ if(!isDormant(MODEL, c.table)) return true; parked.add(c.table); return false; })
    .sort((a,b)=>a.prio-b.prio).map(c=>UID(c));

  const stages = (PATHS[p.dir] || PATHS.in).flatMap(([h])=>byHook(h));
  let final = null, last = stages[0] || (MODEL.chains[0] && UID(MODEL.chains[0]));
  for(const c of stages){
    last = c;
    const hop = steps.length;           /* walk pushes this chain's hop first */
    const out = walk(c);
    if(out.stop==="packet"){ final = out; break; }   /* dropped: done */
    if(out.settled) continue;           /* the chain decided; the policy does not */

    /* it ran out of rules, or returned — a base chain's policy has the last
       word, and it used to be skipped entirely for any chain holding a jump */
    const ch = chainOf(c);
    if(ch.policy && ch.policy!=="accept"){
      steps[hop].policy = ch.policy;
      final = {stop:"packet", v:ch.policy, chain:ch, policy:true};
      break;
    }
    if(ch.policy==="accept"){
      steps[hop].policy = "accept";
      accepted = {v:"accept", chain:ch, policy:true};
    }
  }
  /* survived every hook — the verdict is whatever last accepted it.
     `sure` is the honest half of the answer: this screen's whole claim is that
     its verdict is the one the exported ruleset gives you, and that claim only
     holds for a trace in which every match was actually evaluated. */
  const unsure = [...new Set(guessed)];
  return {
    steps,
    final: final || accepted || {v:"accept", chain:chainOf(last), policy:true},
    sure: unsure.length === 0,
    unsure,
    /* tables this packet would have gone through if they were not parked */
    parked: [...parked],
  };
}

export const setPacket = p => Object.assign(packet, p);
