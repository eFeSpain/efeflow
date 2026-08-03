/* Evaluates a synthetic packet against the same model the code is
   emitted from, so a verdict here is the verdict the export produces. */
import { MODEL, UID, chainOf, jumpTarget, expand } from './model.js';
import { inCidr, family, looksLikeAddr, toBig } from './addr.js';
import { isDormant } from './tables.js';
export { inCidr };

/* Elements a rule put in a set during this walk.
 *
 * `add @banned { ip saddr }` writes the packet's own address into the set, and
 * a rule below it that looks that set up finds it — within the same traversal,
 * in the kernel and so here. Without this the lookup missed, silently, and the
 * shape it misses on is the one this application has a whole finding about:
 * a set filled by traffic.
 *
 * Null outside a walk, deliberately. inSet() is exported and the analyser uses
 * it; away from the one function that controls the lifetime, showing elements
 * no ruleset holds would be worse than showing none. */
let ADDED = null;

const setOf = n => {
  const el = (MODEL.sets.find(s=>s.n===n)||{el:[]}).el;
  const extra = ADDED && ADDED.get(n);
  return extra ? [...el, ...extra] : el;
};

const unquote = s => String(s ?? "").trim().replace(/^"([^"]*)"$/, "$1");

/* An element of a set carries its own attributes when the kernel is keeping
   them: `elements = { 203.0.113.0/24 timeout 30m, 198.51.100.7 }`, which is
   the shape fail2ban and friends write and exactly what a live host prints
   back. Compared whole, the element never matched anything again. */
const bare = e => unquote(String(e ?? "").trim()
  .replace(/\s+(timeout|expires|comment)\s+\S+.*$/, "").trim());

/* `9000-9100`, `10.0.0.1-10.0.0.9`: nftables writes an inclusive range with a
   dash, and both ends have to be the same kind of thing for it to be one.
   Without this test an interface called `wan0-guest` reads as a range. */
const isRange = (a, b) =>
  (/^\d+$/.test(a) && /^\d+$/.test(b)) || (looksLikeAddr(a) && looksLikeAddr(b));

function between(v, lo, hi){
  if(/^\d+$/.test(lo)) return /^\d+$/.test(v) && +v >= +lo && +v <= +hi;
  const n = toBig(v), a = toBig(lo), b = toBig(hi);
  if(n === null || a === null || b === null) return false;
  /* an address of one family is never inside a range of the other */
  return family(v) === family(lo) && n >= a && n <= b;
}

/**
 * One value against one thing the language can compare it to: a port, an
 * address, a prefix, a range, a name.
 *
 * Sets, braced lists and bare tokens each used to carry their own half of
 * this, and none of the three halves knew about ranges — so `udp dport
 * 5060-5070` was a certain miss, in a rule the matcher was confident it had
 * understood. Recognising the shape and then comparing it wrongly is the one
 * failure mode `unmodelled()` cannot catch, because nothing was left over to
 * report. One function, so a shape learned once is learned everywhere.
 */
export function atom(v, tok){
  const t = bare(tok);
  if(!t) return false;
  const s = String(v);
  const dash = t.match(/^([^\s-]+)\s*-\s*([^\s-]+)$/);
  if(dash && isRange(dash[1], dash[2])) return between(s, dash[1], dash[2]);
  if(t.includes("/") || looksLikeAddr(t)) return inCidr(s, t);
  return s === t;
}

/* An interface name, which is the one place nftables takes a wildcard: a
   trailing `*` is a prefix match, and it is how a single rule covers veth0,
   veth1 and every container that does not exist yet. Compared as text it
   matched nothing at all. */
export function nameAtom(v, tok){
  const t = bare(tok);
  const s = String(v ?? "");
  return t.endsWith("*") ? s.startsWith(t.slice(0, -1)) : s === t;
}

/* nftables compares with more than equality: `tcp dport >= 1024` is as
   ordinary as a set, and reading the operator as the value made every one of
   them a certain miss — on a rule about ephemeral ports, which is where they
   are usually written.
   Null when this is not a relational comparison, or not one that can be
   answered, so the caller falls back to reading it as a value. */
function relate(op, v, tok){
  if(op !== "<" && op !== ">" && op !== "<=" && op !== ">=") return null;
  const num = t => /^\d+$/.test(t) ? BigInt(t) : (looksLikeAddr(t) ? toBig(t) : null);
  const a = num(String(v).trim()), b = num(bare(tok));
  if(a === null || b === null) return null;
  return op === "<" ? a < b : op === ">" ? a > b : op === "<=" ? a <= b : a >= b;
}

const items = tok => tok.slice(1, -1).split(",").map(s => s.trim()).filter(Boolean);

export function inSet(v, name, cmp = atom){
  return setOf(name).some(e => cmp(v, e));
}
export function matchVal(v, tok, cmp = atom){
  if(!v && v!==0) return false;
  if(tok.startsWith("@")) return inSet(v, tok.slice(1), cmp);
  if(tok.startsWith("{")) return items(tok).some(e => cmp(v, e));
  return cmp(v, tok);
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
/* names, not values: an interface is never a range and may carry a wildcard */
const matchIface = (v, tok) => matchVal(v ?? "", tok, nameAtom);

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
/* `new,established` and `{ new, established }` name the same two states */
const states = tok => tok.replace(/^\{|\}$/g, "").split(",").map(x => x.trim()).filter(Boolean);
/* nft prints `tcp` and takes `6`, and a ruleset generated by a script usually
   carries the number. `ipv6-icmp` is the same protocol as `icmpv6` under the
   name the v6 header uses for it — comparing either against the other was a
   certain miss on every ICMPv6 rule. */
const PROTO_NUM = { 1:"icmp", 2:"igmp", 6:"tcp", 17:"udp", 33:"dccp", 41:"ipv6",
  47:"gre", 50:"esp", 51:"ah", 58:"icmpv6", 89:"ospf", 112:"vrrp", 132:"sctp",
  136:"udplite" };
const PROTO_ALIAS = { "ipv6-icmp":"icmpv6", "icmp6":"icmpv6", "ipv6-nonxt":"nonxt" };
const protoName = t => {
  const s = String(t ?? "").trim();
  if(/^\d+$/.test(s)) return PROTO_NUM[+s] ?? s;
  return PROTO_ALIAS[s] ?? s;
};
const inList = (tok, v) => (tok.startsWith("{")
  ? tok.slice(1,-1).split(",").map(x=>x.trim())
  : [tok]).some(x => protoName(x) === protoName(v));

/* ── concatenations ──────────────────────────────────────────────────────
   `ip saddr . tcp dport @allowed` is the ordinary way to say "this address
   may talk to this port", and the address matcher used to read the `.` as the
   value it was constraining — so the rule was a certain miss, silently, on
   the one construct people reach for when a plain set is not enough.

   Each key is read off the packet, the tuple is compared element by element
   against the set, and every element goes through the same comparator as it
   would on its own: a prefix, a range or a wildcard inside a concatenation is
   still a prefix, a range or a wildcard. A concatenation naming a key this
   does not read is left whole for unmodelled() to report, rather than half
   evaluated. */
const CONCAT_KEY = {
  "ip saddr":  { of: p => p.saddr, cmp: atom },
  "ip6 saddr": { of: p => p.saddr, cmp: atom },
  "ip daddr":  { of: p => p.daddr, cmp: atom },
  "ip6 daddr": { of: p => p.daddr, cmp: atom },
  "tcp dport": { of: p => p.dport, cmp: atom },
  "udp dport": { of: p => p.dport, cmp: atom },
  "tcp sport": { of: p => p.sport, cmp: atom },
  "udp sport": { of: p => p.sport, cmp: atom },
  "th dport":  { of: p => p.dport, cmp: atom },
  "th sport":  { of: p => p.sport, cmp: atom },
  "iifname":   { of: p => p.iif,   cmp: nameAtom },
  "iif":       { of: p => p.iif,   cmp: nameAtom },
  "oifname":   { of: p => p.oif,   cmp: nameAtom },
  "oif":       { of: p => p.oif,   cmp: nameAtom },
  "meta l4proto": { of: p => p.proto, cmp: (v,t) => protoName(t) === protoName(v) },
  "ip protocol":  { of: p => p.proto, cmp: (v,t) => protoName(t) === protoName(v) },
  "ct state":     { of: p => p.state, cmp: (v,t) => String(v) === String(t).trim() },
};
const KEY_RE = Object.keys(CONCAT_KEY).sort((a,b)=>b.length-a.length)
  .map(k => k.replace(/ /g, "\\s+")).join("|");
const CONCAT_RE = new RegExp(
  `\\b((?:${KEY_RE})(?:\\s*\\.\\s*(?:${KEY_RE}))+)\\s+(!=\\s*)?(@\\w+|\\{[^}]*\\})`, "g");

/* one key or a concatenation of them, then the map that decides */
const VMAP_RE = new RegExp(
  `\\b((?:${KEY_RE})(?:\\s*\\.\\s*(?:${KEY_RE}))*)\\s+vmap\\s+(@\\w+|\\{[^}]*\\})`, "g");

const keysOf = m => m[1].split(/\s*\.\s*/).map(k => k.trim().replace(/\s+/g, " "));

/* the concatenations this can actually evaluate, as spans of the expression */
function concatSpans(e){
  const out = [];
  for(const re of [CONCAT_RE, VMAP_RE])
    for(const m of e.matchAll(re))
      if(keysOf(m).every(k => CONCAT_KEY[k])) out.push([m.index, m.index + m[0].length]);
  return out;
}

/**
 * `tcp dport vmap { 80 : accept, 443 : drop }` — the lookup is the verdict,
 * and the rule carries none of its own.
 *
 * The port matcher read `vmap` as the value it was comparing, so the rule was
 * a certain miss — and a miss is never reported as a guess, because
 * unmodelled() is only asked about rules that matched. A packet to port 80 was
 * shown falling past an accept written for it into a policy drop, and the
 * trace called itself certain. `ct state vmap` had already been found doing
 * this; every other key was doing it too.
 *
 * @returns the verdict as written (`accept`, `jump lan_in`), `null` when no
 *   element holds the key — the rule does not fire — or `undefined` when the
 *   key is one nothing here reads, which is left to unmodelled().
 */
export function vmapVerdict(expr, p){
  const m = new RegExp(VMAP_RE.source).exec(expand(expr));
  if(!m) return undefined;
  const keys = m[1].trim().split(/\s+\.\s+/).map(k => k.trim().replace(/\s+/g, " "));
  const parts = keys.map(k => CONCAT_KEY[k]);
  if(parts.some(x => !x)) return undefined;
  const vals = parts.map(x => x.of(p));
  for(const e of (m[2].startsWith("@") ? setOf(m[2].slice(1)) : items(m[2]))){
    const at = String(e).split(/\s+:\s+/);
    if(at.length !== 2) continue;
    const ks = at[0].split(/\s+\.\s+/);
    if(ks.length === keys.length && ks.every((kv, i) => parts[i].cmp(vals[i], kv)))
      return at[1].trim();
  }
  return null;
}

/* `add @banned { ip saddr }`, and the update form, and a concatenated key.
   An element may carry its own timeout, which is bookkeeping and not part of
   the value. */
const ADD_RE = /\b(?:add|update)\s+@(\w+)\s*\{([^}]*)\}/g;

function addElements(expr, p, note){
  for(const m of String(expr || "").matchAll(ADD_RE)){
    const body = m[2].replace(/\s+timeout\s+\S+/g, "").trim();
    const keys = body.split(/\s+\.\s+/).map(k => k.trim().replace(/\s+/g, " "));
    const parts = keys.map(k => CONCAT_KEY[k]);
    if(parts.some(x => !x)){
      note(`this rule fills @${m[1]} with ${body}, which this cannot read`);
      continue;
    }
    const val = parts.map(x => x.of(p)).join(" . ");
    if(!ADDED.has(m[1])) ADDED.set(m[1], []);
    ADDED.get(m[1]).push(val);
  }
}

function concatOk(m, p){
  const keys = keysOf(m);
  const parts = keys.map(k => CONCAT_KEY[k]);
  if(parts.some(x => !x)) return true;          /* not ours to decide */
  const vals = parts.map(x => x.of(p));
  const tuples = m[3].startsWith("@") ? setOf(m[3].slice(1)) : items(m[3]);
  const hit = tuples.some(t => {
    /* on the separator, not on every dot: nft writes a concatenation as
       `203.0.113.48 . 9038`, and splitting on a bare dot turns the address
       into four elements of its own */
    const ts = String(t).split(/\s+\.\s+/);
    return ts.length === keys.length && ts.every((tv, i) => parts[i].cmp(vals[i], tv));
  });
  return negated(m[2], hit);
}

const MATCHERS = [
  /* an untracked packet has no conntrack entry: `ct state` can only match it
     through the untracked keyword, and `ct status` never matches */
  /* `ct state { new, established }` is the same constraint as the comma form
     and nft prints both. And the negative lookahead is load-bearing: with
     `ct state vmap { established : accept, invalid : drop }` — the shape most
     modern rulesets open a chain with — this read `vmap` as the name of a
     state, found the packet was not in it, and made the rule a certain miss.
     A miss is never reported as a guess, because unmodelled() is only asked
     about rules that matched, so nothing on the screen said anything at all.
     Left unread it becomes what it is: something this cannot evaluate. */
  { re: /\bct\s+state\s+(?!vmap\b)(!=\s*)?(\{[^}]*\}|[\w,]+)/,
    ok: (m,p) => { const want = states(m[2]);
                   return negated(m[1], p.tracked ? want.includes(p.state)
                                                  : want.includes("untracked")); } },
  /* Only the two statuses this can answer for. `confirmed`, `assured`,
     `seen-reply` and the rest are conntrack bookkeeping nothing here models,
     and answering them with "was this packet DNATed" was an invention: it
     made `ct status snat` true for a DNATed packet and `ct status confirmed`
     true for anything at all. Unmatched, they reach unmodelled() and are named
     under the verdict as assumed, which is the honest answer. */
  { re: /\bct\s+status\s+(!=\s*)?(snat|dnat)\b/,
    ok: (m,p) => negated(m[1], !!(p.tracked && (m[2] === "dnat" ? p.dnat : p.snat))) },
  /* Three spellings of one question, and they are not the same question.
       tcp flags syn                    the syn bit is set, whatever else is
       tcp flags & (syn|ack) == syn     of those two bits, exactly syn
       tcp flags syn / fin,syn,rst,ack  the same, with the operands the other
                                        way round — and this one was read as
                                        the bare form, so it matched a syn|ack
                                        packet that nft would have refused.
     Both masked forms come down to: every bit the mask names is exactly as
     the value says. The bare form is the same thing with the value as its own
     mask, which is why it can be written once. */
  { re: /\btcp\s+flags\s+(!=\s*)?(?:&\s*)?\(?([\w|,]+)\)?\s*(?:(==|\/)\s*\(?([\w|,]+)\)?)?/,
    ok: (m,p) => {
      const set = new Set(p.flags || []);
      /* `== 0` names no bits at all — the null-scan check, and a bit called
         "0" is what it used to be compared against */
      const bits = t => /^(0|0x0+|none)$/i.test(t.trim())
        ? [] : t.split(/[|,]/).map(x=>x.trim()).filter(Boolean);
      const want = m[3] === "==" ? bits(m[4]) : bits(m[2]);
      const mask = m[3] === "==" ? bits(m[2]) : m[3] === "/" ? bits(m[4]) : want;
      return negated(m[1], want.every(f => set.has(f))
                        && mask.every(f => set.has(f) === want.includes(f)));
    } },
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
  /* A packet described in this simulator is one whole packet: it is given
     ports and TCP flags, which a later fragment does not carry. Its fragment
     offset is therefore zero, and `ip frag-off & 0x1fff != 0` — the usual
     first line of an ingress chain, and the first line of the one that turned
     this up — does not match it.
     Left unread the rule was taken as matching, so a `drop` on that line
     swallowed every packet before the chain below it was ever reached: an
     answer nobody could use, in the one chain that had just become visible. */
  { re: /\bip\s+frag-off\s+(?:&\s*(\S+)\s+)?(!=\s*)?(\S+)/,
    ok: (m) => {
      const num = t => /^0x/i.test(t) ? parseInt(t, 16) : Number(t);
      const mask = m[1] === undefined ? 0x1fff : num(m[1]);
      const want = num(m[3]);
      /* anything this cannot read a number out of is left to unmodelled() */
      if(!Number.isFinite(mask) || !Number.isFinite(want)) return true;
      return negated(m[2], (0 & mask) === want);
    } },
  /* which family the packet is, which the addresses already say */
  { re: /\bmeta\s+nfproto\s+(!=\s*)?(\{[^}]*\}|\S+)/,
    ok: (m,p) => negated(m[1],
      inList(m[2], family(p.saddr ?? p.daddr) === 6 ? "ipv6" : "ipv4")) },
  /* `ip protocol icmp` is how a v4 rule says it, and `ip6 nexthdr` the v6 one.
     Neither was read, so both matched every packet. */
  { re: /\b(ip|ip6)\s+(?:protocol|nexthdr)\s+(!=\s*)?(\{[^}]*\}|\S+)/,
    ok: (m,p) => (m[1] === "ip6" ? 6 : 4) === family(p.saddr ?? p.daddr)
                 && negated(m[2], inList(m[3], p.proto)) },
  { re: /\b(tcp|udp|sctp|dccp|udplite)\s+(sport|dport)\s+(!=|<=|>=|<|>)?\s*(\{[^}]*\}|\S+)/,
    ok: (m,p) => {
      if(m[1] !== p.proto) return false;
      const v = m[2] === "dport" ? p.dport : p.sport;
      const rel = relate(m[3], v, m[4]);
      return rel !== null ? rel : negated(m[3], matchVal(v, m[4]));
    } },
  { re: /\b(tcp|udp|icmp|icmpv6|sctp|dccp)\b/, ok: (m,p) => m[1] === p.proto },
  { re: /\b(sport|dport)\s+(!=|<=|>=|<|>)?\s*(\{[^}]*\}|\S+)/,
    ok: (m,p) => {
      const v = m[1] === "dport" ? p.dport : p.sport;
      const rel = relate(m[2], v, m[3]);
      return rel !== null ? rel : negated(m[2], matchVal(v, m[3]));
    } },
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
  /* struck out for the same reason as a fib lookup: the address matcher read
     the `.` of `ip saddr . tcp dport @pairs` as the address it was comparing.
     matches() evaluates these before the mask goes on; the ones it cannot are
     reported whole by unmodelled() rather than half read. */
  new RegExp(CONCAT_RE.source, "g"),
  new RegExp(VMAP_RE.source, "g"),
  /* `add @banned { ip saddr }` names a key, not a constraint — and the address
     matcher was reading the `}` after it as the address the rule compared
     against, so the rule never matched. That rule is the standard shape for
     tarpitting a scanner, and the one this application has a whole finding
     about: a set filled by traffic. It never fired in any trace. */
  new RegExp(ADD_RE.source, "g"),
  /* `ip saddr & 255.255.255.0 == 10.0.0.0` is a prefix test written the long
     way, and the address matcher was reading the `&` as the address — another
     certain miss. Nothing here evaluates a bitwise mask on an address, so it
     is struck out and named rather than answered. */
  /\b(?:ip6?|meta|ct)\s+\w+\s+&\s*\S+\s*(?:==|!=)\s*\S+/g,
  /* A hash, or a counter chosen at random, is not something one packet has an
     answer for — and `jhash ip saddr mod 2 == 0` was worse than unanswered:
     the address matcher read the `ip saddr` out of the middle of it and
     compared the packet against the word `mod`. */
  /\b(?:numgen|jhash|symhash)\s+[^{]*?mod\s+\d+(?:\s+offset\s+\d+)?(?:\s*(?:<=|>=|==|!=|<|>)\s*\S+)?/g,
  /\bfib\s+\w+(?:\s*\.\s*\w+)*\s+(?:oif(?:name)?|type|check)(?:\s+(?:!=\s*)?\S+)?/g,
  /* `icmp type echo-request` is two claims, and only one of them is beyond
     this: which message it is. That it is ICMP at all is knowable, and masking
     the keyword along with the type threw it away — so the rule matched a TCP
     packet, admitted only that it had not read something, and was believed.
     The lookbehind leaves the protocol for the matcher above and strikes out
     the part nothing here can answer. */
  /(?<=\b(?:icmp|icmpv6|igmp)\s)(?:type|code)\s+(!=\s*)?(?:\{[^}]*\}|\S+)/g,
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
  /* before the mask, because the mask is what stops anything else reading
     into them */
  for(const m of e.matchAll(CONCAT_RE))
    if(!concatOk(m, p)) return false;
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
  /* Statements, not matches: whether the rule applies does not turn on any of
     them, so reporting them as assumptions was noise — and the whole value of
     that list is in it being short. A rule doing `meta mark set` or `notrack`
     is one this reads perfectly well.
     `limit rate` is deliberately not here. A rate limit really does decide
     whether the rule fires, out of a history no single packet carries, and
     saying so is the honest answer rather than a nuisance. */
  /\bmeta\s+(?:mark|priority|nftrace|secmark|pkttype)\s+set\s+\S+/g,
  /\bct\s+(?:mark|label|event|zone|helper)\s+set\s+\S+/g,
  /\bnotrack\b/g,
  /\bnftrace\s+set\s+\d+/g,
  /\bqueue(?:\s+(?:num|flags)\s+\S+)*/g,
  /\bflow\s+(?:add|offload)\s+@\w+/g,
  /\b(?:add|update|delete)\s+@\w+\s*\{[^}]*\}/g,
  /\b(?:dup|fwd|tproxy)\s+to\s+\S+(?:\s+device\s+\S+)?/g,
  /\bsynproxy\b(?:\s+(?:mss|wscale)\s+\S+|\s+(?:timestamp|sack-perm))*/g,
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
  /* a concatenation matches() could evaluate was read, whatever the mask says
     about it; one naming a key nothing reads stays leftover, and is reported */
  read.push(...concatSpans(e));
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
  /* netdev `ingress` runs before prerouting and `egress` after postrouting,
     and neither was in this list — so a netdev chain was never walked at all.
     A bridge filtering rogue DHCP, which is one of the scenarios this ships as
     a sample, dropped the packet on the real firewall and accepted it here. */
  in:  [["ingress"],["prerouting"],["input"]],
  fwd: [["ingress"],["prerouting"],["forward"],["postrouting"],["egress"]],
  out: [["output"],["postrouting"],["egress"]],
};

/* Which devices a netdev chain is attached to. The header keeps the phrase as
   written — `device "wan0"`, or `devices = { eth0, br0 }` — because that is
   what has to go back out. */
export const chainDevices = ch => [...String(ch.dev || "").matchAll(/"([^"]*)"|[\w.*-]+/g)]
  .map(m => m[1] ?? m[0])
  .filter(d => d && d !== "device" && d !== "devices" && d !== "=");

/* A table's family decides which packets reach its chains at all, and nothing
   was checking it: an `ip nat` table translated IPv6 traffic and an `ip6
   filter` table dropped IPv4. On a dual-stack ruleset — which is most of them
   — half the trace was chains the packet never enters.
   `inet` sees both by design. `bridge` and `netdev` are not decided by the
   address family. `arp` only ever sees ARP, and a packet described here always
   has an IP address, so it is never one. */
const seesPacket = (ch, p) => {
  const f = String(ch.table || "").split(" ")[0];
  if(f === "arp") return false;
  if(f !== "ip" && f !== "ip6") return true;
  return family(p.saddr ?? p.daddr) === (f === "ip6" ? 6 : 4);
};

/* Only packets on that device enter it: `hook ingress device "wan0"` says
   nothing about traffic arriving on br-lan. */
const onDevice = (ch, p) => {
  const ds = chainDevices(ch);
  if(!ds.length) return true;
  const name = ch.hook === "egress" ? p.oif : p.iif;
  return ds.some(d => nameAtom(name, d));
};

/* Where a NAT verdict sends the packet. The target is an address, a port, or
   both — `10.0.0.5`, `10.0.0.5:8080`, `:8080`, `[2001:db8::1]:80` — and an
   unbracketed IPv6 address is all colons and no port at all, which is why the
   port is only read when the address is bracketed or holds no colon of its
   own. Splitting on ":" unconditionally set the port to NaN for every
   `dnat to <address>`, and a packet with no port matches nothing downstream. */
/**
 * `dnat to tcp dport map @port_fwd` — the target is a lookup, not an address.
 *
 * Applied as written, the whole expression became the packet's destination: a
 * string no address matcher recognises, so every rule below a port-forwarding
 * map missed, silently, on the single most common way of writing one.
 *
 * A failed lookup is not a translation to nowhere either. The map is part of
 * the expression, so a key that is not in it means the rule does not fire at
 * all, and the packet carries on to the next one.
 *
 * @returns {{to: string|null, missed: boolean, assumed: string[]}} — `missed`
 *   is the key not being there; `to === null` without it is a key this cannot
 *   read, which is assumed rather than answered.
 */
export function natLookup(spec, p){
  const m = String(spec ?? "").match(/^(.*?)\s+map\s+(@\w+|\{[^}]*\})$/);
  if(!m) return { to: String(spec ?? ""), missed: false, assumed: [] };

  const keys = m[1].trim().split(/\s+\.\s+/).map(k => k.trim().replace(/\s+/g, " "));
  const parts = keys.map(k => CONCAT_KEY[k]);
  if(parts.some(x => !x))
    return { to: null, missed: false,
             assumed: [`the target is a map on ${m[1].trim()}, which this cannot read`] };

  const vals = parts.map(x => x.of(p));
  for(const e of (m[2].startsWith("@") ? setOf(m[2].slice(1)) : items(m[2]))){
    /* nft prints an element as `8443 : 10.20.0.31:443`, and the separator has
       spaces around it — which is what tells it from the colon in the port */
    const at = String(e).split(/\s+:\s+/);
    if(at.length !== 2) continue;
    const ks = at[0].split(/\s+\.\s+/);
    if(ks.length === keys.length && ks.every((kv, i) => parts[i].cmp(vals[i], kv)))
      return { to: at[1].trim(), missed: false, assumed: [] };
  }
  return { to: null, missed: true, assumed: [] };
}

export function natTarget(spec){
  const s = String(spec ?? "").trim();
  const m = s.match(/^(\[[^\]]*\]|[^:]*)(?::(\d+)(?:-(\d+))?)?$/);
  if(!m) return {host:s, port:null, assumed:[]};
  const assumed = [];
  /* An IPv6 target is written in brackets so the port can be told from the
     address. Keeping them made the destination a string no address matcher
     recognised, so every rule downstream of a v6 DNAT quietly missed. */
  let host = (m[1] || "").replace(/^\[(.*)\]$/, "$1");
  /* `dnat to 10.20.1.1-10.20.1.9` hands the kernel a pool and it picks one. A
     packet has one destination, so the trace has to pick too — the first, and
     it says so, because which one it picked can change what matches next. */
  const range = host.match(/^([^\s-]+)\s*-\s*(\S+)$/);
  if(range && looksLikeAddr(range[1]) && looksLikeAddr(range[2])){
    host = range[1];
    assumed.push(`the destination was taken as ${host} out of ${m[1]}`);
  }
  const port = m[2] ? +m[2] : null;
  if(m[3]) assumed.push(`the port was taken as ${port} out of ${m[2]}-${m[3]}`);
  return {host, port, assumed};
}

export function evaluate(input){
  /* The packet the caller handed over is not ours to change, and this used to
     translate it in place: a DNAT rewrote its destination, so running the same
     simulation twice gave two different answers — the second one starting from
     where the first had left the packet, with the rule that moved it no longer
     matching. The interface copies before calling and was never affected; the
     trap was waiting for everything else. The translated packet comes back in
     the result instead. */
  const p = { ...input, flags: [...(input.flags || [])] };
  ADDED = new Map();
  try{
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
  /* The chains currently being walked, so a cycle is refused instead of
     recursing into the stack until the browser stops it.
     `nft` rejects a loop when the ruleset is loaded, so this cannot arrive
     from a host — but the editor can build one with two clicks, and what it
     produced was `RangeError: Maximum call stack size exceeded` from inside a
     click handler, which is precisely the shape of failure that once shipped
     a broken simulator: an exception with nowhere to go and a screen that
     simply stopped answering. A cycle decides nothing and is named under the
     verdict, like anything else this cannot evaluate. */
  const walking = new Set();
  const walk = (chainId, depth=0) => {
    const ch = chainOf(chainId);
    /* a chain that is not there decides nothing — it can be deleted while a
       rule still names it, and lint.js is what says so out loud */
    if(!ch) return {stop:"chain", settled:false};
    if(walking.has(chainId) || depth > 64){
      guessed.push(`${ch.id} jumps back into a chain already being walked, so this trace stops there`);
      return {stop:"chain", settled:false};
    }
    walking.add(chainId);
    try{
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

      /* What a matched rule does to the packet before its verdict is read.
         `notrack` takes it out of conntrack, so every `ct state` below can
         only reach it through the untracked keyword — and left unmodelled it
         was a rule the trace read perfectly and then ignored, which is how a
         raw-table `notrack` produced an answer for a packet that no longer
         had the conntrack entry the answer was about. */
      if(/\bnotrack\b/.test(String(r.expr || ""))) p.tracked = false;
      addElements(r.expr, p, m => guessed.push(m));

      /* NAT terminates the chain, and the packet that walks on to the next
         hook is the translated one. */
      /* a map target is also a constraint: a key the map does not hold means
         the rule never fires, so the packet walks on to the next one */
      let target = r.to;
      if(/\s+map\s+/.test(String(r.to || ""))){
        const look = natLookup(r.to, p);
        if(look.missed){ hop.evs.push({r, i, st:"miss", note:"map"}); continue; }
        guessed.push(...look.assumed);
        target = look.to ?? "";
      }

      /* A verdict map decides the verdict, and the rule carries none of its
         own — the parser reads it as falling through, because there is no
         verdict word at the end of the line to read. Same rule as a map
         target: a key the map does not hold means nothing fires. */
      let verdict = r.verdict;
      if(/\bvmap\b/.test(String(r.expr || ""))){
        const v = vmapVerdict(r.expr, p);
        if(v === null){ hop.evs.push({r, i, st:"miss", note:"vmap"}); continue; }
        if(v !== undefined){
          const go = v.match(/^(jump|goto)\s+(\S+)$/);
          if(go){ verdict = go[1]; target = go[2]; }
          else { verdict = v; target = undefined; }
          hop.evs[hop.evs.length - 1].via = v;
        }
      }

      if(verdict==="dnat" || verdict==="redirect"){
        const {host, port, assumed} = natTarget(target);
        guessed.push(...assumed);
        p.dnat = true;
        if(host) p.daddr = host;
        if(port !== null) p.dport = port;
        hop.nat = r.to || verdict;
        return {stop:"chain", settled:true};
      }
      /* `ct status snat` can only be answered for a packet something has
         actually translated the source of */
      if(verdict==="snat"){ p.snat = true; hop.nat = target; return {stop:"chain", settled:true}; }

      /* jump remembers where it came from and goto does not — which is the
         whole reason nftables has both. A goto whose target settles nothing
         leaves the base chain's policy to decide, never the rules below it. */
      if(verdict==="jump" || verdict==="goto"){
        const tgt = jumpTarget(ch, target);
        if(!tgt) continue;              /* a chain that is not there decides nothing */
        const v = walk(UID(tgt), depth+1);
        if(v.stop==="packet") return v;
        if(verdict==="goto" || v.settled) return {stop:"chain", settled:v.settled};
        continue;
      }

      /* `return` leaves this chain having decided nothing: back to the caller,
         or to the policy if this chain is the base one. */
      if(verdict==="return") return {stop:"chain", settled:false};

      /* nftables terminality: `accept` ends this chain but the packet carries
         on to the next hook. Only drop/reject end the packet outright. */
      if(verdict==="accept"){ accepted = {v:"accept", chain:ch, r, i}; return {stop:"chain", settled:true}; }
      if(verdict==="drop" || verdict==="reject")
        return {stop:"packet", v:verdict, chain:ch, r, i};
    }
    return {stop:"chain", settled:false};
    } finally { walking.delete(chainId); }
  };

  /* A dormant table's base chains are never registered with netfilter, so no
     packet enters them. Walking them anyway made a parked firewall trace
     exactly like a live one — the one case where the whole screen is wrong. */
  const parked = new Set();

  /* nat chains can be skipped entirely, which is how you see what the filter
     path alone decides */
  const byHook = h => MODEL.chains
    .filter(c=>c.hook===h && (p.nat || c.type!=="nat"))
    .filter(c=>seesPacket(c, p))
    .filter(c=>onDevice(c, p))
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
    /* what it was by the end: translated, tracked, and whatever else the walk
       did to it. The one the caller passed in is untouched. */
    packet: p,
    final: final || accepted || {v:"accept", chain:chainOf(last), policy:true},
    sure: unsure.length === 0,
    unsure,
    /* tables this packet would have gone through if they were not parked */
    parked: [...parked],
  };
  } finally { ADDED = null; }
}

export const setPacket = p => Object.assign(packet, p);
