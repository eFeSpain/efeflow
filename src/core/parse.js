/* nftables source → model. The expression is kept verbatim minus the
   counter and comment, which is what makes the round-trip faithful.

   The governing rule is preserve by default. nftables is a much larger
   language than this model, and every construct the parser did not recognise
   used to be dropped on the floor — silently, and in the case of anything that
   opened a brace, taking the enclosing table with it. A flowtable and a named
   counter each closed their table early, so every chain below them was filed
   under a table that did not exist. Whatever we cannot model, we keep as text
   and put back where it was. */
import { ruleLine } from './model.js';
import { generate } from './generate.js';
import { diffLines } from './diff.js';
import { PRIO_NAME } from './priority.js';

const count = (s, ch) => (s.match(ch === "{" ? /\{/g : /\}/g) || []).length;
/* how much deeper this line leaves you: `elements = { a,` is +1, `}` is -1 */
const net = s => count(s, "{") - count(s, "}");

/* A block opener is `chain foo {`, not `elements = {`. nft wraps a long
   element list across lines, so the two shapes have to be told apart before
   anything else looks at them. */
const isOpener = line => /\{$/.test(line) && !line.includes("=");

/* Comment-stripped, brace-balanced lines. nft prints a set's elements over as
   many lines as it needs, and reading them one at a time is how a blocklist
   with four hundred entries imported with none. */
export function logicalLines(text){
  const out = [];
  let pending = null;
  const flush = () => {
    out.push({ text: pending.text, ln: pending.ln, raw: pending.text, handle: pending.handle });
    pending = null;
  };
  text.split("\n").forEach((raw, ln) => {
    /* `nft -a list ruleset` prints the handle of every rule as a trailing
       comment. It is how you delete or replace one rule on a live host, so it
       is worth keeping — and it used to be stripped here and a made-up number
       shown in its place. */
    const h = raw.match(/#\s*handle\s+(\d+)\s*$/);
    const handle = h ? +h[1] : null;
    const line = raw.replace(/#\s*handle\s+\d+\s*$/, "").trim();
    if(pending){
      pending.text += " " + line;
      pending.depth += net(line);
      pending.handle ??= handle;
      if(pending.depth <= 0) flush();
      return;
    }
    if(!line || line.startsWith("#")) return;
    /* a line that opens a brace it does not close, and is not a block header,
       is a statement nft has wrapped: read on until it closes */
    if(net(line) > 0 && !isOpener(line)){ pending = { text: line, ln, depth: net(line), handle }; return; }
    out.push({ text: line, ln, raw: raw.trim(), handle });
  });
  if(pending) flush();
  return out;
}

export function parseNft(text){
  const chains = [], sets = [], objects = [], tables = [], errors = [];

  /* innermost frame last; every `}` pops exactly one */
  const stack = [];
  const top = () => stack[stack.length - 1];
  const tableName = () => {
    for(let i = stack.length - 1; i >= 0; i--) if(stack[i].kind === "table") return stack[i].name;
    return null;
  };
  const close = () => {
    const f = stack.pop();
    if(!f) return;
    if(f.kind === "set")    sets.push(f.set);
    if(f.kind === "object") objects.push(f.obj);
    if(f.kind === "table")  tables.push({ name: f.name, extra: f.extra || [] });
  };

  for(const { text: line, ln, raw, handle } of logicalLines(text)){
    if(/^\}\s*;?$/.test(line)){ close(); continue; }

    let m;
    /* `table inet filter {` — and `table filter {`, where the family is ip */
    if((m = line.match(/^table\s+(\w+)(?:\s+(\S+))?\s*\{$/))){
      stack.push({ kind: "table", name: m[2] ? `${m[1]} ${m[2]}` : `ip ${m[1]}` });
      continue;
    }
    if((m = line.match(/^(set|map)\s+(\S+)\s*\{$/))){
      stack.push({ kind: "set", set: {
        n: m[2], t: "", f: "", el: [], body: [], kind: m[1], table: tableName() || "inet fw",
      }});
      continue;
    }
    if((m = line.match(/^chain\s+(\S+)\s*\{$/))){
      const c = { id: m[1], table: tableName() || "inet fw", hook: null, prio: null,
                  type: "regular", policy: null, rules: [], extra: [],
                  ...(handle ? { handle } : {}) };
      chains.push(c);
      stack.push({ kind: "chain", chain: c });
      continue;
    }
    /* Anything else that opens a block inside a table is an object nftables
       has and this model does not: a flowtable, a named counter or quota, a
       ct helper or timeout, a synproxy. Keep the body verbatim. */
    if(isOpener(line) && tableName()){
      stack.push({ kind: "object", obj: { table: tableName(), ...splitObject(line), body: [] } });
      continue;
    }

    const f = top();
    if(!f) continue;                                  /* outside every table */
    if(f.kind === "object"){ f.obj.body.push(line); continue; }
    if(f.kind === "set"){ readSetLine(f.set, line); continue; }
    /* directly inside a table: `flags dormant`, `comment "…"` */
    if(f.kind === "table"){ (f.extra ||= []).push(line); continue; }

    const cur = f.chain;
    /* chain header: type filter hook input [device "eth0"] priority filter; policy drop; */
    if((m = line.match(/^type\s+(\w+)\s+hook\s+(\w+)\s+(.*?)priority\s+(-?\w+)\s*;(?:\s*policy\s+(\w+)\s*;?)?/))){
      cur.type = m[1];
      cur.hook = m[2];
      /* a netdev chain names the device it is attached to, and without it the
         chain is not one nft will accept back */
      cur.dev = m[3].trim() || null;
      const p = m[4];
      cur.prio = /^-?\d+$/.test(p) ? +p : (PRIO_NAME[p] ?? 0);
      cur.prioName = /^-?\d+$/.test(p) ? null : p;
      cur.policy = m[5] || "accept";
      continue;
    }
    if((m = line.match(/^policy\s+(\w+)\s*;?$/))){ cur.policy = m[1]; continue; }
    /* chain-level statements that are not rules: `flags offload`, `comment "…"` */
    if(/^(flags|comment)\s/.test(line)){ cur.extra.push(line); continue; }

    const rule = parseRule(line);
    if(rule){
      if(handle) rule.handle = handle;
      cur.rules.push(rule);
    }
    else errors.push({ ln: ln + 1, line: raw });
  }
  while(stack.length) close();                        /* an unterminated file */

  return { chains, sets, objects, tables, errors };
}

/* Three of nftables' object kinds are two words, and telling them from a kind
   followed by a name is not something the shape of the line can decide:
   `ct helper ftp-standard {` and `flowtable ft {` look alike to a regex. The
   list is short and closed, so it is a list. Anything unrecognised keeps its
   first word as the kind, which is what nft's own grammar does. */
const TWO_WORD = ["ct helper", "ct timeout", "ct expectation"];

export function splitObject(line){
  const head = line.replace(/\s*\{$/, "").trim();
  for(const k of TWO_WORD)
    if(head === k || head.startsWith(k + " "))
      return { kind: k, name: head.slice(k.length).trim() };
  const cut = head.indexOf(" ");
  return cut < 0
    ? { kind: head, name: "" }
    : { kind: head.slice(0, cut), name: head.slice(cut + 1).trim() };
}

/* `type`, `flags` and `elements` are the parts the set editor owns; every
   other line — size, timeout, gc-interval, auto-merge, policy, comment — is
   kept where it sat so it can be written back in the same place. */
function readSetLine(s, line){
  /* `;` separates statements in nft, so `type ipv4_addr ; flags interval` is
     two of them on one line. Read as one, the type became the whole string and
     the flag disappeared from the editor entirely — while still round-tripping
     as text, which is how it went unnoticed. The `join` marker puts them back
     on the line they arrived on. */
  const parts = line.split(";").map(x => x.trim()).filter(Boolean);
  if(parts.length > 1){
    parts.forEach((p, i) => {
      const before = s.body.length;
      readSetLine(s, p);
      if(i && s.body.length > before) s.body[before].join = true;
    });
    return;
  }

  let m;
  if((m = line.match(/^(type|typeof)\s+(.+?)\s*;?$/))){
    s.t = m[2];
    s.decl = m[1];
    s.body.push({ k: "type" });
    return;
  }
  if((m = line.match(/^flags\s+(.+?)\s*;?$/))){ s.f = m[1]; s.body.push({ k: "flags" }); return; }
  /* The attributes the editor can offer as fields. Everything else still falls
     through to `raw` and is carried untouched — the point is that a set you
     imported with a timeout can have its timeout changed, not that this list
     is nftables' complete set grammar. */
  if((m = line.match(/^(timeout|gc-interval|size|policy)\s+(.+?)\s*;?$/))){
    s.attr = { ...s.attr, [m[1]]: m[2] };
    s.body.push({ k: "attr", n: m[1] });
    return;
  }
  if(/^auto-merge\s*;?$/.test(line)){
    s.attr = { ...s.attr, "auto-merge": true };
    s.body.push({ k: "attr", n: "auto-merge" });
    return;
  }
  if((m = line.match(/^elements\s*=\s*\{(.*)\}\s*$/))){
    s.el = m[1].split(",").map(x => x.trim()).filter(Boolean);
    s.body.push({ k: "elements" });
    return;
  }
  s.body.push({ k: "raw", v: line });
}

/* verdict scanners, longest form first so `dnat to` beats a bare token */
/* (?:^|\s+) — a rule may be nothing but its verdict, e.g. `counter drop` */
const VERDICT_RE = [
  [/(?:^|\s+)masquerade$/,                    ()=>({verdict:"snat", to:"masquerade"})],
  [/(?:^|\s+)(dnat|snat)\s+to\s+(.+)$/,       m=>({verdict:m[1], to:m[2]})],
  /* redirect is a DNAT to this machine, and the port is optional. Folding it
     into dnat lost that distinction and emitted `dnat to :8080`, which nft
     rejects — a dnat needs a destination, a redirect already has one. */
  [/(?:^|\s+)redirect(?:\s+to\s+(.+))?$/,     m=>({verdict:"redirect", ...(m[1]?{to:m[1]}:{})})],
  [/(?:^|\s+)(jump|goto)\s+(\S+)$/,           m=>({verdict:m[1], to:m[2]})],
  [/(?:^|\s+)reject\s+with\s+(.+)$/,          m=>({verdict:"reject", to:m[1]})],
  [/(?:^|\s+)reject$/,                        ()=>({verdict:"reject"})],
  [/(?:^|\s+)(accept|drop|return|continue)$/, m=>({verdict:m[1]})],
];

export function parseRule(line){
  let expr = line.replace(/;$/,"").trim();
  let ctr = false, pkts = 0, bytes = 0, cmt = null;

  const c = expr.match(/\bcomment\s+"((?:[^"\\]|\\.)*)"\s*$/);
  if(c){ cmt = c[1]; expr = expr.slice(0, c.index).trim(); }

  /* `counter` is a statement the rule either has or does not; the packet and
     byte figures are statistics it carries. Inferring the first from the
     second loses every counter that has not matched yet — which is what a
     freshly loaded ruleset is made of, and what a rule that should be firing
     and is not looks like. Keep them apart. */
  /* `counter name "http_hits"` is a reference to a named counter object, not
     the anonymous statement — swallowing the keyword left a dangling
     `name "http_hits"` in the expression and re-emitted the rule in a
     different order. The lookahead keeps this off it. */
  const k = expr.match(/\bcounter(?!\s+name\b)(?:\s+packets\s+(\d+)\s+bytes\s+(\d+))?/);
  if(k){
    ctr = true;
    pkts = +(k[1]||0); bytes = +(k[2]||0);
    expr = (expr.slice(0,k.index) + expr.slice(k.index + k[0].length)).replace(/\s{2,}/g," ").trim();
  }

  for(const [re, make] of VERDICT_RE){
    const m = expr.match(re);
    if(!m) continue;
    const v = make(m);
    return Object.assign({expr: expr.slice(0, m.index).trim(), on:true, ctr, pkts, bytes},
                         v, cmt?{cmt}:{});
  }
  /* no terminal verdict — a counting or logging rule that falls through.
     A bare `counter` is a legal rule, so an empty expr is not an error. */
  if(!expr && !ctr) return null;
  return {expr, verdict:"continue", implicit:true, on:true, ctr, pkts, bytes, ...(cmt?{cmt}:{})};
}

/* ── round-trip proof: re-emit each rule and compare to its source ── */
export const normalise = s => s.replace(/#\s*handle\s+\d+\s*$/,"")
                        .replace(/\bcounter\s+packets\s+\d+\s+bytes\s+\d+/,"counter")
                        .replace(/\s+/g," ").replace(/\s+;/g,";").replace(/;$/,"").trim();

export function roundTrip(text, parsed){
  const srcRules = [];
  let inChain = false, inSet = false;
  logicalLines(text).forEach(({text: line})=>{
    if(/^(set|map)\s+\S+\s*\{$/.test(line)){ inSet = true; return; }
    if(/^chain\s+\S+\s*\{$/.test(line)){ inChain = true; return; }
    if(/^\}\s*;?$/.test(line)){ if(inSet) inSet = false; else inChain = false; return; }
    if(!inChain || inSet) return;
    if(/^(type|policy|flags|comment)\s/.test(line)) return;
    srcRules.push(normalise(line));
  });

  const emitted = parsed.chains.flatMap(ch=>ch.rules.map(r=>
    normalise(ruleLine(r) + (r.cmt ? ` comment "${r.cmt}"` : ""))));

  return compare(srcRules, emitted);
}

/* ── lining the two files up ────────────────────────────────────────────
   By index, a source line that produced no output shifted every line after
   it: each then compared against its neighbour and reported as changed, so
   one lost line out of ten read as nine broken ones and named none of them.
   Align first, then report — a line that vanished is a line that vanished,
   and a line that came back different is its own, separate thing. */
function compare(src, out){
  /* the common case is two identical lists, and that needs no matrix */
  if(src.length === out.length && src.every((l, i) => l === out[i]))
    return { total: src.length, ok: src.length, diffs: [] };

  /* diffLines is O(n·m) in time and memory. Rulesets are lines, not bytes —
     a set of ten thousand elements is one line — so this is small in every
     real case; the cap is here so that a pathological one degrades to the old
     positional answer instead of asking for a gigabyte. */
  if(src.length > 4000 || out.length > 4000) return byIndex(src, out);

  const diffs = [];
  const rows = diffLines(src, out);
  let i = 0;
  for(let k = 0; k < rows.length; k++){
    const [sign, text] = rows[k];
    if(sign === " "){ i++; continue; }
    if(sign === "-"){
      /* a removal answered by an addition is one line that came back changed */
      const next = rows[k + 1];
      if(next && next[0] === "+"){ diffs.push({ i, src: text, out: next[1] }); k++; }
      else diffs.push({ i, src: text, out: "—" });
      i++;
    } else {
      diffs.push({ i, src: "—", out: text });
    }
  }
  /* `ok` counts source lines that came back as themselves */
  const lost = diffs.filter(d => d.src !== "—").length;
  return { total: src.length, ok: src.length - lost, diffs };
}

function byIndex(src, out){
  const diffs = [];
  const n = Math.max(src.length, out.length);
  for(let i=0;i<n;i++)
    if(src[i] !== out[i]) diffs.push({i, src:src[i]??"—", out:out[i]??"—"});
  return {total:src.length, ok:src.length-diffs.length, diffs};
}

/* ── the honest version of the same question ──────────────────────────────
   roundTrip answers "did every rule come back the same". That is a smaller
   claim than the import dialog was making with it: chain headers, sets, table
   flags and every object were outside its reach, so it could report a clean
   100% on a ruleset whose netdev chain had lost its device. This compares the
   whole file — parse it, emit it, and diff what we get against what we were
   given, line for line. */
const meaningful = lines => lines
  .map(l => normalise(typeof l === "string" ? l : l.text))
  .filter(l => l && l !== "flush ruleset" && !l.startsWith("#"));

export function verify(text){
  const parsed = parseNft(text);
  const src = meaningful(logicalLines(text));
  const out = meaningful(generate(parsed));

  return { ...compare(src, out), parsed };
}
