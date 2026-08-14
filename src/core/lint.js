/* Will nftables load this rule?
 *
 * A different question from the one the analyser asks. analyse() reads a
 * ruleset that works and says what is unwise about it — a shadowed rule, an
 * unrated log. This says whether `nft -f` would take the line at all, and
 * until now nothing did: the only answer came from `nft -c`, which needs a
 * Linux host within reach, and the rule that will not load is not a style
 * problem you get to fix later. It is the whole ruleset failing to apply.
 *
 * Everything here is findable in the text. It is deliberately not a parser for
 * nftables — that is nft's job and it is very good at it — but the handful of
 * mistakes below are the ones people actually make writing a rule by hand, and
 * catching them without leaving the editor is worth more than being complete. */
import { ruleLine } from "./model.js";

/* the transports a port match can hang off, plus `th`, which is any of them */
const TRANSPORT = /\b(tcp|udp|udplite|sctp|dccp|th)\s+[sd]port\b/;
const PORT = /\b[sd]port\b/;

/* the whole log statement, arguments and all — the one place a rule carries
   quoted text that is not the name of something */
const LOG_STMT = /\blog\b(?:\s+(?:prefix\s+"(?:[^"\\]|\\.)*"|level\s+\S+|group\s+\d+|snaplen\s+\d+|queue-threshold\s+\d+|flags\s+\S+))*/g;
const LOG_ARG = /\b(prefix\s+"|level\s+\w|group\s+\d|snaplen\s+\d|queue-threshold\s+\d)/;

const VERDICTS = /\b(accept|drop|reject|return|continue|masquerade)\b/g;
/* What each terminal verdict is allowed to carry after it. `reject with tcp
   reset` and `masquerade to :1024-65535` are one verdict each, not a verdict
   followed by stray text. */
const VERDICT_TAIL = {
  reject:     /^(with\s+\S.*)?$/,
  masquerade: /^(to\s+:\S+)?([\s,]*(random|fully-random|persistent))*$/,
};
const NEEDS_TARGET = /(?:^|\s)(jump|goto|dnat\s+to|snat\s+to)\s*$/;

const balanced = (s, open, close) => {
  /* quotes first: a brace inside a string is not a brace */
  let depth = 0, inStr = false;
  for(let i = 0; i < s.length; i++){
    const c = s[i];
    if(c === "\\"){ i++; continue; }
    if(c === '"'){ inStr = !inStr; continue; }
    if(inStr) continue;
    if(c === open) depth++;
    if(c === close) depth--;
    if(depth < 0) return false;
  }
  return depth === 0;
};
const evenQuotes = s => (s.replace(/\\./g, "").match(/"/g) || []).length % 2 === 0;

/* Strip strings before looking for keywords, so a log prefix of "accept " is
   not read as a verdict sitting in the middle of the rule. */
const bare = s => s.replace(/"(?:[^"\\]|\\.)*"/g, '""');
/* Strings and braced groups both blanked. A verdict map spells its verdicts
   inside the braces — `tcp dport vmap { 22 : accept, 80 : drop }` — and those
   are values, not the end of the rule. */
const outer = s => bare(s).replace(/\{[^{}]*\}/g, "{}");

const F = (code, en, es) => ({ code, level: "error", title: [en, es] });

/**
 * @param line  the rule as nft source, verdict and all
 * @param ctx   {chains, sets} — names that exist in the table this rule is in.
 *              Omit either and the names it uses are not checked, because a
 *              name you cannot resolve is not a name you can call wrong.
 */
export function lintRule(line, ctx = {}){
  const src = String(line || "").trim();
  const out = [];
  if(!src) return out;

  if(!evenQuotes(src))
    out.push(F("unbalanced",
      "Unterminated string — nft reads to the end of the line",
      "Cadena sin cerrar — nft lee hasta el final de la línea"));
  else if(!balanced(src, "{", "}") || !balanced(src, "(", ")"))
    out.push(F("unbalanced",
      "Unbalanced braces or brackets",
      "Llaves o paréntesis sin equilibrar"));

  const e = bare(src);

  if(LOG_ARG.test(e) && !/\blog\b/.test(e))
    out.push(F("orphan-log",
      "log arguments with no log statement to belong to",
      "argumentos de log sin una sentencia log a la que pertenecer"));

  if(/\bburst\b/.test(e) && !/\blimit rate\b/.test(e))
    out.push(F("orphan-burst",
      "burst with no limit rate to burst against",
      "burst sin un limit rate sobre el que aplicarse"));

  if(PORT.test(e) && !TRANSPORT.test(e))
    out.push(F("port-no-proto",
      "A port match needs a transport in front of it — tcp dport, not dport",
      "Una coincidencia de puerto necesita un transporte delante — tcp dport, no dport"));

  if(NEEDS_TARGET.test(e))
    out.push(F("no-target",
      "This verdict names something, and nothing was named",
      "Este veredicto nombra algo, y no se ha nombrado nada"));

  /* a verdict is terminal: anything after it, beyond what that verdict itself
     takes, is text nft has no room for */
  const o = outer(src);
  const last = [...o.matchAll(VERDICTS)].at(-1);
  if(last){
    /* nft allows a trailing `comment "…"` after the verdict — bare() left it as
       `comment ""`, and without allowing it, `... accept comment "x"` (a rule
       nft loads fine) was marked red. */
    const rest = o.slice(last.index + last[0].length).trim()
      .replace(/\bcomment\s+""\s*$/, "").trim();
    const tail = VERDICT_TAIL[last[1]];
    if(tail ? !tail.test(rest) : rest !== "")
      out.push(F("verdict-not-last",
        "A verdict ends the rule — this one has a match after it",
        "Un veredicto termina la regla — esta tiene una coincidencia después"));
  }

  /* Every jump on the line, and the name only.
     `\S+` swallowed the punctuation around it, so the commonest way of writing
     several jumps at once — `iifname vmap { "lan0" : jump zone_lan, "dmz0" :
     jump zone_dmz }` — reported `No chain called zone_lan,` about a chain that
     was right there. And without /g only the first was ever looked at, so in
     that same rule two of the three targets went unchecked: a jump to a chain
     that really is missing, in a verdict map, was silently fine. */
  if(Array.isArray(ctx.chains)){
    const said = new Set();
    for(const m of e.matchAll(/\b(?:jump|goto)\s+([A-Za-z_][\w.-]*)/g)){
      if(ctx.chains.includes(m[1]) || said.has(m[1])) continue;
      said.add(m[1]);
      out.push(F("unknown-chain",
        `No chain called ${m[1]} in this table`,
        `No hay ninguna cadena llamada ${m[1]} en esta tabla`));
    }
  }
  /* A flowtable is reached with `flow add @ft`, so `@` does not only mean a
     set — reported against the sets alone, every offload rule in every router
     ruleset came back as naming a set that does not exist. */
  if(Array.isArray(ctx.sets)){
    const named = [...ctx.sets, ...(ctx.flowtables || [])];
    for(const m of e.matchAll(/@([A-Za-z_]\w*)/g))
      if(!named.includes(m[1]))
        out.push(F("unknown-set",
          `Nothing called @${m[1]} in this table`,
          `No hay nada llamado @${m[1]} en esta tabla`));
  }

  /* The objects that are named in a statement rather than with an @. The set
     reference was checked and these were not, which is the same gap seen from
     the other side. */
  if(Array.isArray(ctx.objects)){
    /* Against the source, not the blanked copy: for these the quoted text is
       the name, and bare() exists precisely to hide quoted text. The one place
       stray quoted text comes from is a log prefix, so that goes instead. */
    const named = src.replace(LOG_STMT, " ");
    const NAMED = [
      [/\bcounter\s+name\s+"([^"]*)"/g,      "counter"],
      [/\bquota\s+name\s+"([^"]*)"/g,        "quota"],
      [/\bct\s+helper\s+set\s+"([^"]*)"/g,   "ct helper"],
      [/\bct\s+timeout\s+set\s+"([^"]*)"/g,  "ct timeout"],
      [/\bsynproxy\s+name\s+"([^"]*)"/g,     "synproxy"],
    ];
    for(const [re, kind] of NAMED)
      for(const m of named.matchAll(re))
        if(!ctx.objects.some(o => o.kind === kind && o.name === m[1]))
          out.push(F("unknown-object",
            `No ${kind} called ${m[1]} in this table`,
            `No hay ningún ${kind} llamado ${m[1]} en esta tabla`));
  }
  return out;
}

/* Every rule in the ruleset, with the names of its own table to check against.
   Returned in the shape analyse() uses so the two can be shown together. */
export function lintRuleset(model){
  const out = [];
  for(const ch of model.chains || []){
    const own = (model.objects || []).filter(o => o.table === ch.table);
    const ctx = {
      chains: (model.chains || []).filter(c => c.table === ch.table).map(c => c.id),
      sets: (model.sets || []).filter(s => !s.table || s.table === ch.table).map(s => s.n),
      flowtables: own.filter(o => o.kind === "flowtable").map(o => o.name),
      objects: own,
    };
    ch.rules.forEach((r, i) => {
      if(!r.on) return;
      /* the rule exactly as it will be written out, which is what nft reads */
      for(const f of lintRule(ruleLine(r), ctx)) out.push({ ...f, chain: ch, i });
    });
  }
  return out;
}

/* ── names nftables will not let you use ─────────────────────────────────
 *
 * `chain log { ... }` does not load. Neither does a set called `ct`, nor a
 * table called `ip`. nft's scanner turns these words into keywords before the
 * grammar ever gets to decide it is looking at a name, so the file dies with
 * `syntax error, unexpected log, expecting string` — and it dies at the
 * declaration, which takes the rest of the block down with it.
 *
 * This is the export path's version of the failure this project keeps finding
 * elsewhere: nothing was unreadable, so nothing was reported. The parser reads
 * the chain back, verify() calls the round trip exact, the generated file says
 * `round-trip safe` in its header, and nft refuses to load it.
 *
 * Quoting does not help — nft rejects a quoted name in a declaration too — so
 * there is nothing to fix on the way out. The name has to change, which means
 * the person who chose it has to be told.
 *
 * The list is measured, not remembered: each candidate was offered to nft 1.0.6
 * as a chain, a set and a table name, and these are the ones it refused. All
 * three kinds refuse exactly the same words. It is certainly not every keyword
 * nft has — a list built by hand never is — and that is the safe direction to
 * be wrong in, because a name missing from it costs a warning that was not
 * given, while a name wrongly on it would refuse one that works.
 *
 * Words that read like keywords and are *not* here are here on purpose:
 * `filter`, `nat`, `route`, `input`, `output`, `forward`, `prerouting`,
 * `postrouting`, `state`, `new`, `established`, `last`, `zone`, `name`, `to`,
 * `prefix`, `level`, `group`, `rate`, `burst`, `packets` and `bytes` all load
 * fine, because nft only treats them as keywords where one can appear. Nearly
 * every chain anyone writes is called one of the first eight.
 */
export const RESERVED = new Set(`accept add ah all arp bridge chain comment comp constant
continue counter cpu ct day dccp define delete device devices dnat drop dup dynamic elements
esp ether exists expires export fib flags flow flowtable fwd goto handle hook hour icmp icmpv6
igmp iif iifname iiftype include index inet insert interval ip ip6 ipsec jhash jump limit list
log map mark masquerade meta meter missing monitor netdev nftrace notrack numgen offload oif
oifname oiftype osf pkttype policy position priority queue quota random redirect reject rename
replace reset return rt rule ruleset sctp secmark set size snat socket symhash synproxy table
tcp th time timeout tproxy type udp udplite update vlan vmap xt`.trim().split(/\s+/));

/** the word nftables would choke on, or null — the name of a table is
    `family name`, and only the name half is the identifier */
export const reservedName = name => {
  const word = String(name || "").trim().split(/\s+/).pop();
  return RESERVED.has(word) ? word : null;
};

/* Every name the ruleset declares. Separate from lintRuleset() because these
   are not rules: a finding here points at a declaration, and has no rule index
   to go to. */
export function lintNames(model){
  const out = [];
  const seen = new Set();
  /* `es` carries its own article: "cadena" and "set" do not take the same one,
     and a sentence that gets it wrong reads as nobody having looked. */
  const check = (kind, es, name, where) => {
    const word = reservedName(name);
    if(!word || seen.has(kind + " " + word)) return;
    seen.add(kind + " " + word);
    out.push({
      code: "reserved-name", level: "error", kind, name: word, where,
      title: [`nftables keeps the word "${word}" for itself, so no ${kind} can be called that`,
              `nftables se reserva la palabra "${word}", así que ${es} puede llamarse así`],
    });
  };
  for(const tb of model.tables || []) check("table", "ninguna tabla", tb.name, tb.name);
  for(const ch of model.chains || []) check("chain", "ninguna cadena", ch.id, `${ch.table} / ${ch.id}`);
  for(const s of model.sets || []) check("set", "ningún set", s.n, s.table ? `${s.table} / ${s.n}` : s.n);
  for(const o of model.objects || []) check(o.kind, `ningún ${o.kind}`, o.name, `${o.table} / ${o.name}`);

  /* A flowtable with no devices is not an incomplete flowtable, it is a syntax
     error: nft answers `unexpected '}', expecting string` and takes the rest of
     the file with it. The object template in objects.js writes exactly that —
     `devices = { }` — on purpose, as a shape for the user to fill in, and
     nothing until now said what happens if they do not. The same trap as
     `quota over 1 gbytes`, which shipped in a template and which nft also
     refuses; found again while checking two new samples against nft 1.1.6
     before shipping them. */
  for(const o of model.objects || []){
    if(o.kind !== "flowtable") continue;
    const devices = (o.body || []).find(l => /^devices\s*=/.test(l.trim()));
    if(devices && /=\s*\{\s*\}\s*$/.test(devices.trim()))
      out.push({
        code: "flowtable-no-devices", level: "error", kind: "flowtable",
        name: o.name, where: `${o.table} / ${o.name}`,
        title: [`the flowtable "${o.name}" lists no devices, and nft refuses an empty list rather than ignoring it`,
                `el flowtable "${o.name}" no lista ningún dispositivo, y nft rechaza una lista vacía en vez de ignorarla`],
      });
  }
  return out;
}

/* ── what nft itself said ────────────────────────────────────────────────
 * Everything above is a reading of nftables. This is nftables, read back.
 *
 * `nft -c -f file` prints one line per complaint, in the shape
 *   /tmp/whatever.nft:6:1-2: Error: Could not process rule: Operation not supported
 * followed by the offending source line and a caret rule. The path is a
 * temporary nobody wants to see, and the carets are for a terminal, so what is
 * kept is the line number and what went wrong.
 */
export function readNftErrors(text){
  const out = [];
  for(const raw of String(text || "").split("\n")){
    if(!/:\s*Error:/.test(raw)) continue;
    const m = raw.match(/:(\d+):[\d-]*:\s*Error:\s*(.*)$/);
    out.push({ line: m ? +m[1] : null, message: (m ? m[2] : raw).trim() });
  }
  return out;
}
