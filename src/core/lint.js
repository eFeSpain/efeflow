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
    const rest = o.slice(last.index + last[0].length).trim();
    const tail = VERDICT_TAIL[last[1]];
    if(tail ? !tail.test(rest) : rest !== "")
      out.push(F("verdict-not-last",
        "A verdict ends the rule — this one has a match after it",
        "Un veredicto termina la regla — esta tiene una coincidencia después"));
  }

  if(Array.isArray(ctx.chains)){
    const m = e.match(/\b(?:jump|goto)\s+(\S+)/);
    if(m && !ctx.chains.includes(m[1]))
      out.push(F("unknown-chain",
        `No chain called ${m[1]} in this table`,
        `No hay ninguna cadena llamada ${m[1]} en esta tabla`));
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
