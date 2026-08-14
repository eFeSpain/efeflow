/* The rule editor: the object library, the properties panel, and every way a
 * rule is made, moved or removed on the canvas.
 *
 * Four sections of app.js that were always one screen. The library offers
 * what a rule can be made of — your ruleset reflected back, plus vocabularies
 * kept on this machine; select() is the one door into the properties panel,
 * and the canvas edits (add, duplicate, delete, reorder, drag, context menu,
 * keyboard) all funnel through edit() so every one of them is a labelled,
 * undoable step.
 *
 * select, openCtx and killCtx are provided to shell's late registry from
 * here — this module is where they are real; everywhere else holds the name.
 * Three calls go the other way and arrive late through provideEditor():
 * openChain and chSync belong to the chain dialog, paintCode to the code
 * pane, and neither screen has moved out yet.
 */
import { MODEL, R, UID, chainOf, VNAME, fmtN, fmtB, ruleLine } from "../core/model.js";
import { parseRule } from "../core/parse.js";
import { readExpr, editExpr, readLog, editLogParts, LOG_LEVELS } from "../core/expr.js";
import { lintRule } from "../core/lint.js";
import { catalogue, protoOf, OWNABLE, BUILT_IN, emptyVocabulary, TEMPLATES } from "../core/vocabulary.js";
import { tableNames, readTable } from "../core/tables.js";
import { interfaces, addresses } from "../core/mentions.js";
import { project } from "../core/project.js";
import { findings, modelChanged, onModelChange, onRender } from "../core/bus.js";
import { t } from "../i18n.js";
import { pushRule } from "../host.js";
import { asTauriTarget, describe } from "../target.js";
import * as native from "../native.js";
import { $, $$, esc, el, cssEsc, toast, highlight, go, provide } from "./shell.js";
import { UI } from "./state.js";
import { HOOK_X, renderChains, drawWires } from "./canvas.js";
import { edit, undo, redo, snapshot, pushHist, state as hist } from "./history.js";
import { findingsFor, tt } from "./findings.js";
import { runSim } from "./simulator.js";
import { REACH } from "./host.js";

/* The chain dialog and the code pane have not moved out yet; their three
   verbs arrive late, the way project-io receives openProject. */
const hooks = { openChain(){}, chSync(){}, paintCode(){} };
export const provideEditor = (h) => Object.assign(hooks, h);

/* ══ OBJECT LIBRARY ═════════════════════════════════════════════════════
   What you add to the vocabularies is kept on this machine, not in the
   project. A port you had to look up once should be there in the next project
   too, and without having saved anything — telnet is 23 whoever's firewall you
   are writing. The interfaces and networks in project.scratch are the opposite
   case: they describe the box these rules are for, so they travel with it. */
const VKEY = "efeflow.vocabulary";
let VOCAB = emptyVocabulary();

/* Synchronously from local storage so the first render has something, then
   from the file, which is the authority. The webview's storage is a leveldb
   blob — unreadable, unmergeable, and it does not leave the machine. */
try{
  const raw = localStorage.getItem(VKEY);
  if(raw) Object.assign(VOCAB, JSON.parse(raw));
}catch{ /* a corrupt entry is not worth a crash */ }

export const mergeVocab = text => {
  try{
    const o = JSON.parse(text);
    if(!o || typeof o !== "object") return false;
    for(const k of Object.keys(emptyVocabulary()))
      if(Array.isArray(o[k])) VOCAB[k] = o[k];
    return true;
  }catch{ return false; }
};

native.readSetting("vocabulary").then(text=>{
  if(text && mergeVocab(text)) renderLibrary();
  else if(VOCAB.services.length || VOCAB.protocols.length || VOCAB.helpers.length)
    vocabChanged();          /* first run after the move: carry the old store over */
}).catch(()=>{ /* browser, or no config directory */ });

export const ownOf = gl => VOCAB[OWNABLE[gl]?.key] ?? [];
export function vocabChanged(){
  const text = JSON.stringify(VOCAB, null, 2);
  try{ localStorage.setItem(VKEY, text); }catch{ /* private mode */ }
  native.writeSetting("vocabulary", text).catch(()=>{ /* read-only profile */ });
  renderLibrary();
}

const CH_ = () => t("chains","cadenas"), CH1 = () => t("chain","cadena"), RL_ = () => t("rules","reglas");
const LIB = () => [
  /* the tables and sets your ruleset has, not four invented ones */
  [t("Tables","Tablas"),"TB", (()=>{
     /* derived from every filing, not only from the chains: a table can exist
        holding nothing but a set, or nothing at all but a comment and a flag */
     const rows = tableNames(MODEL).map(n=>{
       const info = readTable(MODEL, n);
       return [n, info.dormant ? t("dormant","dormant")
                               : `${info.chains} ${info.chains===1?CH1():CH_()}`];
     });
     /* the fallback named a table called "inet filter" that nothing had
        created — the third flag marks a row as a note, not an object */
     return rows.length ? rows : [[t("no tables yet","aún sin tablas"), "", true]];
   })()],
  [t("Chains","Cadenas"),"CH",[[t("base chain","cadena base"),""],[t("regular chain","cadena regular"),""],["prerouting",""],["input",""],["forward",""],["output",""],["postrouting",""]]],
  /* maps have their own category below; listing them in both put @porthost on
     the shelf twice */
  ["Sets","SE", (()=>{
     const sets = MODEL.sets.filter(s=>(s.kind||"set") !== "map");
     return sets.length
       ? sets.map(s=>["@"+s.n, s.el.length>999 ? (s.el.length/1000).toFixed(1)+"k" : String(s.el.length)])
       : [[t("no sets yet","aún sin sets"),"",true]];
   })()],
  /* Sets were derived and maps were not: this listed a map called @port_fwd
     with three elements, which no ruleset here has ever contained. */
  ["Maps","MP", (()=>{
     const maps = MODEL.sets.filter(s=>s.kind === "map");
     return maps.length
       ? maps.map(s=>["@"+s.n, `${s.el.length} ${s.el.length===1?t("entry","entrada"):t("entries","entradas")}`])
       : [[t("no maps yet","aún sin maps"),"",true]];
   })()],
  /* Yours, both halves: the interfaces your rules already name, and the ones
     you have written down for the box you are working on. No invented list —
     an unchangeable placeholder is worse than an empty shelf. */
  [t("Interfaces","Interfaces"),"IF", (()=>{
     const used = interfaces();
     const kept = project.scratch.ifaces.filter(n=>!used.some(e=>e.name===n));
     return [
       ...used.map(e=>[e.name, `${e.rules} ${e.rules===1?t("rule","regla"):t("rules","reglas")}`]),
       ...kept.map(n=>[n, t("unused","sin usar")]),
     ];
   })()],
  [t("Networks","Redes"),"NW", (()=>{
     const used = addresses();
     const kept = project.scratch.networks.filter(n=>!used.some(a=>a.text===n));
     return [
       ...used.map(a=>[a.text, `${a.n} ${a.n===1?t("rule","regla"):t("rules","reglas")}`]),
       ...kept.map(n=>[n, t("unused","sin usar")]),
     ];
   })()],
  /* Seven services, seven protocols and three helpers, none of them editable,
     so the first thing anybody needed — ftp, telnet — sent them elsewhere. */
  [t("Services","Servicios"),"SV",
    catalogue(ownOf("SV")).map(s=>[s.n, `${s.p}/${s.proto}`])],
  [t("Protocols","Protocolos"),"PR",
    catalogue(ownOf("PR"), BUILT_IN.PR).map(p=>[p.n, ""])],
  [t("Connection states","Estados de conexión"),"CT",[["established",""],["related",""],["new",""],["invalid",""],["untracked",""],["ct status dnat",""]]],
  [t("Actions","Acciones"),"AC",[["accept",""],["drop",""],["reject with",""],["jump",""],["goto",""],["return",""],["continue",""]]],
  /* `redirect` on its own is a whole rule — it sends the packet to this
     machine on the port it arrived on — so it is not listed as needing a
     target it does not need. dnat and snat do, and theirs is left blank. */
  ["NAT","NT",[["dnat to",""],["snat to",""],["masquerade",""],["redirect",""]]],
  [t("Helpers","Helpers"),"HL",
    catalogue(ownOf("HL"), BUILT_IN.HL).map(h=>[h.n, `${h.p}/${h.proto}`])],
  /* nft vocabulary, untranslated like the rest of it — and the named counters
     are the ones this ruleset has, the way Sets and Maps are. `named counter`
     used to be a label that dropped a plain anonymous counter, which is the
     shape of thing this list was built to stop doing. */
  [t("Counters","Contadores"),"CN",[
    ["counter",""],
    ...MODEL.objects.filter(o=>o.kind==="counter").map(o=>[`counter name "${o.name}"`, o.name]),
    ["quota over",""],
  ]],
  [t("Meters","Medidores"),"ME",[["meter",""],["limit rate",""],["limit rate over",""]]],
  [t("Marks","Marcas"),"MK",[["meta mark set",""],["ct mark set",""],["meta priority",""]]],
  /* The counts here were invented and dropping one did nothing. They are real
     rule groups now, and the count is however many rules the group holds. */
  [t("Templates","Plantillas"),"TP",
    TEMPLATES.map(x=>[t(x.title.en, x.title.es), `${x.rules.length} ${RL_()}`])],
];
const libBody = $("#lib-body");
export function renderLibrary(){
  const open = $$(".cat",libBody).map(d=>d.open);
  libBody.innerHTML = "";
  LIB().forEach(([cat,gl,items],i)=>{
    const d = el("details","cat"); d.open = open.length ? open[i] : i<4;
    /* Two kinds of category, and they were indistinguishable: these four are
       your ruleset reflected back, the rest are constants to drag. */
    const derived = ["TB","CH","SE","MP","IF","NW"].includes(gl);
    d.dataset.kind = gl;
    /* Two kinds of list can be added to: the ones describing this box, and the
       vocabularies describing the world. The rest are closed by nftables' own
       grammar — there is no eighth verdict, and offering to invent one would
       emit a ruleset that does not load. Those are completed, not opened. */
    const ownable = gl === "IF" || gl === "NW" || !!OWNABLE[gl];
    d.innerHTML = `<summary>
        <svg class="ico sm tw" viewBox="0 0 24 24"><path d="m9 6 6 6-6 6"/></svg>
        <span class="nm">${esc(cat)}</span>
        ${derived?`<span class="derived" title="${esc(t("From your ruleset — right-click to rename everywhere",
                    "De tu ruleset — clic derecho para renombrar en todo"))}">·</span>`:""}
        ${ownable?`<button class="cat-add" data-add="${gl}" title="${esc(
            gl==="IF" ? t("Add an interface you plan to use","Añadir una interfaz que vas a usar")
          : gl==="NW" ? t("Add a network you work with","Añadir una red con la que trabajas")
                      : t("Add one — kept on this machine, in every project",
                          "Añadir uno — se guarda en esta máquina, en todos los proyectos"))}">+</button>`:""}
        <span class="ct">${items.filter(i=>!i[2]).length}</span></summary>
      <div class="cat-items">${items.map(([n,r,ph])=>
        `<div class="obj${ph?" ph":""}" draggable="${ph?"false":"true"}"><span class="gl">${gl}</span><span class="nm">${esc(n)}</span><span class="rf">${esc(r)}</span></div>`).join("")}</div>`;
    libBody.appendChild(d);
  });
}
renderLibrary();
onRender(renderLibrary);
/* the library mirrors the ruleset, so it has to follow it */
onModelChange(renderLibrary);
$("#lib-filter").addEventListener("input",e=>{
  const q = e.target.value.toLowerCase().trim();
  $$(".cat").forEach(c=>{
    let hits = 0;
    $$(".obj",c).forEach(o=>{ const m = !q || o.querySelector(".nm").textContent.toLowerCase().includes(q);
      o.style.display = m?"":"none"; if(m) hits++; });
    c.style.display = hits?"":"none"; if(q) c.open = true;
  });
});


/* ══ SELECTION + PROPERTIES ════════════════════════════════════════════ */
export const EMPTY = () => `
  <div class="empty-props">
    <div class="art"><svg viewBox="0 0 24 24" style="width:28px;height:28px;stroke:currentColor;fill:none;stroke-width:1.4;stroke-linecap:round">
      <path d="M4 20h4L19 9a2.8 2.8 0 0 0-4-4L4 16z"/><path d="M14 6l4 4"/></svg></div>
    <h4>${t("Nothing selected","Nada seleccionado")}</h4>
    <p>${t("Pick a rule on the canvas — or a line in the generated code — to edit its matches, verdict and counters here.",
           "Elige una regla en el lienzo — o una línea del código generado — para editar aquí sus coincidencias, veredicto y contadores.")}</p>
    <div style="display:flex;gap:6px;flex-wrap:wrap;justify-content:center">
      <span class="chip">${t("click a rule","clic en una regla")}</span><span class="chip">${t("⇧ click to multi-select","⇧ clic para multi-selección")}</span>
    </div>
  </div>`;

/* core/expr.js owns both halves of this now: what an expression says, and how
   to change one thing it says without touching the rest. */
const parse = readExpr;
const opt = (v,list) => list.map(o=>`<option${o===v?" selected":""}>${o}</option>`).join("");

/* Which verdicts name something, and what that something looks like. The
   target field used to appear only when the rule already carried one, so
   switching a rule to `jump` left nowhere to say where — and the rule emitted
   `jump undefined`, which is a ruleset that does not load. */
const TARGET_OF = {
  jump:     () => t("chain name","nombre de cadena"),
  goto:     () => t("chain name","nombre de cadena"),
  dnat:     () => "10.0.0.5:8080",
  snat:     () => t("address, or masquerade","dirección, o masquerade"),
  redirect: () => t(":port — blank keeps the original",":puerto — vacío conserva el original"),
  reject:   () => "icmp type admin-prohibited",
};

UI.sel = null;
export function select(chainId, i, fromCode){
  UI.sel = {chainId,i};
  const ch = chainOf(chainId);
  /* the chain may be gone — a fix deleted it, or the whole ruleset was
     replaced while a deferred select was still queued */
  if(!ch || !ch.rules[i]){ UI.sel = null; $("#props-body").innerHTML = EMPTY(); return; }
  const r = ch.rules[i];
  $$(".rule").forEach(x=>x.classList.toggle("sel", x.dataset.chain===chainId && +x.dataset.i===i));
  $$(".chain").forEach(x=>x.classList.toggle("focus", x.dataset.chain===chainId));

  $$("#codeout .ln, #codeout2 .ln").forEach(l=>{
    const hit = l.dataset.chain===chainId && +l.dataset.i===i;
    l.classList.toggle("hl",hit);
    if(hit && !fromCode) l.scrollIntoView({block:"center",behavior:"smooth"});
  });
  if(fromCode){
    const row = $(`.rule[data-chain="${cssEsc(chainId)}"][data-i="${i}"]`);
    if(row){ go("editor"); row.scrollIntoView({block:"center",inline:"center",behavior:"smooth"}); }
  }
  const p = parse(r.expr);
  const lg = readLog(r.expr);
  $("#props-body").innerHTML = `
    <div class="rule-hero">
      <div class="top">
        <span class="pill v-${r.verdict}"><span class="sw"></span>${VNAME[r.verdict]}</span>
        ${r.handle ? `<button class="chip" id="rule-push" title="${esc(t(
            "The handle this rule had on the host it was read from. Click to change just this rule there, instead of replacing the whole table.",
            "El handle que tenía esta regla en el host del que se leyó. Púlsalo para cambiar solo esta regla allí, en vez de reemplazar la tabla entera."))}"
          >handle ${r.handle}</button>` : ""}
        <div style="flex:1"></div>
        <span class="sw-toggle${r.on?" on":""}" id="rule-on" title="${t("Enable rule","Activar la regla")}"></span>
      </div>
      <div class="path">${esc(ch.table)} / ${esc(ch.id)} · ${t("position","posición")} ${i+1} ${t("of","de")} ${ch.rules.length}</div>
      <!-- The rule as nft source, and editable as nft source. The fields below
           cover the nine things this panel models; nftables says a great deal
           more than nine things, and until this existed there was no way to
           write any of the rest — only to import it and hope. -->
      <div class="expr-big" id="f-raw" contenteditable="plaintext-only" spellcheck="false"
           role="textbox" aria-label="${esc(t("Rule source","Código de la regla"))}"
           >${highlight(ruleLine(r))}</div>
      <div id="f-raw-lint"></div>
      ${findingsFor(chainId,i).map(f=>{
        const c = f.sev==="error" ? ["250,90,90","--v-drop"] : ["240,193,60","--warn"];
        return `<div style="display:flex;gap:8px;align-items:flex-start;margin-top:9px;padding:9px 10px;
                     border-radius:var(--r-sm);background:rgba(${c[0]},.08);border:1px solid rgba(${c[0]},.22)">
          <svg class="ico sm" style="color:var(${c[1]});margin-top:1px;flex:none" viewBox="0 0 24 24"><path d="M12 9v4m0 4h.01M10.3 3.9 2.4 17a2 2 0 0 0 1.7 3h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/></svg>
          <div style="flex:1">
            <div style="font-size:11.5px;color:var(--t1);line-height:1.45;font-weight:500">${esc(tt(f.title))}</div>
            ${f.fix?`<button class="tb" style="height:22px;margin-top:6px;padding:0 8px;color:var(${c[1]})"
               data-fix="${findings.list.indexOf(f)}">${tt(f.fix.label)}</button>`:""}
          </div></div>`;
      }).join("")}
    </div>

    <div class="stat-strip">
      <div><div class="lbl">${t("Packets","Paquetes")}</div><div class="v">${fmtN(r.pkts)}</div></div>
      <div><div class="lbl">Bytes</div><div class="v">${fmtB(r.bytes)}</div></div>
      <div><div class="lbl">${t("Position cost","Coste de posición")}</div><div class="v">${i+1}<span style="font-size:11px;color:var(--t4)"> ev</span></div></div>
    </div>

    <details class="pgrp" open><summary><svg class="ico sm tw" viewBox="0 0 24 24"><path d="m9 6 6 6-6 6"/></svg><span class="lbl">${t("Match","Coincidencia")}</span><span class="chip">${Object.values(p).filter(Boolean).length}</span></summary>
      <div class="pgrp-body">
        <div class="fld"><span class="lbl">${t("Protocol","Protocolo")}</span><select id="f-proto">${opt(p.proto,["","tcp","udp","icmp","icmpv6","sctp","esp","ah"])}</select></div>
        <div class="row2">
          <div class="fld"><span class="lbl">${t("Source address","Dirección origen")}</span><input type="text" id="f-saddr" value="${esc(p.saddr)}" placeholder="${t("any","cualquiera")}"></div>
          <div class="fld"><span class="lbl">${t("Source port","Puerto origen")}</span><input type="text" id="f-sport" value="${esc(p.sport)}" placeholder="${t("any","cualquiera")}"></div>
        </div>
        <div class="row2">
          <div class="fld"><span class="lbl">${t("Dest. address","Dirección destino")}</span><input type="text" id="f-daddr" value="${esc(p.daddr)}" placeholder="${t("any","cualquiera")}"></div>
          <div class="fld"><span class="lbl">${t("Dest. port","Puerto destino")}</span><input type="text" id="f-dport" value="${esc(p.dport)}" placeholder="${t("any","cualquiera")}"></div>
        </div>
        <div class="row2">
          <div class="fld"><span class="lbl">${t("Input interface","Interfaz entrada")}</span>
            <input type="text" id="f-iif" list="dl-ifaces" value="${esc(p.iif)}" placeholder="${t("any","cualquiera")}" spellcheck="false"></div>
          <div class="fld"><span class="lbl">${t("Output interface","Interfaz salida")}</span>
            <input type="text" id="f-oif" list="dl-ifaces" value="${esc(p.oif)}" placeholder="${t("any","cualquiera")}" spellcheck="false"></div>
        </div>
        <div class="fld"><span class="lbl">${t("Conntrack state","Estado de conntrack")}</span>
          <div style="display:flex;gap:4px;flex-wrap:wrap" id="f-state">
            ${["new","established","related","invalid","untracked"].map(s=>
              `<button class="chip" data-ct="${s}" style="${p.state.split(",").includes(s)?"color:var(--aqua);border-color:var(--aqua-line);background:var(--aqua-wash)":""}">${s}</button>`).join("")}
          </div>
        </div>
        <div class="row2">
          <div class="fld"><span class="lbl">${t("ICMP type","Tipo ICMP")}</span>
            <input type="text" id="f-icmptype" value="${esc(p.icmptype)}" placeholder="${t("any","cualquiera")} · echo-request" spellcheck="false"></div>
          <div class="fld"><span class="lbl">${t("TCP flags","Flags TCP")}</span>
            <input type="text" id="f-tcpflags" value="${esc(p.tcpflags)}" placeholder="${t("any","cualquiera")} · syn / syn,ack" spellcheck="false"></div>
        </div>
        <div class="fld"><span class="lbl">${t("Firewall mark","Marca firewall")}</span>
          <input type="text" id="f-metamark" value="${esc(p.metamark)}" placeholder="${t("any","cualquiera")} · 0x1" spellcheck="false"></div>
      </div>
    </details>

    <details class="pgrp" open><summary><svg class="ico sm tw" viewBox="0 0 24 24"><path d="m9 6 6 6-6 6"/></svg><span class="lbl">${t("Verdict","Veredicto")}</span></summary>
      <div class="pgrp-body">
        <div class="fld"><span class="lbl">${t("Action","Acción")}</span><select id="f-verdict">${opt(r.verdict,["accept","drop","reject","jump","goto","dnat","snat","redirect","log","return","continue"])}</select></div>
        ${TARGET_OF[r.verdict]?`<div class="fld"><span class="lbl">${t("Target","Destino")}</span>
          <input type="text" id="f-to" value="${esc(r.to||"")}" placeholder="${esc(TARGET_OF[r.verdict]())}"
            ${r.verdict==="jump"||r.verdict==="goto"?'list="dl-chains"':""}>
          <datalist id="dl-chains">${MODEL.chains.filter(c=>c.table===ch.table && c!==ch)
            .map(c=>`<option value="${esc(c.id)}">`).join("")}</datalist></div>`:""}
        <div class="inline"><span class="lbl">${t("Count packets","Contar paquetes")}</span>
          <span class="sw-toggle${r.ctr?" on":""}" id="f-ctr"></span></div>
        <div class="inline"><span class="lbl">${t("Log matches","Registrar coincidencias")}</span>
          <span class="sw-toggle${p.log?" on":""}" id="f-log"></span></div>
        ${lg.on?(lg.group
          ? `<div class="fld"><span class="lbl">${t("Log prefix","Prefijo de log")}</span>
              <input type="text" id="f-logprefix" value="${esc(lg.prefix)}" placeholder="${t("none","ninguno")} · drop-ssh " spellcheck="false">
              <span class="hint" style="font-size:11px;color:var(--t4)">${t(`logs to nflog group ${lg.group} — no syslog level`,`registra al grupo nflog ${lg.group} — sin nivel de syslog`)}</span></div>`
          : `<div class="row2">
              <div class="fld"><span class="lbl">${t("Log prefix","Prefijo de log")}</span>
                <input type="text" id="f-logprefix" value="${esc(lg.prefix)}" placeholder="${t("none","ninguno")} · drop-ssh " spellcheck="false"></div>
              <div class="fld"><span class="lbl">${t("Log level","Nivel de log")}</span>
                <select id="f-loglevel">${opt(lg.level,["",...LOG_LEVELS])}</select></div>
            </div>`):""}
      </div>
    </details>

    <details class="pgrp"${p.limit?" open":""}><summary><svg class="ico sm tw" viewBox="0 0 24 24"><path d="m9 6 6 6-6 6"/></svg><span class="lbl">${t("Rate limit","Límite de tasa")}</span>${p.limit?`<span class="chip">${esc(p.limit)}</span>`:""}</summary>
      <div class="pgrp-body">
        <div class="row2">
          <div class="fld"><span class="lbl">${t("Rate","Tasa")}</span>
            <input type="text" id="f-limit" value="${esc(p.limit)}" placeholder="${t("no limit","sin límite")} · 5/second"></div>
          <div class="fld"><span class="lbl">${t("Burst","Ráfaga")}</span>
            <input type="text" id="f-burst" value="${esc(p.burst)}" placeholder="${t("none","ninguna")} · 10"></div>
        </div>
        <div class="inline"><span class="lbl">${t("Invert (rate over)","Invertir (rate over)")}</span>
          <span class="sw-toggle${p.over?" on":""}" id="f-over"></span></div>
      </div>
    </details>

    <details class="pgrp" open><summary><svg class="ico sm tw" viewBox="0 0 24 24"><path d="m9 6 6 6-6 6"/></svg><span class="lbl">${t("Comment","Comentario")}</span></summary>
      <div class="pgrp-body">
        <textarea id="f-cmt" rows="2" placeholder="${t("Why does this rule exist?","¿Por qué existe esta regla?")}">${esc(r.cmt||"")}</textarea>
        <div class="inline"><span class="lbl">${t("Priority within chain","Prioridad en la cadena")}</span>
          <div style="display:flex;gap:3px">
            <button class="tb icon" style="width:24px;height:24px" data-move="-1" title="${t("Move up","Subir")}"><svg class="ico sm" viewBox="0 0 24 24"><path d="m6 15 6-6 6 6"/></svg></button>
            <button class="tb icon" style="width:24px;height:24px" data-move="1" title="${t("Move down","Bajar")}"><svg class="ico sm" viewBox="0 0 24 24"><path d="m6 9 6 6 6-6"/></svg></button>
          </div>
        </div>
      </div>
    </details>`;

  /* live two-way binding — edit a field, the generated code re-emits.
     The patch only carries the fields the panel is actually showing; every
     statement it has never heard of is left where it is. */
  const rebuild = (extra = {})=>{
    const patch = {...extra};
    for(const k of ["proto","saddr","daddr","sport","dport","iif","oif","icmptype","tcpflags","metamark"]){
      const f = $("#f-"+k);
      if(f) patch[k] = f.value.trim();
    }
    r.expr = editExpr(r.expr, patch);
    /* a port typed into a rule that never named a transport gets one, and the
       panel says so rather than doing it behind the field */
    const sel = $("#f-proto");
    if(sel && !sel.value) sel.value = readExpr(r.expr).proto;
    const vd = $("#f-verdict"); if(vd) r.verdict = vd.value;
    const to = $("#f-to");      if(to) r.to = to.value.trim();
    const cm = $("#f-cmt");     if(cm) r.cmt = cm.value.trim();
    renderChains(); hooks.paintCode(); drawWires(); modelChanged();
    $$(".rule").forEach(x=>x.classList.toggle("sel", x.dataset.chain===chainId && +x.dataset.i===i));
    $$(".chain").forEach(x=>x.classList.toggle("focus", x.dataset.chain===chainId));
    $(".expr-big").innerHTML = highlight(ruleLine(r));
    $$("#codeout .ln, #codeout2 .ln").forEach(l=>
      l.classList.toggle("hl", l.dataset.chain===chainId && +l.dataset.i===i));
  };
  /* Typing gives a live preview with no history entry; the change lands in
     history once, on blur — so undo steps are edits, not keystrokes. */
  ["f-saddr","f-daddr","f-sport","f-dport","f-cmt","f-proto","f-iif","f-oif","f-verdict","f-to",
   "f-limit","f-burst","f-icmptype","f-tcpflags","f-metamark"]
    .forEach(id=>{
      const n = $("#"+id); if(!n) return;
      n.addEventListener("focus", ()=>{ hist.pending = snapshot(); });
      const apply = () => rebuild({
        limit: $("#f-limit")?.value.trim(),
        burst: $("#f-burst")?.value.trim(),
      });
      n.addEventListener("input", apply);
      n.addEventListener("change", ()=>{
        apply();
        if(hist.pending!==null){ pushHist(hist.pending, t("rule edit","edición de regla")); hist.pending = null; }
        /* the verdict decides which fields belong on the panel — a jump needs
           somewhere to jump to, and an accept has nowhere to put one */
        if(id==="f-verdict") select(chainId, i);
      });
    });

  /* ── the rule as nft source ──────────────────────────────────────────
     The fields cover nine things. This covers nftables. Highlighting is
     dropped while the caret is in there — re-rendering the markup under a
     caret on every keystroke is how contenteditable ruins an editor — and put
     back on the way out. */
  const raw = $("#f-raw");
  if(raw){
    const ctx = () => ({
      chains: MODEL.chains.filter(c=>c.table===ch.table).map(c=>c.id),
      sets:   MODEL.sets.filter(s=>!s.table || s.table===ch.table).map(s=>s.n),
    });
    const svg = `<svg class="ico sm" viewBox="0 0 24 24"><path d="M12 9v4m0 4h.01M10.3 3.9 2.4 17a2 2 0 0 0 1.7 3h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/></svg>`;
    const showLint = text => {
      const found = lintRule(text, ctx());
      /* A line nft cannot read is its own finding, and the loudest one: the box
         used to swallow it without a word. */
      const unreadable = !!text && !parseRule(text);
      const rows = unreadable
        ? [t("nftables cannot read this line — the rule is left as it was until it can.",
             "nftables no puede leer esta línea — la regla se queda como estaba hasta que pueda.")]
        : [];
      rows.push(...found.map(f=>tt(f.title)));
      $("#f-raw-lint").innerHTML = rows.map(m=>
        `<div class="raw-lint">${svg}<span>${esc(m)}</span></div>`).join("");
      raw.classList.toggle("bad", unreadable || found.length > 0);
    };
    showLint(ruleLine(r));

    raw.addEventListener("focus", ()=>{
      hist.pending = snapshot();
      /* Normally show the rule as plain text under the caret. But when the box
         is holding an edit nft could not read, keep it — the flag was so it
         could be fixed, not retyped. */
      const held = raw.textContent.trim();
      if(!(raw.classList.contains("bad") && held && held !== ruleLine(r)))
        raw.textContent = ruleLine(r);
    });
    raw.addEventListener("input", ()=> showLint(raw.textContent.trim()));
    raw.addEventListener("keydown", e=>{
      if(e.key === "Enter"){ e.preventDefault(); raw.blur(); }
      if(e.key === "Escape"){ e.preventDefault(); raw.textContent = ruleLine(r); raw.blur(); }
    });
    raw.addEventListener("blur", ()=>{
      const text = raw.textContent.trim();
      if(!text || text === ruleLine(r)){
        /* unchanged, or emptied to nothing — a rule is not deleted by
           clearing the box, which would be a very expensive way to miss */
        raw.innerHTML = highlight(ruleLine(r));
        showLint(ruleLine(r));
        hist.pending = null;
        return;
      }
      const next = parseRule(text);
      if(!next){
        /* Changed, not empty, and nft cannot read it. This used to snap the box
           back to the old rule and drop the typed line without a word — a novel
           construct one character off simply vanished. Keep what was typed and
           flag it; focus keeps it too, and Esc still restores the original. */
        raw.textContent = text;
        showLint(text);
        hist.pending = null;
        return;
      }
      /* The line is the rule. What the line cannot carry is kept: whether the
         rule is enabled, its comment, and the handle.

         The handle used to go, on the grounds that `nft replace` did not keep
         it either. Measured on nft 1.1.3, and it does: a rule replaced at
         handle 4 is still handle 4 afterwards. Only its counters restart.
         Dropping it cost three things at once — the rule stopped pairing with
         its own copy on the host, so the apply diff showed an edit as a
         deletion and an unrelated addition; the drift warning then read that
         deletion as somebody else having added a rule since you looked, which
         it was not; and the surgical apply had to express one edit as a delete
         and an insert instead of the one replace nftables offers.
         The counters do go: they described the rule as it was. */
      const keep = { on: r.on, ...(r.cmt !== undefined ? { cmt: r.cmt } : {}),
                     ...(r.handle !== undefined ? { handle: r.handle } : {}) };
      hist.pending = null;                       /* edit() records this one itself */
      edit(t("edit rule source","editar el código de la regla"), ()=>{
        for(const k of Object.keys(r)) delete r[k];
        Object.assign(r, next, keep);
      });
      select(chainId, i);
    });
  }

  /* Controls that are not text fields. Each of these looked like a control and
     did nothing at all: the conntrack chips, both toggles under the verdict,
     and the whole rate-limit group were painted from the rule and wired to
     no handler. */
  $$("#f-state [data-ct]").forEach(b=>b.addEventListener("click",()=>{
    const have = readExpr(r.expr).state.split(",").map(x=>x.trim()).filter(Boolean);
    const s = b.dataset.ct;
    const next = have.includes(s) ? have.filter(x=>x!==s) : [...have, s];
    edit(t("conntrack state","estado de conntrack"),
         ()=>{ r.expr = editExpr(r.expr, {state: next.join(",")}); }, true);
  }));
  $("#f-ctr")?.addEventListener("click", ()=>
    edit(r.ctr ? t("stop counting","dejar de contar") : t("count packets","contar paquetes"),
         ()=>{ r.ctr = !r.ctr; if(!r.ctr){ r.pkts = 0; r.bytes = 0; } }, true));
  $("#f-log")?.addEventListener("click", ()=>{
    const on = readExpr(r.expr).log;
    edit(on ? t("stop logging","dejar de registrar") : t("log matches","registrar coincidencias"),
         ()=>{ r.expr = editExpr(r.expr, {log: !on}); }, true);
  });
  $("#f-over")?.addEventListener("click", ()=>{
    const q = readExpr(r.expr);
    edit(t("invert rate limit","invertir límite de tasa"),
         ()=>{ r.expr = editExpr(r.expr, {limit: q.limit || "5/second", over: !q.over}); }, true);
  });

  /* The log prefix and level ride on the log statement the toggle turned on;
     each leaves the other, and everything else in the statement, alone. Prefix
     is a text field — live preview, one history step on blur, like the rest;
     level is a discrete pick, so it lands in one go. */
  const lp = $("#f-logprefix");
  if(lp){
    lp.addEventListener("focus", ()=>{ hist.pending = snapshot(); });
    const apply = ()=>{ r.expr = editLogParts(r.expr, { prefix: lp.value }); rebuild(); };
    lp.addEventListener("input", apply);
    lp.addEventListener("change", ()=>{
      apply();
      if(hist.pending!==null){ pushHist(hist.pending, t("log prefix","prefijo de log")); hist.pending = null; }
    });
  }
  $("#f-loglevel")?.addEventListener("change", e=>
    edit(t("log level","nivel de log"),
         ()=>{ r.expr = editLogParts(r.expr, { level: e.target.value }); }, true));

  /* Changing one rule where it runs, rather than replacing the table it is in
     to change one line. host.js re-reads the chain first and refuses if the
     host no longer agrees about it — a handle is a position in somebody else's
     kernel, and acting on a stale one deletes a rule you never looked at. */
  $("#rule-push")?.addEventListener("click", async ()=>{
    if(!REACH?.ok){ toast(t(`No host to change — ${REACH?.why||""}`,
                            `Ninguna máquina que cambiar — ${REACH?.why||""}`)); return; }
    const res = await pushRule({model: MODEL, chain: ch, index: i,
                                op: "replace", target: asTauriTarget()});
    if(res.ok){
      toast(t(`Rule ${i+1} replaced on ${describe()} · handle ${res.handle}`,
              `Regla ${i+1} reemplazada en ${describe()} · handle ${res.handle}`));
      return;
    }
    toast(res.error === "unaddressable"
      ? t(`${describe()} no longer agrees about this chain — re-read it first`,
          `${describe()} ya no coincide en esta cadena — reléelo primero`)
      : t(`nft refused it — ${res.error}`, `nft lo rechazó — ${res.error}`));
  });

  const onT = $("#rule-on");
  if(onT) onT.addEventListener("click",()=>
    edit(r.on ? t("disable rule","desactivar regla") : t("enable rule","activar regla"),
         ()=>{ r.on = !r.on; }, true));

  $$("[data-move]", $("#props-body")).forEach(b=>b.addEventListener("click",()=>{
    const d = +b.dataset.move, j = i + d;
    if(j < 0 || j >= ch.rules.length) return;
    edit(t("reorder rule","reordenar regla"), ()=>{
      const [m] = ch.rules.splice(i,1); ch.rules.splice(j,0,m);
    });
    select(chainId, j);
  }));
}
$("#props-body").innerHTML = EMPTY();
document.addEventListener("click",e=>{
  const row = e.target.closest(".rule");
  if(row) select(row.dataset.chain, +row.dataset.i);
});
onRender(()=>{
  if(UI.sel) select(UI.sel.chainId, UI.sel.i);
  else $("#props-body").innerHTML = EMPTY();
});
/* Open on something real rather than a hard-coded chain that an imported or
   empty ruleset will not have. */
setTimeout(()=>{
  if(UI.sel) return;
  const ch = MODEL.chains.find(c=>c.hook==="input" && c.rules.length) ||
             MODEL.chains.find(c=>c.rules.length);
  if(ch) select(UID(ch), Math.min(4, ch.rules.length-1));
},400);


/* ══ CANVAS EDITING ═════════════════════════════════════════════════════ */

/* ── add / duplicate / delete ── */
function addRule(chainId){
  const ch = chainOf(chainId);
  edit(t("add rule","añadir regla"), ()=>{
    ch.rules.push(R("", ch.policy==="drop" ? "accept" : "drop", {pkts:0,bytes:0}));
  });
  select(chainId, ch.rules.length-1);
  const row = $(`.rule[data-chain="${cssEsc(chainId)}"][data-i="${ch.rules.length-1}"]`);
  if(row) row.scrollIntoView({block:"center",behavior:"smooth"});
  const f = $("#f-dport"); if(f) f.focus();
}
function duplicateRule(chainId,i){
  const ch = chainOf(chainId);
  edit(t("duplicate rule","duplicar regla"), ()=>{
    ch.rules.splice(i+1, 0, Object.assign({}, ch.rules[i], {pkts:0, bytes:0}));
  });
  select(chainId, i+1);
}
function deleteRule(chainId,i){
  const ch = chainOf(chainId), line = ruleLine(ch.rules[i]);
  edit(t("delete rule","eliminar regla"), ()=>{ ch.rules.splice(i,1); });
  toast(t("Deleted ","Eliminada ")+`«${line}» — Ctrl+Z`);
}
function moveRule(chainId,i,j){
  const ch = chainOf(chainId);
  if(j<0 || j>=ch.rules.length || i===j) return;
  edit(t("reorder rule","reordenar regla"), ()=>{
    const [m] = ch.rules.splice(i,1); ch.rules.splice(j,0,m);
  });
  select(chainId, j);
}

document.addEventListener("click",e=>{
  const add = e.target.closest(".addrule");
  if(add) addRule(add.closest(".chain").dataset.chain);
});

/* ── context menu ── */
let ctxEl = null;
export const killCtx = ()=>{ if(ctxEl){ ctxEl.remove(); ctxEl = null; } };
document.addEventListener("click", killCtx, true);
document.addEventListener("scroll", killCtx, true);
document.addEventListener("keydown", e=>{ if(e.key==="Escape") killCtx(); });

export function openCtx(x, y, items){
  killCtx();
  ctxEl = el("div","ctx glass");
  ctxEl.innerHTML = items.map(it => it==="-" ? "<hr>" :
    `<button data-act="${it[0]}"${it[3]?' class="danger"':""}>
       <svg class="ico sm" viewBox="0 0 24 24"><path d="${it[2]}"/></svg>
       <span>${it[1]}</span>${it[4]?`<span class="k">${it[4]}</span>`:""}</button>`).join("");
  document.body.appendChild(ctxEl);
  const w = ctxEl.offsetWidth, h = ctxEl.offsetHeight;
  ctxEl.style.left = Math.min(x, window.innerWidth  - w - 8) + "px";
  ctxEl.style.top  = Math.min(y, window.innerHeight - h - 8) + "px";
  return ctxEl;
}

document.addEventListener("contextmenu", e=>{
  const row = e.target.closest(".rule");
  const chainCard = e.target.closest(".chain");
  if(!row && !chainCard) return;
  e.preventDefault();

  if(row){
    const cid = row.dataset.chain, i = +row.dataset.i, r = chainOf(cid).rules[i];
    select(cid, i);
    const m = openCtx(e.clientX, e.clientY, [
      ["dup",  t("Duplicate","Duplicar"),            "M9 9h12v12H9zM5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1", false, "Ctrl D"],
      ["tog",  r.on ? t("Disable","Desactivar") : t("Enable","Activar"), "M12 3v9M7 6a8 8 0 1 0 10 0"],
      "-",
      ["up",   t("Move up","Subir"),                 "m6 15 6-6 6 6", false, "Alt ↑"],
      ["down", t("Move down","Bajar"),               "m6 9 6 6 6-6", false, "Alt ↓"],
      "-",
      ["copy", t("Copy nft line","Copiar línea nft"),"M9 9h12v12H9zM5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1"],
      ["del",  t("Delete","Eliminar"),               "M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13", true, "Del"],
    ]);
    m.addEventListener("click", ev=>{
      const a = ev.target.closest("[data-act]"); if(!a) return;
      const act = a.dataset.act;
      if(act==="dup")  duplicateRule(cid,i);
      if(act==="del")  deleteRule(cid,i);
      if(act==="up")   moveRule(cid,i,i-1);
      if(act==="down") moveRule(cid,i,i+1);
      if(act==="tog")  edit(r.on?t("disable rule","desactivar regla"):t("enable rule","activar regla"), ()=>{ r.on=!r.on; }, true);
      if(act==="copy"){ navigator.clipboard?.writeText(ruleLine(r)); toast(t("Copied to clipboard","Copiado al portapapeles")); }
      killCtx();
    });
    return;
  }

  const cid = chainCard.dataset.chain;
  const m = openCtx(e.clientX, e.clientY, [
    ["add",  t("Add rule","Añadir regla"), "M12 5v14M5 12h14", false, "Ctrl ↵"],
    ["new",  t("New chain…","Cadena nueva…"), "m9 6 6 6-6 6", false, "Ctrl ⇧ N"],
    "-",
    ["props",t("Chain properties…","Propiedades de la cadena…"), "M4 20h4L19 9a2.8 2.8 0 0 0-4-4L4 16z"],
    ["sim",  t("Simulate through this chain","Simular por esta cadena"), "M5 3v18l15-9z"],
    "-",
    ["del",  t("Delete chain…","Eliminar cadena…"), "M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13", true],
  ]);
  m.addEventListener("click", ev=>{
    const a = ev.target.closest("[data-act]"); if(!a) return;
    if(a.dataset.act==="add")   addRule(cid);
    if(a.dataset.act==="new")   hooks.openChain(null);
    if(a.dataset.act==="props") hooks.openChain(cid);
    if(a.dataset.act==="del"){  hooks.openChain(cid); $("#ch-delete").click(); }
    if(a.dataset.act==="sim"){  go("sim"); runSim(); }
    killCtx();
  });
});

/* ── keyboard ── */
document.addEventListener("keydown", e=>{
  /* not always an element, and this runs on every keystroke — an exception
     here took every shortcut registered below it with it */
  const typing = e.target?.closest?.("input, textarea, select");
  const mod = e.ctrlKey || e.metaKey;

  if(mod && e.key.toLowerCase()==="z" && !e.shiftKey){ e.preventDefault(); undo(); return; }
  if(mod && (e.key.toLowerCase()==="y" || (e.shiftKey && e.key.toLowerCase()==="z"))){ e.preventDefault(); redo(); return; }
  /* rule shortcuts belong to the editor canvas only */
  if(typing || !UI.sel || !$("#s-editor").classList.contains("on")) return;

  const ch = chainOf(UI.sel.chainId);
  if(e.key==="Delete" || e.key==="Backspace"){ e.preventDefault(); deleteRule(UI.sel.chainId, UI.sel.i); return; }
  if(mod && e.key.toLowerCase()==="d"){ e.preventDefault(); duplicateRule(UI.sel.chainId, UI.sel.i); return; }
  if(mod && e.key==="Enter"){ e.preventDefault(); addRule(UI.sel.chainId); return; }
  if(e.altKey && e.key==="ArrowUp"){   e.preventDefault(); moveRule(UI.sel.chainId, UI.sel.i, UI.sel.i-1); return; }
  if(e.altKey && e.key==="ArrowDown"){ e.preventDefault(); moveRule(UI.sel.chainId, UI.sel.i, UI.sel.i+1); return; }
  if(e.key==="ArrowUp"   && UI.sel.i>0){                 e.preventDefault(); select(UI.sel.chainId, UI.sel.i-1); }
  if(e.key==="ArrowDown" && UI.sel.i<ch.rules.length-1){ e.preventDefault(); select(UI.sel.chainId, UI.sel.i+1); }
});

$("#undo").addEventListener("click", undo);
$("#redo").addEventListener("click", redo);


/* ══ DRAG & DROP ════════════════════════════════════════════════════════
   Two payloads share one pipeline: a library object (creates or amends a
   rule) and a rule being reordered (order is semantics, so this is an
   edit, not a cosmetic move).                                           */
let DRAG = null;
/* was SVC_PROTO, three entries hard-coded beside a seven-item list; the
   catalogue in core/vocabulary.js carries the protocol with the service */

/* What a dropped object contributes to a rule. Exported so a test can ask
   every palette category what it produces — five of them used to produce
   nothing at all, which is invisible until somebody drags one. */
export function fragment(k, name, ref, ch){
  const egress = ch.hook==="output" || ch.hook==="postrouting";
  switch(k){
    case "SV": return {expr:`${protoOf(name, ownOf("SV"))} dport ${ref.split("/")[0]}`};
    case "PR": return {expr:`meta l4proto ${name}`};
    /* A helper is assigned in a rule on the port the protocol negotiates on;
       it was listed and did nothing when dropped. */
    case "HL": {
      const h = catalogue(ownOf("HL"), BUILT_IN.HL).find(x=>x.n===name);
      return h ? {expr:`${h.proto} dport ${h.p} ct helper set "${h.n}"`} : null;
    }
    case "MP": {
      const m = MODEL.sets.find(x=>"@"+x.n===name && x.kind==="map");
      return m ? {expr:`ip ${egress?"daddr":"saddr"} @${m.n}`} : null;
    }
    case "TP": {
      const tpl = TEMPLATES.find(x=>t(x.title.en, x.title.es) === name);
      return tpl ? {rules: tpl.rules} : null;
    }
    case "NW": return {expr:`ip ${egress?"daddr":"saddr"} ${name}`};
    case "IF": return {expr:`${egress?"oifname":"iifname"} "${name}"`};
    case "CT": return {expr: name.startsWith("ct ") ? name : `ct state ${name}`};
    /* A meter is a limit kept per key, which is the whole reason to reach for
       one; this dropped a plain rate limit and called it a meter. */
    case "ME":
      if(name==="meter")      return {expr:"meter flood { ip saddr limit rate 10/second }"};
      if(name==="limit rate") return {expr:"limit rate 5/second burst 10 packets"};
      return {expr:"limit rate over 100/second"};
    case "MK": return {expr:`${name} 0x1`};
    case "SE": {
      const s = MODEL.sets.find(x=>"@"+x.n===name);
      if(!s) return null;
      return {expr: s.t==="inet_service" ? `tcp dport @${s.n}` : `ip ${egress?"daddr":"saddr"} @${s.n}`};
    }
    case "AC": {
      const v = name.split(" ")[0];
      if(v==="reject") return {verdict:"reject", to:"icmpx admin-prohibited"};
      /* This offered a jump to `fwd_mgmt`, a chain from the demo ruleset that
         has not shipped for a long time. Aim at a chain the project has, and
         say so when it has none to aim at. */
      if(v==="jump" || v==="goto"){
        const target = MODEL.chains.find(c=>c.table===ch.table && !c.hook && c!==ch)
                    || MODEL.chains.find(c=>c.table===ch.table && c!==ch);
        if(!target) return null;
        return {verdict:v, to:target.id};
      }
      return {verdict:v};
    }
    case "NT": {
      if(name==="masquerade")      return {verdict:"snat", to:"masquerade"};
      /* These arrived carrying 10.20.0.15:443 and 198.51.100.10 — addresses
         from the old demo, silently written into somebody's real ruleset. The
         verdict is what was dragged; the destination is theirs to fill in. */
      if(name.startsWith("dnat"))  return {verdict:"dnat", to:""};
      if(name.startsWith("snat"))  return {verdict:"snat", to:""};
      /* redirect is its own verdict, not a dnat with the target left off —
         which is what this produced, and what nft refuses. */
      return {verdict:"redirect"};
    }
    /* `pkts = 1` claimed one packet the rule had never seen, which is the lie
       the counter split was made to remove. `ctr` is the statement. A named
       counter and a quota are not that statement: they are their own. */
    case "CN":
      if(name.startsWith("counter name")) return {expr:name};
      if(name === "quota over")           return {expr:"quota over 1 mbytes"};
      return {ctr:true};
    default:   return null;
  }
}
const dropLabel = (k,n) => k==="AC"||k==="NT" ? t("set verdict ","fijar veredicto ")+n
                         : k==="CN" ? t("add counter","añadir contador")
                         : t("new rule · ","nueva regla · ")+n;

/* ── library source ── */
document.addEventListener("dragstart", e=>{
  const obj = e.target.closest(".obj");
  if(obj){
    const cat = obj.closest(".cat");
    DRAG = {type:"lib", k:$(".gl",obj).textContent.trim(),
            n:$(".nm",obj).textContent.trim(), r:$(".rf",obj).textContent.trim()};
    obj.classList.add("dragging");
    e.dataTransfer.effectAllowed = "copy";
    e.dataTransfer.setData("text/plain", DRAG.n);
    return;
  }
  const row = e.target.closest(".rule");
  if(row){
    DRAG = {type:"move", chain:row.dataset.chain, i:+row.dataset.i};
    row.classList.add("dragging");
    e.dataTransfer.effectAllowed = "move";
    e.dataTransfer.setData("text/plain", "");
  }
});
document.addEventListener("dragend", ()=>{
  DRAG = null;
  $$(".dragging,.dropzone,.droptarget,.dropbefore,.dropafter")
    .forEach(n=>n.classList.remove("dragging","dropzone","droptarget","dropbefore","dropafter"));
});

/* ── dropping a chain onto the canvas ────────────────────────────────
   Dragging `prerouting` out of the library is the obvious gesture, and it
   used to show the no-entry cursor: only rule-sized objects had a target.
   The canvas itself is a target for chains, and where you drop decides the
   hook, because that is what the horizontal axis already means. */
const HOOK_AT = x => {
  let best = null, dist = Infinity;
  for(const [h, hx] of Object.entries(HOOK_X)){
    const d = Math.abs(x - (hx + 142));
    if(d < dist){ dist = d; best = h; }
  }
  return best;
};
const isChainDrag = () => DRAG?.type === "lib" && DRAG.k === "CH";
const HOOK_NAMES = Object.keys(HOOK_X);

function canvasPoint(e){
  const c = $("#canvas").getBoundingClientRect();
  return {x:(e.clientX - c.left)/UI.zoom, y:(e.clientY - c.top)/UI.zoom};
}

$("#cscroll").addEventListener("dragover", e=>{
  if(!isChainDrag() || e.target.closest(".chain")) return;
  e.preventDefault();
  e.dataTransfer.dropEffect = "copy";
  const hook = HOOK_NAMES.includes(DRAG.n) ? DRAG.n : HOOK_AT(canvasPoint(e).x);
  $$(".hk").forEach(k=>k.classList.toggle("lit", k.dataset.hook === hook));
});

$("#cscroll").addEventListener("drop", e=>{
  if(!isChainDrag() || e.target.closest(".chain")) return;
  e.preventDefault();
  $$(".hk").forEach(k=>k.classList.remove("lit"));

  const named = HOOK_NAMES.includes(DRAG.n);
  const hook = named ? DRAG.n : HOOK_AT(canvasPoint(e).x);
  const table = MODEL.chains[0]?.table || "inet filter";
  DRAG = null;

  /* "base chain" / "regular chain" are templates, not a hook — and a name
     that already exists needs a decision, so both go to the dialog */
  if(!named || MODEL.chains.some(c=>c.table===table && c.id===hook)){
    hooks.openChain(null);
    $("#ch-name").value = named ? hook : "";
    $("#ch-hook").value = hook;
    if(DRAG?.n === "regular chain") $('#ch-kind [data-kind="regular"]')?.click();
    hooks.chSync();
    return;
  }
  addChainAt(hook, table);
});

function addChainAt(hook, table){
  const facing = hook === "input" || hook === "forward";
  edit(t("new chain","cadena nueva"), ()=>{
    MODEL.chains.push({
      id: hook, table, hook, prio: 0, type: "filter",
      policy: facing ? "drop" : "accept", rules: [],
    });
  });
  go("editor");
  const uid = table + "/" + hook;
  setTimeout(()=>$(`.chain[data-chain="${cssEsc(uid)}"]`)
    ?.scrollIntoView({block:"center", inline:"center", behavior:"smooth"}), 40);
  toast(t(`Added ${hook} — click its header to set type and priority`,
          `Añadida ${hook} — pulsa su cabecera para tipo y prioridad`));
}

/* The hook rail already names every hook; clicking one adds a chain there. */
$(".hookrail").addEventListener("click", e=>{
  const hk = e.target.closest(".hk"); if(!hk) return;
  const hook = hk.dataset.hook, table = MODEL.chains[0]?.table || "inet filter";
  if(MODEL.chains.some(c=>c.table===table && c.id===hook)){
    hooks.openChain(null); $("#ch-hook").value = hook; hooks.chSync();
  } else addChainAt(hook, table);
});

/* ── targets ── */
document.addEventListener("dragover", e=>{
  if(!DRAG) return;
  const card = e.target.closest(".chain");
  if(!card) return;
  e.preventDefault();
  e.dataTransfer.dropEffect = DRAG.type==="move" ? "move" : "copy";

  $$(".dropzone").forEach(n=>{ if(n!==card) n.classList.remove("dropzone"); });
  $$(".droptarget,.dropbefore,.dropafter").forEach(n=>n.classList.remove("droptarget","dropbefore","dropafter"));

  const row = e.target.closest(".rule");
  if(DRAG.type==="move"){
    card.classList.remove("dropzone");
    if(row && !(row.dataset.chain===DRAG.chain && +row.dataset.i===DRAG.i)){
      const b = row.getBoundingClientRect();
      row.classList.add(e.clientY < b.top + b.height/2 ? "dropbefore" : "dropafter");
    }
    return;
  }
  if(row) row.classList.add("droptarget");
  else {
    card.classList.add("dropzone");
    $(".chain-rules",card).dataset.drop = dropLabel(DRAG.k, DRAG.n);
  }
});

document.addEventListener("drop", e=>{
  if(!DRAG) return;
  const card = e.target.closest(".chain");
  if(!card) return;
  e.preventDefault();
  const cid = card.dataset.chain, ch = chainOf(cid);
  const row = e.target.closest(".rule");

  /* reorder within, or across, chains */
  if(DRAG.type==="move"){
    if(!row){ DRAG = null; return; }
    const from = chainOf(DRAG.chain);
    const b = row.getBoundingClientRect();
    let to = +row.dataset.i + (e.clientY < b.top + b.height/2 ? 0 : 1);
    if(DRAG.chain===cid && DRAG.i < to) to--;
    if(DRAG.chain===cid && DRAG.i===to){ DRAG = null; return; }
    const src = DRAG;
    edit(t("reorder rule","reordenar regla"), ()=>{
      const [m] = from.rules.splice(src.i,1);
      ch.rules.splice(to,0,m);
    });
    select(cid, to);
    DRAG = null;
    return;
  }

  /* library object */
  const frag = fragment(DRAG.k, DRAG.n, DRAG.r, ch);
  if(!frag){
    toast(t(`“${DRAG.n}” can't be dropped on a rule`, `«${DRAG.n}» no se puede soltar en una regla`));
    DRAG = null; return;
  }
  const name = DRAG.n;
  let idx;

  /* a template is a group of rules, so it appends rather than merging */
  if(frag.rules){
    edit(t("add template ","añadir plantilla ")+name, ()=>{
      frag.rules.forEach(x=> ch.rules.push(R(x.expr, x.verdict, {
        ctr: !!x.ctr, pkts:0, bytes:0, ...(x.cmt?{cmt:x.cmt}:{}), ...(x.implicit?{implicit:true}:{}),
      })));
    });
    select(cid, ch.rules.length-1);
    toast(t(`Added ${frag.rules.length} rules`,`Añadidas ${frag.rules.length} reglas`)+" — Ctrl+Z");
    DRAG = null; return;
  }

  edit(t("drop ","soltar ")+name, ()=>{
    let r;
    if(row){ idx = +row.dataset.i; r = ch.rules[idx]; }
    else { r = R("", ch.policy==="drop" ? "accept" : "drop", {pkts:0,bytes:0}); ch.rules.push(r); idx = ch.rules.length-1; }
    if(frag.expr){
      /* replace the same criterion rather than stacking a contradiction */
      const key = frag.expr.match(/^(\w+ \w+|\w+)/)[0];
      const re = new RegExp(key.replace(/[.*+?^${}()|[\]\\]/g,"\\$&") + " \\S+", "g");
      r.expr = (re.test(r.expr) ? r.expr.replace(re, frag.expr) : (r.expr ? r.expr+" "+frag.expr : frag.expr)).trim();
    }
    if(frag.verdict){ r.verdict = frag.verdict; if(frag.to!==undefined) r.to = frag.to; else delete r.to; }
    if(frag.ctr) r.ctr = true;
  });
  select(cid, idx);
  toast(t(`Added ${name}`,`Añadido ${name}`)+" — Ctrl+Z");
  DRAG = null;
});

/* the library is a palette, not a list: make that legible before the drag */
$("#lib-body").addEventListener("mousedown", e=>{
  const o = e.target.closest(".obj");
  if(o) o.style.cursor = "grabbing";
});


/* ══ THE CATALOGUE: WHERE IT LIVES, AND HOW IT LEAVES ═══════════════════
   What you add to Services, Protocols and Helpers is kept on this machine,
   which is right for knowledge about the world — telnet is 23 in every
   project. It is also why it needs a way out: the ports of an internal
   network get looked up by one person and used by ten. */
$("#lib-menu")?.addEventListener("click", async e=>{
  e.stopPropagation();
  const mine = VOCAB.services.length + VOCAB.protocols.length + VOCAB.helpers.length;
  const m = openCtx(e.clientX, e.clientY, [
    ["where", t("Where is it kept?","¿Dónde se guarda?"),
     "M12 21s7-5.7 7-11a7 7 0 1 0-14 0c0 5.3 7 11 7 11z M12 10h.01"],
    ["export", t(`Export your catalogue (${mine})`, `Exportar tu catálogo (${mine})`),
     "M12 3v13M7 11l5 5 5-5M4 21h16"],
    ["import", t("Import a catalogue…","Importar un catálogo…"),
     "M12 16V3M7 8l5-5 5 5M4 21h16"],
  ]);
  m.addEventListener("click", async ev=>{
    const a = ev.target.closest("[data-act]"); if(!a) return;
    const act = a.dataset.act;
    killCtx();

    if(act === "where"){
      const where = await native.settingPath("vocabulary");
      await confirmDialog(t("Your catalogue","Tu catálogo"),
        where
          ? t(`It is a plain JSON file at:\n\n${where}\n\nBack it up, put it in a repository, or point a synced folder at it — editing it by hand is fine.`,
              `Es un fichero JSON en:\n\n${where}\n\nHaz copia, mételo en un repositorio, o apunta una carpeta sincronizada ahí — editarlo a mano es correcto.`)
          : t("In the browser it is kept in local storage, which does not leave this profile. The desktop app writes a JSON file you can back up.",
              "En el navegador se guarda en el almacenamiento local, que no sale de este perfil. La aplicación de escritorio escribe un fichero JSON del que puedes hacer copia."),
        t("Close","Cerrar"));
      return;
    }

    if(act === "export"){
      if(!mine){
        toast(t("Nothing of your own to export yet","Todavía no has añadido nada"));
        return;
      }
      const where = await native.saveTextFile("efeflow-catalogue.json",
        JSON.stringify(VOCAB, null, 2), [{name:"eFeFlow catalogue", extensions:["json"]}]);
      if(where) toast(t("Exported to ","Exportado a ")+where);
      return;
    }

    if(act === "import"){
      const picked = await native.openTextFile([{name:"eFeFlow catalogue", extensions:["json"]}]);
      if(!picked) return;
      const before = VOCAB.services.length + VOCAB.protocols.length + VOCAB.helpers.length;
      if(!mergeVocab(picked.text)){
        toast(t("That is not a catalogue file","Eso no es un fichero de catálogo"));
        return;
      }
      vocabChanged();
      const after = VOCAB.services.length + VOCAB.protocols.length + VOCAB.helpers.length;
      toast(t(`Catalogue imported — ${after} entries, was ${before}`,
              `Catálogo importado — ${after} entradas, antes ${before}`));
    }
  });
});

/* The names every other screen holds are real here. */
provide({ select, openCtx, killCtx });
