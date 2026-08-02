/* eFeFlow — the interface.
 *
 * Everything with a verdict in it lives in ./core: the parser, the generator,
 * the analyser and the packet evaluator are pure and covered by `npm test`.
 * This module is the part that has to touch the DOM. */

import {
  MODEL, R, UID, jumpTarget, chainOf, blankRuleset,
  VCOLOR, VNAME, fmtN, fmtB, verdictText, ruleLine,
} from "./core/model.js";
import { generate, generateWithMap } from "./core/generate.js";
import { parseNft, parseRule, verify, normalise } from "./core/parse.js";
import { analyse, worstCase } from "./core/analyse.js";
import { evaluate, matches, inSet, inCidr, PRESETS, PATHS, packet } from "./core/simulate.js";
import { diffLines } from "./core/diff.js";
import { PRIO_NAME, NAME_PRIO } from "./core/priority.js";
import { PROJECT, project, setProject, serialise, deserialise } from "./core/project.js";
import { SAMPLES, sampleById } from "./core/samples.js";
import { TOUR, tourStep } from "./core/tour.js";
import { catalogue, protoOf, OWNABLE, BUILT_IN, emptyVocabulary,
         TEMPLATES, templateById } from "./core/vocabulary.js";
import { readExpr, editExpr } from "./core/expr.js";
import { modelChanged, rerender, onModelChange, onRender, findings, setFindings } from "./core/bus.js";
import { t, lang, setLang, applyLang, onLangChange } from "./i18n.js";
import { target, loadTarget, saveTarget, asTauriTarget, describe, probe } from "./target.js";
import * as native from "./native.js";

const MODEL_HOOKS = { push: onModelChange };
const RERENDER = { push: onRender, forEach: () => {} };

/* The language switch. Its handler lived in the prototype's i18n block, which
   was cut when that moved into a module — and nothing put it back, so the
   control was inert in the desktop build. */
document.addEventListener("click", (e) => {
  const b = e.target.closest("#lang [data-lang]");
  if (b) setLang(b.dataset.lang);
});

/* hoisted: the prototype relied on <script> ordering for these */
let FIND, CUR, PENDING, toastT, POS, LANES, zoom, SEL, timers, CODE_VARIANT, BASELINE, DW_TAB, TOOL, VFILTER, ctxEl, DRAG, IMPORTED, SETSEL, TOPO_MODE, PAL, PALI, TOURI;

FIND = [];
const $  = (s,r=document)=>r.querySelector(s);
const $$ = (s,r=document)=>[...r.querySelectorAll(s)];
const esc = s => s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
const el = (tag,c,h)=>{const n=document.createElement(tag); if(c)n.className=c; if(h!=null)n.innerHTML=h; return n;};
/* chain and interface keys contain "/" and spaces, so they need escaping
   before they go into an attribute selector. Declared here with the other
   helpers because layout runs at module evaluation and a const declared
   further down would still be in its dead zone. */
const cssEsc = s => (window.CSS && CSS.escape) ? CSS.escape(s) : String(s).replace(/["\\]/g, "\\$&");

/* the screens live at document root while authoring; dock them into the shell */
$$(".screen").forEach(s=>$("#screens").appendChild(s));
$$(".scrim").forEach(s=>document.body.appendChild(s));

/* ══ MODEL ══════════════════════════════════════════════════════════════
   Real nftables semantics: a chain is (hook, priority, policy); a rule is
   an ordered list of match expressions terminated by a verdict.          */
/* ══ HISTORY ════════════════════════════════════════════════════════════
   Every mutation goes through edit(); nothing writes MODEL directly. The
   snapshot is the whole ruleset, which is cheap at this size and removes a
   whole class of bugs that per-field diffing invites.                    */
const HIST = {past:[], future:[], max:80};
/* Everything the ruleset is made of, including the parts nothing edits: an
   undo that forgot the flowtables would delete them on the first Ctrl+Z. */
const snapshot = () => JSON.stringify(
  {c:MODEL.chains, s:MODEL.sets, o:MODEL.objects, tb:MODEL.tables});
CUR = null, PENDING = null;
function restore(str){
  const o = JSON.parse(str);
  MODEL.chains = o.c; MODEL.sets = o.s;
  MODEL.objects = o.o || []; MODEL.tables = o.tb || [];
}
function refresh(keepSel){
  renderChains(); paintCode(); drawWires(); modelChanged();
  if(keepSel && SEL){
    const ch = chainOf(SEL.chainId);
    if(ch && ch.rules.length){ select(SEL.chainId, Math.min(SEL.i, ch.rules.length-1)); return; }
  }
  SEL = null; $("#props-body").innerHTML = EMPTY();
}
function pushHist(before,label){
  if(before === snapshot()) return false;
  HIST.past.push({s:before, label});
  if(HIST.past.length > HIST.max) HIST.past.shift();
  HIST.future.length = 0;
  CUR = snapshot(); syncHistUI();
  return true;
}
/* label is what the user would call the change — it surfaces in the tooltip */
function edit(label, fn, keepSel){
  const before = CUR ?? snapshot();
  fn();
  if(pushHist(before,label)) refresh(keepSel);
}
function undo(){
  if(!HIST.past.length) return;
  const e = HIST.past.pop();
  HIST.future.push({s:snapshot(), label:e.label});
  restore(e.s); CUR = e.s; syncHistUI(); refresh(true);
  toast(t("Undone: ","Deshecho: ")+e.label);
}
function redo(){
  if(!HIST.future.length) return;
  const e = HIST.future.pop();
  HIST.past.push({s:snapshot(), label:e.label});
  restore(e.s); CUR = e.s; syncHistUI(); refresh(true);
  toast(t("Redone: ","Rehecho: ")+e.label);
}
function syncHistUI(){
  const u = $("#undo"), r = $("#redo");
  if(!u) return;
  u.disabled = !HIST.past.length;
  r.disabled = !HIST.future.length;
  u.title = HIST.past.length   ? t("Undo ","Deshacer ")+HIST.past.at(-1).label+" — Ctrl+Z"   : t("Nothing to undo","Nada que deshacer");
  r.title = HIST.future.length ? t("Redo ","Rehacer ")+HIST.future.at(-1).label+" — Ctrl+Y" : t("Nothing to redo","Nada que rehacer");
  const d = $(".dot-live");
  if(d) d.style.opacity = HIST.past.length ? "1" : ".25";
}

toastT = null;
function toast(msg){
  let n = $("#toast");
  if(!n){ n = el("div","glass"); n.id = "toast"; document.body.appendChild(n); }
  n.textContent = msg;
  n.classList.add("on");
  clearTimeout(toastT);
  toastT = setTimeout(()=>n.classList.remove("on"), 2200);
}

/* ══ NAVIGATION ═════════════════════════════════════════════════════════ */
const NAV = [
  {id:"dash",     en:"Dashboard",        es:"Panel",               k:"1", d:"M4 13h7V4H4zM13 9h7V4h-7zM13 20h7v-9h-7zM4 20h7v-5H4z"},
  {id:"editor",   en:"Rule editor",      es:"Editor de reglas",    k:"2", d:"M4 20h4L19 9a2.8 2.8 0 0 0-4-4L4 16z"},
  {id:"sim",      en:"Packet simulator", es:"Simulador de paquetes",k:"3", d:"M5 3v18l15-9z"},
  {id:"sets",     en:"Set manager",      es:"Gestor de sets",      k:"4", d:"M4 7h16M4 12h16M4 17h9"},
  {id:"topo",     en:"Topology",         es:"Topología",           k:"5", d:"M12 7.5v4m0 0-5 5m5-5 5 5M12 5a2.5 2.5 0 1 0 0-.01M5 19a2.5 2.5 0 1 0 0-.01M19 19a2.5 2.5 0 1 0 0-.01"},
  {id:"code",     en:"Generated code",   es:"Código generado",     k:"6", d:"m9 8-5 4 5 4M15 8l5 4-5 4"},
  {id:"validate", en:"Validation",       es:"Validación",          k:"7", d:"M12 3 4 6v6c0 4.5 3.2 8.4 8 9.5 4.8-1.1 8-5 8-9.5V6zm-3 9 2 2 4-4", b:"3"},
  {id:"help",     en:"Guide",            es:"Guía",                k:"8",
   d:"M12 17h.01M9.1 9a3 3 0 1 1 4.2 2.7c-.8.4-1.3 1.2-1.3 2.1V15M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18"},
];
const rail = $("#rail");
function renderRail(){
  const cur = $(".rb.on")?.dataset.go;
  rail.innerHTML = "";
  NAV.forEach(n=>{
    const b = el("button","rb"+(n.id===cur?" on":""));
    b.dataset.go = n.id;
    b.innerHTML = `<svg class="ico lg" viewBox="0 0 24 24"><path d="${n.d}"/></svg>
      ${n.b?`<span class="bdg" style="display:none"></span>`:""}
      <span class="tip">${t(n.en,n.es)}<kbd>Alt ${n.k}</kbd></span>`;
    rail.appendChild(b);
    if(n.id==="sim"){
      const sep = el("div"); sep.style.cssText="height:1px;width:22px;background:var(--line-2);margin:6px 0";
      rail.appendChild(sep);
    }
  });
}
renderRail();
RERENDER.push(renderRail);

function go(id){
  if(id==="export"){ $("#scrim-export").classList.add("on"); return; }
  if(id==="about"){ $("#scrim-about").classList.add("on"); return; }
  if(id==="open"){ $("#scrim-palette").classList.add("on"); $("#pal-input").focus(); return; }
  $$(".screen").forEach(s=>s.classList.toggle("on", s.id==="s-"+id));
  $$(".rb").forEach(b=>b.classList.toggle("on", b.dataset.go===id));
  /* A hidden element measures zero, so every card laid out while the editor
     was on another screen fell back to a nominal height — and any chain taller
     than that had the next one placed on top of it. Measure again now that
     there is something to measure. */
  if(id==="editor") requestAnimationFrame(()=>{ placeChains(); drawWires(); });
  if(id==="topo")   requestAnimationFrame(renderTopo);
  /* The simulator arrives already run. An empty stage reads as "broken", and
     the result is cheap and deterministic — there is no reason to make the
     user press a button to find out what their own ruleset does. */
  /* A frame is long enough to leave again. Without the check, arriving and
     going straight back out starts a run on a screen that is no longer there,
     and it plays on into whatever comes next — the boot path has always
     guarded this; this one did not. */
  if(id==="sim")    requestAnimationFrame(()=>{
    if(!$("#s-sim")?.classList.contains("on")) return;
    readForm(); runSim();
  });
  else              stopSim();
}
document.addEventListener("click",e=>{
  const g = e.target.closest("[data-go]"); if(g){ go(g.dataset.go); return; }
  if(e.target.closest("[data-close]")) $$(".scrim").forEach(s=>s.classList.remove("on"));
  const sc = e.target.closest(".scrim"); if(sc && e.target===sc) sc.classList.remove("on");
});
document.addEventListener("keydown",e=>{
  if(e.key==="Escape") $$(".scrim").forEach(s=>s.classList.remove("on"));
  if(e.altKey && /^[1-8]$/.test(e.key) && NAV[+e.key-1]){ e.preventDefault(); go(NAV[+e.key-1].id); }
  if((e.ctrlKey||e.metaKey) && e.key.toLowerCase()==="k"){ e.preventDefault(); go("open"); }
  if((e.ctrlKey||e.metaKey) && e.key.toLowerCase()==="e"){ e.preventDefault(); go("export"); }
});
$("#omni-open").addEventListener("click",()=>go("open"));

/* toggles are decorative-but-real */
document.addEventListener("click",e=>{
  const t=e.target.closest(".sw-toggle"); if(t) t.classList.toggle("on");
  const s=e.target.closest(".seg button"); if(s) $$("button",s.parentElement).forEach(b=>b.classList.toggle("on",b===s));
  const c=e.target.closest(".choice"); if(c) $$(".choice",c.parentElement).forEach(x=>x.classList.toggle("on",x===c));
  const vt=e.target.closest(".val-tab"); if(vt) $$(".val-tab").forEach(x=>x.classList.toggle("on",x===vt));
  const si=e.target.closest(".set-item"); if(si) $$(".set-item").forEach(x=>x.classList.toggle("on",x===si));
  const dt=e.target.closest(".dw-tab"); if(dt) $$(".dw-tab").forEach(x=>x.classList.toggle("on",x===dt));
});
$("#dw-toggle").addEventListener("click",e=>{
  const d=$("#drawer"); d.classList.toggle("min");
  e.currentTarget.querySelector("path").setAttribute("d", d.classList.contains("min")?"m6 9 6 6 6-6":"m6 15 6-6 6 6");
  requestAnimationFrame(drawWires);
});

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

const mergeVocab = text => {
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

const ownOf = gl => VOCAB[OWNABLE[gl]?.key] ?? [];
function vocabChanged(){
  const text = JSON.stringify(VOCAB, null, 2);
  try{ localStorage.setItem(VKEY, text); }catch{ /* private mode */ }
  native.writeSetting("vocabulary", text).catch(()=>{ /* read-only profile */ });
  renderLibrary();
}

const CH_ = () => t("chains","cadenas"), CH1 = () => t("chain","cadena"), RL_ = () => t("rules","reglas");
const LIB = () => [
  /* the tables and sets your ruleset has, not four invented ones */
  [t("Tables","Tablas"),"TB", (()=>{
     const seen = new Map();
     MODEL.chains.forEach(c=> seen.set(c.table, (seen.get(c.table)||0)+1));
     const rows = [...seen].map(([n,k])=>[n, `${k} ${k===1?CH1():CH_()}`]);
     /* the fallback named a table called "inet filter" that nothing had
        created — the third flag marks a row as a note, not an object */
     return rows.length ? rows : [[t("no tables yet","aún sin tablas"), "", true]];
   })()],
  [t("Chains","Cadenas"),"CH",[[t("base chain","cadena base"),""],[t("regular chain","cadena regular"),""],["prerouting",""],["input",""],["forward",""],["output",""],["postrouting",""]]],
  ["Sets","SE", MODEL.sets.length
     ? MODEL.sets.map(s=>["@"+s.n, s.el.length>999 ? (s.el.length/1000).toFixed(1)+"k" : String(s.el.length)])
     : [[t("no sets yet","aún sin sets"),"",true]]],
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
  ["NAT","NT",[["dnat to",""],["snat to",""],["masquerade",""],["redirect to",""]]],
  [t("Helpers","Helpers"),"HL",
    catalogue(ownOf("HL"), BUILT_IN.HL).map(h=>[h.n, `${h.p}/${h.proto}`])],
  [t("Counters","Contadores"),"CN",[["counter",""],[t("named counter","counter con nombre"),""],["quota",""]]],
  [t("Meters","Medidores"),"ME",[["meter flood",""],["limit rate",""],["limit rate over",""]]],
  [t("Marks","Marcas"),"MK",[["meta mark set",""],["ct mark set",""],["meta priority",""]]],
  /* The counts here were invented and dropping one did nothing. They are real
     rule groups now, and the count is however many rules the group holds. */
  [t("Templates","Plantillas"),"TP",
    TEMPLATES.map(x=>[t(x.title.en, x.title.es), `${x.rules.length} ${RL_()}`])],
];
const libBody = $("#lib-body");
function renderLibrary(){
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
RERENDER.push(renderLibrary);
/* the library mirrors the ruleset, so it has to follow it */
MODEL_HOOKS.push(renderLibrary);
$("#lib-filter").addEventListener("input",e=>{
  const q = e.target.value.toLowerCase().trim();
  $$(".cat").forEach(c=>{
    let hits = 0;
    $$(".obj",c).forEach(o=>{ const m = !q || o.querySelector(".nm").textContent.toLowerCase().includes(q);
      o.style.display = m?"":"none"; if(m) hits++; });
    c.style.display = hits?"":"none"; if(q) c.open = true;
  });
});

/* ══ CANVAS · chains anchored at (hook, priority) ═══════════════════════ */
const HOOK_X = {prerouting:88, input:392, forward:696, output:1000, postrouting:1304};
/* nft prints priorities by name; both directions are needed for round-trip */

const ruler = $("#ruler");
POS = {}, LANES = [];
/* chains the user has placed by hand, keyed by table/chain */
const CHAIN_POS = {};

/* x is the hook, y is the priority — the canvas is a field, not a freeform
   board. Only the column is decided here; the rows need real heights. */
function layout(){
  LANES = [...new Set(MODEL.chains.filter(c=>c.hook).map(c=>c.prio))].sort((a,b)=>a-b);
  POS = {};
  MODEL.chains.filter(c=>c.hook).forEach(ch=>{
    POS[UID(ch)] = {x: HOOK_X[ch.hook] ?? HOOK_X.prerouting, lane: ch.prio, hook: ch.hook};
  });
  /* a regular chain has no hook of its own — hang it under whoever jumps to it */
  MODEL.chains.filter(c=>!c.hook).forEach(ch=>{
    const src = MODEL.chains.find(c=>c.table===ch.table && c.rules.some(r=>
      (r.verdict==="jump"||r.verdict==="goto") && r.to===ch.id));
    POS[UID(ch)] = {x: (src && POS[UID(src)]?.x) ?? HOOK_X.forward, lane: null, after: src && UID(src)};
  });
}

/* Second pass, once the cards are in the document. A chain card grows with its
   rule count, so a fixed lane pitch was always going to collide — which is
   exactly what happened in prerouting, where raw_pre ran into nat_pre. */
function placeChains(){
  const TOP = 96, GUT = 34, LANE_GAP = 46;
  const elOf = uid => $(`.chain[data-chain="${cssEsc(uid)}"]`);
  /* A card on a screen that is not showing measures zero. One nominal height
     for every chain put a two-rule card and a twenty-rule card in the same
     space, so the tall ones were overlapped; estimating from the rule count is
     close enough to survive until go("editor") measures for real. */
  const H = uid => {
    const n = elOf(uid);
    if(n?.offsetHeight) return n.offsetHeight;
    const ch = chainOf(uid);
    return 96 + (ch ? ch.rules.filter(r => r.on).length : 2) * 34;
  };

  const laneTop = {};
  let y = TOP;

  for(const prio of LANES){
    laneTop[prio] = y;
    let tallest = 0;
    /* several chains can share one hook at one priority; stack them */
    for(const hook of Object.keys(HOOK_X)){
      const here = MODEL.chains.filter(c => c.hook === hook && c.prio === prio);
      let cy = y;
      for(const ch of here){
        POS[UID(ch)].y = cy;
        cy += H(UID(ch)) + GUT;
      }
      tallest = Math.max(tallest, cy - y);
    }
    y += Math.max(tallest, 120) + LANE_GAP;
  }

  /* regular chains sit below the chain that jumps to them */
  for(const ch of MODEL.chains.filter(c => !c.hook)){
    const p = POS[UID(ch)];
    const src = p.after;
    p.y = src && POS[src]?.y !== undefined ? POS[src].y + H(src) + 46 : y;
    while(Object.entries(POS).some(([uid, q]) =>
      uid !== UID(ch) && q.x === p.x && q.y !== undefined &&
      Math.abs(q.y - p.y) < 80)) p.y += 80;
  }

  /* apply, honouring anything dragged */
  for(const ch of MODEL.chains){
    const uid = UID(ch), node = elOf(uid), saved = CHAIN_POS[uid];
    if(!node) continue;
    const p = POS[uid];
    if(saved){ p.x = saved.x; p.y = saved.y; }
    node.style.left = p.x + "px";
    node.style.top  = p.y + "px";
  }

  const bottom = Math.max(620, ...MODEL.chains.map(ch =>
    (POS[UID(ch)]?.y ?? 0) + H(UID(ch)))) + 80;
  $("#canvas").style.height = bottom + "px";

  ruler.innerHTML = LANES.map(p=>{
    const nm = NAME_PRIO[String(p)], top = laneTop[p] ?? TOP;
    return `<div class="tick" style="top:${top}px"><b>${p>0?"+"+p:p}</b></div>
            ${nm?`<div class="tick sub" style="top:${top+18}px">
              <span style="font-size:9px;opacity:.7">${nm}</span></div>`:""}`;
  }).join("");
}

zoom = 1;
const chainsEl = $("#chains");
function renderChains(){
  layout();
  chainsEl.innerHTML = "";
  MODEL.chains.forEach(ch=>{
    const p = POS[UID(ch)]; if(!p) return;
    const node = el("div","chain");
    node.dataset.chain = UID(ch);
    node.style.left = p.x+"px";   /* the row comes from placeChains, after measuring */
    const polPill = ch.policy
      ? `<span class="pill ${ch.policy==="drop"?"v-drop":"v-accept"}"><span class="sw"></span>policy ${ch.policy}</span>`
      : `<span class="pill v-neutral">${t("regular","regular")}</span>`;
    node.innerHTML = `
      <div class="chain-hd">
        <span style="color:var(--${ch.policy==="drop"?"v-drop":"v-accept"});font-size:9px">◆</span>
        <span class="cn">${ch.id}</span><span class="fam">${ch.table.split(" ")[0]}</span>
      </div>
      <div class="chain-meta">
        ${ch.hook?`<span class="chip">hook ${ch.hook}</span><span class="chip">prio ${ch.prio}</span>`:`<span class="chip">${t("no hook","sin hook")}</span>`}
        ${polPill}
      </div>
      <div class="chain-rules"></div>
      <div class="chain-ft">
        <button class="addrule"><svg class="ico sm" viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg>${t("Add rule","Añadir regla")}</button>
        <span class="lbl" style="font-size:9px">${ch.rules.length}</span>
      </div>`;
    const list = $(".chain-rules",node);
    ch.rules.forEach((r,i)=>{
      const row = el("div","rule"+(r.on?"":" off"));
      row.dataset.chain = UID(ch); row.dataset.i = i;
      row.draggable = true;
      row.style.color = `var(${VCOLOR[r.verdict]})`;
      const body = r.expr ? esc(r.expr).replace(/@(\w+)/g,'<span class="s">@$1</span>')
                                        .replace(/\b(ct|tcp|udp|ip|ip6|meta|iif|oif|iifname|oifname|limit|log)\b/g,'<span class="k">$1</span>')
                          : `<span class="dimmer">${t("any packet","cualquier paquete")}</span>`;
      row.innerHTML = `
        <span class="gut"></span>
        <span class="idx">${i+1}</span>
        <span class="expr">${body}</span>
        <span class="rt">
          ${r.pkts?`<span class="ctr">${fmtN(r.pkts)}<br>${fmtB(r.bytes)}</span>`:""}
          <span class="pill v-${r.verdict}"><span class="sw"></span>${VNAME[r.verdict]}</span>
        </span>`;
      list.appendChild(row);
    });
    chainsEl.appendChild(node);
  });
  placeChains();
  renderMinimap();
  renderLegend();
}

/* The key to the stripe colours, in evaluation-verdict order and holding only
   the verdicts this ruleset actually reaches for. Fixed at seven entries it
   was both noise — a key to a DNAT in a ruleset with no NAT at all — and
   wider than the dock, so `goto` and `continue` were clipped off the end. */
const VORDER = ["accept","drop","reject","jump","goto","dnat","redirect","snat",
                "log","return","continue"];
function renderLegend(){
  const used = new Set(MODEL.chains.flatMap(c => c.rules.filter(r => r.on).map(r => r.verdict)));
  const rows = VORDER.filter(v => used.has(v));
  $("#legend").innerHTML = rows.map(v =>
    `<div class="row" style="color:var(${VCOLOR[v]})"><i></i>${VNAME[v]}</div>`).join("");
  $("#legend").style.display = rows.length ? "" : "none";
}
renderChains();
RERENDER.push(()=>{ renderChains(); drawWires(); });

/* connectors follow the real packet path + explicit jumps, both derived */
const HOOK_FLOW = [["prerouting","input"],["prerouting","forward"],
                   ["forward","postrouting"],["output","postrouting"]];
function links(){
  const out = [];
  const inHook = h => MODEL.chains.filter(c=>c.hook===h).sort((a,b)=>a.prio-b.prio);
  /* within a hook, packets traverse chains in priority order */
  Object.keys(HOOK_X).forEach(h=>{
    const cs = inHook(h);
    for(let i=1;i<cs.length;i++) out.push([UID(cs[i-1]), UID(cs[i]), false]);
  });
  /* between hooks, the last chain of one feeds the first of the next */
  HOOK_FLOW.forEach(([a,b])=>{
    const A = inHook(a).at(-1), B = inHook(b)[0];
    if(A && B) out.push([UID(A), UID(B), false]);
  });
  /* explicit jumps are dashed — they are calls, not the packet path */
  MODEL.chains.forEach(ch=> ch.rules.forEach(r=>{
    const tgt = (r.verdict==="jump"||r.verdict==="goto") && jumpTarget(ch, r.to);
    if(tgt && POS[UID(tgt)]) out.push([UID(ch), UID(tgt), true]);
  }));
  return out;
}
function drawWires(){
  const svg = $("#wires");
  const h = parseInt($("#canvas").style.height) || 920;
  svg.setAttribute("viewBox",`0 0 1680 ${h}`);
  svg.setAttribute("width","1680"); svg.setAttribute("height",String(h));
  let out = "";
  /* straight from the DOM, so a card being dragged pulls its wires with it */
  links().forEach(([a,b,jump])=>{
    const A = $(`.chain[data-chain="${cssEsc(a)}"]`), B = $(`.chain[data-chain="${cssEsc(b)}"]`);
    if(!A||!B) return;
    const left = A.offsetLeft + A.offsetWidth/2 <= B.offsetLeft + B.offsetWidth/2;
    const x1 = left ? A.offsetLeft + A.offsetWidth : A.offsetLeft;
    const y1 = A.offsetTop + A.offsetHeight/2;
    const x2 = left ? B.offsetLeft : B.offsetLeft + B.offsetWidth;
    const y2 = B.offsetTop + B.offsetHeight/2;
    const dx = Math.max(46, Math.abs(x2-x1)*.55) * (left ? 1 : -1);
    out += `<path d="M${x1} ${y1} C${x1+dx} ${y1} ${x2-dx} ${y2} ${x2} ${y2}"${jump?' stroke-dasharray="4 5"':''}/>`;
    out += `<circle class="cap" cx="${x2}" cy="${y2}" r="3"/>`;
  });
  svg.innerHTML = out;
}
requestAnimationFrame(drawWires);
window.addEventListener("resize",()=>{ drawWires();
  if($("#s-topo").classList.contains("on")) renderTopo(); });

/* minimap mirrors the real chain positions and the real viewport */
function renderMinimap(){
  const mm = $("#mm"), sc = $("#cscroll");
  const H = parseInt($("#canvas").style.height) || 920;
  const SX = 176/1680, SY = 104/H;
  mm.innerHTML = MODEL.chains.map(ch=>{
    const node = $(`.chain[data-chain="${cssEsc(UID(ch))}"]`);
    if(!node) return "";
    return `<div class="blk${SEL && SEL.chainId===UID(ch)?" a":""}"
             style="left:${node.offsetLeft*SX}px;top:${node.offsetTop*SY}px;
             width:${node.offsetWidth*SX}px;height:${Math.max(2,node.offsetHeight*SY)}px"></div>`;
  }).join("") + `<div class="vp" id="mm-vp"></div>`;
  syncViewport();
}
function syncViewport(){
  const sc = $("#cscroll"), vp = $("#mm-vp");
  if(!vp) return;
  const H = parseInt($("#canvas").style.height) || 920;
  vp.style.cssText = `left:${sc.scrollLeft/zoom/1680*176}px;top:${sc.scrollTop/zoom/H*104}px;
    width:${Math.min(176, sc.clientWidth/zoom/1680*176)}px;
    height:${Math.min(104, sc.clientHeight/zoom/H*104)}px`;
}
$("#cscroll").addEventListener("scroll", syncViewport, {passive:true});
/* click the minimap to jump there */
$("#mm").addEventListener("pointerdown", e=>{
  const b = $("#mm").getBoundingClientRect();
  const H = parseInt($("#canvas").style.height) || 920;
  const sc = $("#cscroll");
  sc.scrollTo({left:(e.clientX-b.left)/176*1680*zoom - sc.clientWidth/2,
               top:(e.clientY-b.top)/104*H*zoom - sc.clientHeight/2, behavior:"smooth"});
});

/* ── chains are draggable by their header ───────────────────────────────
   Not by the body: rules there are draggable in their own right, for
   reordering. The header is the handle, which is also where you would grab a
   window. Auto-layout still owns everything you have not touched. */
(function chainDrag(){
  const scroll = $("#cscroll");
  let d = null;

  scroll.addEventListener("pointerdown", e=>{
    if(e.button !== 0 || TOOL === "pan") return;
    const grip = e.target.closest(".chain-hd, .chain-meta");
    if(!grip || e.target.closest("button")) return;
    const node = grip.closest(".chain");
    d = {node, dx: e.clientX/zoom - node.offsetLeft, dy: e.clientY/zoom - node.offsetTop, moved:false};
    node.setPointerCapture(e.pointerId);
    node.classList.add("dragging");
    e.preventDefault();
  });

  scroll.addEventListener("pointermove", e=>{
    if(!d) return;
    d.moved = true;
    const x = Math.max(70, e.clientX/zoom - d.dx);
    const y = Math.max(46, e.clientY/zoom - d.dy);
    d.node.style.left = x + "px";
    d.node.style.top  = y + "px";
    drawWires();
  });

  const end = ()=>{
    if(!d) return;
    if(d.moved){
      CHAIN_POS[d.node.dataset.chain] = {x: d.node.offsetLeft, y: d.node.offsetTop};
      renderMinimap();
      $("#chain-reset")?.classList.add("on");
    }
    d.node.classList.remove("dragging");
    d = null;
  };
  scroll.addEventListener("pointerup", end);
  scroll.addEventListener("pointercancel", end);
})();

$("#chain-reset").addEventListener("click", resetChainLayout);
function resetChainLayout(){
  Object.keys(CHAIN_POS).forEach(k=>delete CHAIN_POS[k]);
  $("#chain-reset")?.classList.remove("on");
  renderChains(); drawWires();
}

/* zoom
   The second argument is the point to keep still. Scaling from the corner is
   what a transform does on its own, and it throws whatever you were looking at
   off the screen — the further you are from the origin, the further it goes.
   Zooming towards the pointer is the whole difference between a canvas that
   feels steered and one that feels thrown. */
function setZoom(z, anchor){
  const sc = $("#cscroll");
  const prev = zoom;
  zoom = Math.min(1.6,Math.max(.4,z));
  $("#canvas").style.transform = `scale(${zoom})`;
  $("#canvas").style.transformOrigin = "0 0";
  $("#zl").textContent = Math.round(zoom*100)+"%";
  if(anchor && sc && prev){
    const r = sc.getBoundingClientRect();
    /* where the anchor sits on the canvas, in unscaled coordinates */
    const cx = (sc.scrollLeft + anchor.x - r.left) / prev;
    const cy = (sc.scrollTop  + anchor.y - r.top)  / prev;
    sc.scrollLeft = cx * zoom - (anchor.x - r.left);
    sc.scrollTop  = cy * zoom - (anchor.y - r.top);
  }
  syncViewport();
}
const zoomCentre = ()=>{
  const sc = $("#cscroll"); if(!sc) return undefined;
  const r = sc.getBoundingClientRect();
  return {x:r.left + sc.clientWidth/2, y:r.top + sc.clientHeight/2};
};
$("#zi").onclick = ()=>setZoom(zoom+.1, zoomCentre());
$("#zo").onclick = ()=>setZoom(zoom-.1, zoomCentre());
$("#zf").onclick = ()=>setZoom(.72);
/* The wheel zooms. It used to scroll, and zoom only with Ctrl held — but this
   is a canvas laid out in two dimensions, where scrolling by wheel reaches
   almost nothing and the thing you actually want is to get closer. Ctrl still
   works, for the hands that learned it. Shift scrolls sideways. */
$("#cscroll").addEventListener("wheel", e=>{
  if(e.shiftKey && !e.ctrlKey) return;              /* leave horizontal scroll alone */
  e.preventDefault();
  const step = e.deltaMode === 1 ? e.deltaY * 0.02 : e.deltaY * 0.0015;
  setZoom(zoom - step, {x:e.clientX, y:e.clientY});
}, {passive:false});

/* ══ CODE GENERATION ════════════════════════════════════════════════════ */
/* Tables are discovered from the model, never assumed. Hard-coding them
   silently dropped every chain of an imported ruleset whose tables were
   named anything else. */
const TOKEN = /(#.*$)|("(?:[^"\\]|\\.)*")|(@[A-Za-z_]\w*)|\b(accept|drop|reject|jump|goto|return|continue|masquerade|redirect|dnat|snat)\b|\b(table|chain|set|map|type|hook|priority|policy|elements|flags|comment|flush|ruleset|include|define)\b|\b(ct|meta|tcp|udp|icmp|ipv6-icmp|ip|ip6|inet|iif|oif|iifname|oifname|saddr|daddr|sport|dport|state|status|l4proto|limit|log|counter|rate|burst|prefix|to|with|filter|nat|srcnat|dstnat)\b|\b(\d[\w./:]*)\b/gm;
const CLS = ["c-cm","c-str","c-st","c-vd","c-kw","c-mt","c-nm"];
function highlight(line){
  let out = "", last = 0, m;
  TOKEN.lastIndex = 0;
  while((m = TOKEN.exec(line))){
    out += esc(line.slice(last, m.index));
    let cls = "c-nm";
    for(let g=1; g<=7; g++) if(m[g]!==undefined){ cls = CLS[g-1]; break; }
    if(cls==="c-vd" && /^(drop|reject)$/.test(m[0])) cls = "c-vdd";
    out += `<span class="${cls}">${esc(m[0])}</span>`;
    last = m.index + m[0].length;
  }
  return out + esc(line.slice(last));
}
function paintCode(){
  /* Each emitted line carries the rule it came from, so the code pane and the
     canvas point at each other by identity. Matching on text looked fine until
     two chains held the same rule and selecting one lit up all of them. */
  const {lines, map} = generateWithMap();
  const html = lines.map((l,i)=>{
    const o = map[i];
    const origin = o ? ` data-chain="${esc(o.uid)}" data-i="${o.i}"` : "";
    return `<div class="ln" data-ln="${i+1}"${origin}><span class="no">${i+1}</span>`
         + `<span class="tx">${highlight(l)}</span></div>`;
  }).join("");
  $("#codeout").innerHTML = html;
  $("#codeout2").innerHTML = html;
  $$(".dw-tab")[0].querySelector(".n").textContent = lines.length;
}
paintCode();

/* click a code line → select the matching rule (round-trip both ways) */
document.addEventListener("click",e=>{
  const ln = e.target.closest("#codeout .ln, #codeout2 .ln"); if(!ln) return;
  /* the line knows which rule it came from; no need to search by text, which
     used to land on whichever chain happened to hold an identical rule first */
  if(ln.dataset.chain) select(ln.dataset.chain, +ln.dataset.i, true);
});

/* ══ SELECTION + PROPERTIES ════════════════════════════════════════════ */
const EMPTY = () => `
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

SEL = null;
function select(chainId, i, fromCode){
  SEL = {chainId,i};
  const ch = chainOf(chainId);
  /* the chain may be gone — a fix deleted it, or the whole ruleset was
     replaced while a deferred select was still queued */
  if(!ch || !ch.rules[i]){ SEL = null; $("#props-body").innerHTML = EMPTY(); return; }
  const r = ch.rules[i];
  $$(".rule").forEach(x=>x.classList.toggle("sel", x.dataset.chain===chainId && +x.dataset.i===i));
  $$(".chain").forEach(x=>x.classList.toggle("focus", x.dataset.chain===chainId));

  $$("#codeout .ln, #codeout2 .ln").forEach(l=>{
    const hit = l.dataset.chain===chainId && +l.dataset.i===i;
    l.classList.toggle("hl",hit);
    if(hit && !fromCode) l.scrollIntoView({block:"center",behavior:"smooth"});
  });
  if(fromCode){
    const row = $(`.rule[data-chain="${chainId}"][data-i="${i}"]`);
    if(row){ go("editor"); row.scrollIntoView({block:"center",inline:"center",behavior:"smooth"}); }
  }
  const p = parse(r.expr);
  $("#props-body").innerHTML = `
    <div class="rule-hero">
      <div class="top">
        <span class="pill v-${r.verdict}"><span class="sw"></span>${VNAME[r.verdict]}</span>
        ${r.handle ? `<span class="chip" title="${esc(t(
            "The handle this rule had on the host it was read from — how you address it with nft on a live ruleset.",
            "El handle que tenía esta regla en el host del que se leyó — con él se la direcciona con nft en un ruleset vivo."))}"
          >handle ${r.handle}</span>` : ""}
        <div style="flex:1"></div>
        <span class="sw-toggle${r.on?" on":""}" id="rule-on" title="${t("Enable rule","Activar la regla")}"></span>
      </div>
      <div class="path">${ch.table} / ${ch.id} · ${t("position","posición")} ${i+1} ${t("of","de")} ${ch.rules.length}</div>
      <div class="expr-big">${highlight(ruleLine(r))}</div>
      ${findingsFor(chainId,i).map(f=>{
        const c = f.sev==="error" ? ["250,90,90","--v-drop"] : ["240,193,60","--warn"];
        return `<div style="display:flex;gap:8px;align-items:flex-start;margin-top:9px;padding:9px 10px;
                     border-radius:var(--r-sm);background:rgba(${c[0]},.08);border:1px solid rgba(${c[0]},.22)">
          <svg class="ico sm" style="color:var(${c[1]});margin-top:1px;flex:none" viewBox="0 0 24 24"><path d="M12 9v4m0 4h.01M10.3 3.9 2.4 17a2 2 0 0 0 1.7 3h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/></svg>
          <div style="flex:1">
            <div style="font-size:11.5px;color:var(--t1);line-height:1.45;font-weight:500">${tt(f.title)}</div>
            ${f.fix?`<button class="tb" style="height:22px;margin-top:6px;padding:0 8px;color:var(${c[1]})"
               data-fix="${FIND.indexOf(f)}">${tt(f.fix.label)}</button>`:""}
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
    for(const k of ["proto","saddr","daddr","sport","dport","iif","oif"]){
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
    renderChains(); paintCode(); drawWires(); modelChanged();
    $$(".rule").forEach(x=>x.classList.toggle("sel", x.dataset.chain===chainId && +x.dataset.i===i));
    $$(".chain").forEach(x=>x.classList.toggle("focus", x.dataset.chain===chainId));
    $(".expr-big").innerHTML = highlight(ruleLine(r));
    $$("#codeout .ln, #codeout2 .ln").forEach(l=>
      l.classList.toggle("hl", l.dataset.chain===chainId && +l.dataset.i===i));
  };
  /* Typing gives a live preview with no history entry; the change lands in
     history once, on blur — so undo steps are edits, not keystrokes. */
  ["f-saddr","f-daddr","f-sport","f-dport","f-cmt","f-proto","f-iif","f-oif","f-verdict","f-to",
   "f-limit","f-burst"]
    .forEach(id=>{
      const n = $("#"+id); if(!n) return;
      n.addEventListener("focus", ()=>{ PENDING = snapshot(); });
      const apply = () => rebuild({
        limit: $("#f-limit")?.value.trim(),
        burst: $("#f-burst")?.value.trim(),
      });
      n.addEventListener("input", apply);
      n.addEventListener("change", ()=>{
        apply();
        if(PENDING!==null){ pushHist(PENDING, t("rule edit","edición de regla")); PENDING = null; }
        /* the verdict decides which fields belong on the panel — a jump needs
           somewhere to jump to, and an accept has nowhere to put one */
        if(id==="f-verdict") select(chainId, i);
      });
    });

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
RERENDER.push(()=>{
  if(SEL) select(SEL.chainId, SEL.i);
  else $("#props-body").innerHTML = EMPTY();
});
/* Open on something real rather than a hard-coded chain that an imported or
   empty ruleset will not have. */
setTimeout(()=>{
  if(SEL) return;
  const ch = MODEL.chains.find(c=>c.hook==="input" && c.rules.length) ||
             MODEL.chains.find(c=>c.rules.length);
  if(ch) select(UID(ch), Math.min(4, ch.rules.length-1));
},400);

/* ══ PACKET SIMULATOR ═══════════════════════════════════════════════════
   The trace is evaluated against the same MODEL the code is emitted from,
   so a verdict here is the verdict the exported ruleset produces.        */
/* ── render + animate ── */
const lane = $("#lane"), traceEl = $("#trace"), pkt = $("#pkt"), vb = $("#vb");
function renderLane(res){
  lane.innerHTML = res.steps.map(h=>`
    <div class="hop" data-chain="${UID(h.chain)}" style="${h.depth?`margin-left:${h.depth*22}px`:""}">
      <span class="knob"></span>
      <div class="hop-t">
        <span class="h">${h.chain.hook || (lang() === "es"?"salto":"jump")}</span>
        <span class="c">${h.chain.id}</span>
        ${h.chain.prio!==null?`<span class="chip">prio ${h.chain.prio}</span>`:""}
        ${h.chain.policy?`<span class="pill ${h.chain.policy==="drop"?"v-drop":"v-accept"}"><span class="sw"></span>policy ${h.chain.policy}</span>`:""}
      </div>
      ${h.evs.map(e=>`
        <div class="ev" data-chain="${UID(h.chain)}" data-i="${e.i}">
          <span class="g"></span>
          <span class="x">${e.r.expr ? highlight(e.r.expr) : `<span class="c-cm">${t("any packet","cualquier paquete")}</span>`}</span>
          <span class="pill v-${e.r.verdict}"><span class="sw"></span>${VNAME[e.r.verdict]}</span>
        </div>`).join("")}
      ${h.policy?`<div class="ev" data-policy="1"><span class="g"></span>
        <span class="x"><span class="c-cm">${t("fall through to chain policy","cae a la política de la cadena")}</span></span>
        <span class="pill v-${h.policy}"><span class="sw"></span>${VNAME[h.policy]}</span></div>`:""}
    </div>`).join("");
}

timers = [];
/* step mode: the trace stops after every rule and waits to be advanced */
const STEP = {
  waiting:false, next:()=>{},
  arm(i,n){
    this.waiting = true;
    let bar = $("#step-bar");
    if(!bar){
      bar = el("div","glass"); bar.id = "step-bar";
      bar.innerHTML = `<button class="tb pri" id="step-go" style="height:26px">
          <svg class="ico" viewBox="0 0 24 24"><path d="m9 6 6 6-6 6"/></svg><span></span></button>
        <kbd>Space</kbd><span class="lbl" id="step-n"></span>
        <button class="tb" id="step-all" style="height:26px"></button>`;
      $(".sim-stage").appendChild(bar);
      $("#step-go").addEventListener("click", ()=>STEP.next());
      $("#step-all").addEventListener("click", ()=>{ packet.step = false; syncForm(); STEP.stop(); STEP.next(); });
    }
    $("#step-go span").textContent = t("Step","Paso");
    $("#step-all").textContent = t("Play the rest","Reproducir el resto");
    $("#step-n").textContent = `${i} / ${n}`;
    bar.classList.add("on");
  },
  stop(){ this.waiting = false; $("#step-bar")?.classList.remove("on"); },
};

/* Playback pace. The first pass ran at 190ms a rule, which meant four seconds
   of mostly-dimmed misses before the verdict landed — long enough to read as
   nothing happening. Fast enough to feel like a trace, slow enough to follow. */
const RULE_MS = 95, HOP_MS = 210;

/* Leaving the screen stops the trace. It used to keep firing its chain of
   timers into a pane nobody was looking at. */
function stopSim(){
  (timers || []).forEach(clearTimeout);
  timers = [];
  STEP.stop();
}

function runSim(){
  stopSim();
  const p = {...packet};
  const res = evaluate(p);
  renderLane(res);
  traceEl.innerHTML = "";
  vb.classList.remove("show");
  pkt.style.opacity = "0";
  $$(".rule").forEach(r=>r.classList.remove("trace","faded","hit"));

  const flat = [];
  res.steps.forEach(h=>{
    flat.push({type:"hop",h});
    $$(`.hop[data-chain="${UID(h.chain)}"] .ev`, lane).forEach((node,k)=>{
      flat.push({type:"ev", node, e:h.evs[k], h});
    });
  });

  const stamp = () => packet.step ? "#"+idx : (d/1000).toFixed(2)+"s";
  /* `when`, not `t` — a parameter called t shadowed the translation helper and
     the call below threw on the very first trace row, taking runSim with it. */
  const push = (cls, when, m)=>{
    const row = el("div","tr "+cls);
    row.innerHTML = `<span class="t">${when}</span><span class="m">${m}</span>`;
    traceEl.appendChild(row); traceEl.scrollTop = traceEl.scrollHeight;
    $("#tr-count").textContent = traceEl.querySelectorAll(".tr:not(.hd-row)").length + t(" steps"," pasos");
  };
  const port = n => /icmp/.test(p.proto) ? "" : ":"+n;
  push("hd-row","", `${t("packet","paquete")} ${p.proto} ${packet.saddr}${port(packet.sport)} → ${packet.daddr}${port(packet.dport)}`
     + ` · ${p.tracked ? "ct "+p.state : t("untracked","sin seguimiento")}`
     + (p.flags.length && p.proto==="tcp" ? " · "+p.flags.join("|") : "")
     + (p.iif ? ` · ${t("in","por")} ${p.iif}` : "") + (p.oif ? ` → ${p.oif}` : "")
     + (p.nat ? "" : " · "+t("NAT skipped","NAT omitido")));

  /* one frame of the trace, whether it arrives on a timer or on a keypress */
  let d = 0, idx = 0;
  const frame = f=>{
      if(f.type==="hop"){
        const hop = $(`.hop[data-chain="${UID(f.h.chain)}"]`, lane);
        hop.classList.add("done");
        $$(".hk").forEach(k=>k.classList.toggle("lit", k.dataset.hook===f.h.chain.hook));
        push("", stamp(), `${t("enter","entra en")} <b>${f.h.chain.table} / ${f.h.chain.id}</b>${f.h.chain.hook?` · hook ${f.h.chain.hook} prio ${f.h.chain.prio}`:""}`);
        return;
      }
      const {node,e} = f;
      const r = node.getBoundingClientRect(), lr = lane.parentElement.getBoundingClientRect();
      pkt.style.opacity = "1";
      pkt.style.transform = `translate(${r.left-lr.left-6}px,${r.top-lr.top+r.height/2-5}px)`;
      if(!e){ node.classList.add("match","final"); return; }
      node.classList.add(e.st==="match"?"match":"miss");
      if(e.st!=="match") node.classList.add("pass");
      /* mirror the trace back onto the editor canvas */
      const cvRow = $(`.rule[data-chain="${node.dataset.chain}"][data-i="${node.dataset.i}"]`);
      if(cvRow) cvRow.classList.add(e.st==="match"?"trace":"faded");
      if(e.st==="match"){
        if(cvRow) cvRow.classList.add("hit");
        const v = e.r.verdict;
        push(v==="accept"?"ok":(v==="drop"||v==="reject")?"no":"",
             stamp(),
             `${t("rule","regla")} ${e.i+1} ${t("matched","coincide")} → <b>${VNAME[v]}</b>${e.r.to?` <span style="color:var(--t3)">${esc(e.r.to)}</span>`:""}`);
      }
  };

  /* auto-play runs on a timer; step mode waits for Space or the button */
  const advance = ()=>{
    if(idx >= flat.length){ STEP.stop(); finish(); return; }
    const f = flat[idx++];
    d += f.type==="hop" ? HOP_MS : RULE_MS;
    frame(f);
    if(packet.step) STEP.arm(idx, flat.length);
    else timers.push(setTimeout(advance, f.type==="hop" ? HOP_MS : RULE_MS));
  };
  STEP.next = advance;
  if(packet.step) STEP.arm(0, flat.length); else advance();

  function finish(){
    const v = res.final.v, ok = v==="accept";
    const col = ok?"--v-accept":v==="reject"?"--v-reject":"--v-drop";
    $("#vb-icon").style.cssText = `width:38px;height:38px;border-radius:11px;display:grid;place-items:center;flex:none;background:rgba(255,255,255,.05);border:1px solid var(${col});color:var(${col})`;
    $("#vb-icon").innerHTML = ok
      ? `<svg class="ico lg" viewBox="0 0 24 24"><path d="m6 12 4 4 8-8"/></svg>`
      : `<svg class="ico lg" viewBox="0 0 24 24"><path d="M6 6l12 12M18 6 6 18"/></svg>`;
    $("#vb-txt").textContent = VNAME[v];
    $("#vb-txt").style.color = `var(${col})`;
    const loc = `<code>${res.final.chain.table} / ${res.final.chain.id}</code>`;
    $("#vb-why").innerHTML = res.final.policy
      ? t(`No rule in ${loc} matched — the packet fell through to the chain policy.`,
          `Ninguna regla de ${loc} ha coincidido — el paquete cae a la política de la cadena.`)
      : t(`Matched rule ${res.final.i+1} in ${loc}: <code>${esc(ruleLine(res.final.r))}</code>`,
          `Coincide la regla ${res.final.i+1} de ${loc}: <code>${esc(ruleLine(res.final.r))}</code>`);
    vb.classList.add("show");
    const n = traceEl.querySelectorAll(".tr").length-1;
    push(ok?"ok":"no","", t(`verdict <b>${VNAME[v]}</b> after ${n} evaluations`,
                            `veredicto <b>${VNAME[v]}</b> tras ${n} evaluaciones`));
    const lastHop = $$(".hop",lane).at(-1);
    if(lastHop){ lastHop.classList.add("term"); if(!ok) lastHop.classList.add("drop"); }
    pkt.style.opacity = "0";
  }
}

/* ── form ⇄ packet ── */
const HOOK_LABEL = {in:["prerouting","input"], fwd:["prerouting","forward","postrouting"], out:["output","postrouting"]};

/* An interface in nftables is a name inside a rule, not a declared object.
   Offering a closed list meant a rule mentioning vlan40 could not be edited
   without losing it — the select had no option to hold it. Suggest, never
   restrict. */
/* The literal addresses the rules carry, so the Networks palette shows your
   ruleset instead of five numbers I made up. Set references are excluded —
   they belong to the Sets category and have their own editor. */
export function addresses(){
  const m = new Map();
  MODEL.chains.forEach(ch=> ch.rules.forEach(r=>{
    if(!r.on) return;
    for(const x of r.expr.matchAll(/\bip6?\s+[sd]addr\s+(?:!=\s*)?([0-9a-fA-F.:]+(?:\/\d+)?)/g)){
      const text = x[1];
      m.set(text, {text, n:(m.get(text)?.n || 0) + 1});
    }
  }));
  return [...m.values()].sort((a,b)=>b.n-a.n);
}

/* Both halves, exactly as the Interfaces palette shows them: the names your
   rules already mention, and the ones you wrote down for the box you are
   working on. Keeping a name and then not being offered it — in the simulator
   or on a rule — makes the act of keeping it pointless. */
export function ifaceNames(){
  return [...new Set([
    ...interfaces().map(e=>e.name),
    ...project.scratch.ifaces,
    "lo",
  ])].sort();
}

function fillInterfaces(){
  const names = ifaceNames();
  const dl = $("#dl-ifaces");
  if(dl) dl.innerHTML = names.map(n=>`<option value="${esc(n)}">`).join("");

  /* The empty choice has to stay — a locally generated packet has no input
     interface, which is what the egress preset selects — but unlabelled it
     read as a blank line you could pick by accident. It is not "any": an
     absent interface matches no `iif` rule at all, where a rule without an
     iif clause matches every interface. Different things, so different words. */
  const opts = [`<option value="">${esc(t("(no interface)","(sin interfaz)"))}</option>`,
    ...names.map(n=>`<option>${esc(n)}</option>`)].join("");
  const iif = $("#sim-iif"), oif = $("#sim-oif");
  /* keep whatever the packet names even if no rule mentions it yet */
  [["#sim-iif", packet.iif], ["#sim-oif", packet.oif]].forEach(([sel, val])=>{
    const n = $(sel); if(!n) return;
    n.innerHTML = opts + (val && !names.includes(val) ? `<option>${esc(val)}</option>` : "");
    n.value = val || "";
  });
}

function syncForm(){
  $$("#sim-dir button").forEach(b=>b.classList.toggle("on", b.dataset.dir===packet.dir));
  $("#fld-iif").style.display = packet.dir==="out" ? "none" : "";
  $("#fld-oif").style.display = packet.dir==="in"  ? "none" : "";
  $("#fld-flags").style.display = packet.proto==="tcp" ? "" : "none";
  $("#fld-dport").style.display = /icmp/.test(packet.proto) ? "none" : "";
  $("#sim-path").textContent = HOOK_LABEL[packet.dir]
    .filter(h=> packet.nat || MODEL.chains.some(c=>c.hook===h && c.type!=="nat"))
    .join(" → ");
  $("#sim-saddr").value = packet.saddr; $("#sim-sport").value = packet.sport;
  $("#sim-daddr").value = packet.daddr; $("#sim-dport").value = packet.dport;
  $("#sim-proto").value = packet.proto; $("#sim-state").value = packet.state;
  $("#sim-iif").value = packet.iif || ""; $("#sim-oif").value = packet.oif || "";
  $$("#sim-flags button").forEach(b=>b.classList.toggle("on", packet.flags.includes(b.dataset.flag)));
  $$("#sim-flags button").forEach(b=> b.style.cssText = b.classList.contains("on")
    ? "color:var(--aqua);border-color:var(--aqua-line);background:var(--aqua-wash)" : "");
  $("#opt-ct").classList.toggle("on", packet.tracked);
  $("#opt-nat").classList.toggle("on", packet.nat);
  $("#opt-step").classList.toggle("on", packet.step);
  $("#sim-state").disabled = !packet.tracked;
  $("#sim-state").style.opacity = packet.tracked ? "1" : ".4";
}
function readForm(){
  packet.saddr = $("#sim-saddr").value.trim();
  packet.daddr = $("#sim-daddr").value.trim();
  packet.sport = +$("#sim-sport").value || 0;
  packet.dport = +$("#sim-dport").value || 0;
  packet.proto = $("#sim-proto").value;
  packet.state = $("#sim-state").value;
  packet.iif = $("#sim-iif").value;
  packet.oif = $("#sim-oif").value;
}

$("#sim-dir").addEventListener("click", e=>{
  const b = e.target.closest("[data-dir]"); if(!b) return;
  packet.dir = b.dataset.dir;
  if(packet.dir==="out" ) packet.iif = "";
  if(packet.dir==="in"  ) packet.oif = "";
  if(packet.dir!=="in" && !packet.oif) packet.oif = "wan0";
  if(packet.dir!=="out" && !packet.iif) packet.iif = "wan0";
  syncForm(); runSim();
});
$("#sim-flags").addEventListener("click", e=>{
  const b = e.target.closest("[data-flag]"); if(!b) return;
  const f = b.dataset.flag;
  packet.flags = packet.flags.includes(f) ? packet.flags.filter(x=>x!==f) : [...packet.flags, f];
  syncForm(); runSim();
});
$("#opt-ct").addEventListener("click", ()=>{ packet.tracked = !packet.tracked; syncForm(); runSim(); });
$("#opt-nat").addEventListener("click", ()=>{ packet.nat = !packet.nat; syncForm(); runSim(); });
$("#opt-step").addEventListener("click", ()=>{ packet.step = !packet.step; syncForm(); runSim(); });
$$("#s-sim input[type=text], #s-sim select").forEach(n=>{
  n.addEventListener("change", ()=>{ readForm(); syncForm(); runSim(); });
});
$(".sim-form .panel-hd .tb").addEventListener("click", ()=>{
  Object.assign(packet, {...PRESETS.ssh}); syncForm(); runSim();
});

$("#run-sim").addEventListener("click", ()=>{ readForm(); runSim(); });
$$("[data-preset]").forEach(b=>b.addEventListener("click",()=>{
  Object.assign(packet, {...PRESETS[b.dataset.preset], flags:[...PRESETS[b.dataset.preset].flags]});
  $$("[data-preset]").forEach(x=>x.style.cssText="");
  b.style.cssText = "color:var(--aqua);border-color:var(--aqua-line);background:var(--aqua-wash)";
  syncForm(); runSim();
}));
document.addEventListener("keydown",e=>{
  const onSim = $("#s-sim").classList.contains("on");
  if(e.key==="Enter" && onSim && !e.target.closest("input")) runSim();
  if(e.code==="Space" && onSim && STEP.waiting && !e.target.closest("input,textarea")){
    e.preventDefault(); STEP.next();
  }
  if((e.ctrlKey||e.metaKey) && e.shiftKey && e.key.toLowerCase()==="r"){ e.preventDefault(); go("sim"); runSim(); }
});
fillInterfaces(); syncForm();
MODEL_HOOKS.push(fillInterfaces);

/* ══ CODE VARIANTS ═════════════════════════════════════════════════════
   Full is the ruleset. Delta is what you would send to a running box.
   Atomic is the same ruleset wrapped so a syntax error changes nothing. */
CODE_VARIANT = "full";
function codeLines(mode){
  const base = generate();
  if(mode==="delta"){
    const L = ["# incremental delta — apply with: nft -f -", ""];
    MODEL.chains.forEach(ch=>{
      L.push(`flush chain ${ch.table} ${ch.id}`);
      ch.rules.filter(r=>r.on).forEach(r=>
        L.push(`add rule ${ch.table} ${ch.id} ${ruleLine(r)}${r.cmt?` comment "${r.cmt}"`:""}`));
      L.push("");
    });
    if(L.at(-1)==="") L.pop();
    return L;
  }
  if(mode==="atomic"){
    return ["# atomic apply — the kernel sees all of this or none of it",
            "# validate first:  nft -c -f this-file",
            "", ...base.filter(l=>l!=="#!/usr/sbin/nft -f")];
  }
  return base;
}

/* ══ DIFF ══════════════════════════════════════════════════════════════
   Against the baseline: whatever was last imported, opened or exported. */
BASELINE = null;
const setBaseline = () => { BASELINE = generate().join("\n"); paintDrawer(); };

/* classic LCS diff — the rulesets are small enough that clarity wins */
DW_TAB = "code";
function paintDrawer(){
  const cur = codeLines(CODE_VARIANT);
  const diff = BASELINE ? diffLines(BASELINE.split("\n"), generate()) : [];
  const adds = diff.filter(d=>d[0]==="+").length, dels = diff.filter(d=>d[0]==="-").length;

  const tabs = $$(".dw-tab");
  tabs[0].querySelector(".n").textContent = cur.length;
  tabs[1].querySelector(".n").textContent = adds||dels ? `+${adds} −${dels}` : "—";
  tabs[2].querySelector(".n").textContent = FIND.filter(f=>f.sev!=="hint").length;
  tabs.forEach(b=>b.classList.toggle("on", b.dataset.dw===DW_TAB));

  $("#codeout").style.display    = DW_TAB==="code" ? "" : "none";
  $("#dw-diff").style.display    = DW_TAB==="diff" ? "" : "none";
  $("#dw-problems").style.display= DW_TAB==="problems" ? "" : "none";

  if(DW_TAB==="diff"){
    $("#dw-diff").innerHTML = diff.length && (adds||dels)
      ? diff.map(([k,line])=>{
          const cls = k==="+" ? "add" : k==="-" ? "del" : "";
          return `<div class="ln ${cls}"><span class="no">${k==="+"?"+":k==="-"?"−":""}</span>` +
                 `<span class="tx">${highlight(line)}</span></div>`;
        }).join("")
      : `<div style="padding:34px;text-align:center;color:var(--t4);font-size:12px">
           ${t("No changes since the last import or export.","Sin cambios desde la última importación o exportación.")}</div>`;
  }
  if(DW_TAB==="problems"){
    $("#dw-problems").innerHTML = FIND.length ? FIND.map(f=>`
      <div class="ln" style="grid-template-columns:22px 1fr;cursor:pointer;padding:3px 0"
           ${f.chain?`data-goto="${FIND.indexOf(f)}"`:""}>
        <span class="no" style="color:var(--${f.sev==="error"?"v-drop":f.sev==="warn"?"warn":"t4"})">●</span>
        <span class="tx" style="white-space:normal;padding-right:20px">
          <span style="color:var(--t1)">${tt(f.title)}</span>
          <span style="color:var(--t4)"> · ${f.where}</span></span>
      </div>`).join("")
      : `<div style="padding:34px;text-align:center;color:var(--t4);font-size:12px">
           ${t("No problems found.","Sin problemas.")}</div>`;
  }
}
$(".dw-hd").addEventListener("click", e=>{
  const b = e.target.closest("[data-dw]"); if(!b) return;
  DW_TAB = b.dataset.dw; paintDrawer();
  $("#drawer").classList.remove("min");
});
$("#code-variant").addEventListener("click", e=>{
  const b = e.target.closest("[data-cv]"); if(!b) return;
  CODE_VARIANT = b.dataset.cv;
  const lines = codeLines(CODE_VARIANT);
  $("#codeout2").innerHTML = lines.map((l,i)=>
    `<div class="ln"><span class="no">${i+1}</span><span class="tx">${highlight(l)}</span></div>`).join("");
  $$("#s-code .panel-hd .chip")[0].textContent = t(`${lines.length} lines`,`${lines.length} líneas`);
});

/* ══ CANVAS TOOLS ══════════════════════════════════════════════════════ */
TOOL = "select";
$(".cv-tools").addEventListener("click", e=>{
  const b = e.target.closest("[data-tool]"); if(!b) return;
  TOOL = b.dataset.tool;
  $$("[data-tool]").forEach(x=>x.classList.toggle("on", x===b));
  $("#cscroll").style.cursor = TOOL==="pan" ? "grab" : "";
});
(function panning(){
  const sc = $("#cscroll");
  let drag = null;

  /* Empty canvas. Everything listed here has its own answer to being dragged:
     a card moves, a rule reorders, a control is pressed. What is left is the
     background, and dragging the background is how every canvas moves. */
  const onBackground = node =>
    !node.closest(".chain, .rule, .addrule, button, input, select, textarea, .cv-tools, .minimap, .legend, .hop, .ev");

  sc.addEventListener("pointerdown", e=>{
    const middle = e.button===1;                        /* middle-drag always pans */
    const bg = e.button===0 && onBackground(e.target);
    if(!(TOOL==="pan" || middle || bg)) return;
    if(e.target.closest(".rule, .addrule, button")) return;
    drag = {x:e.clientX, y:e.clientY, l:sc.scrollLeft, t:sc.scrollTop, moved:false};
    sc.setPointerCapture(e.pointerId);
    sc.style.scrollBehavior = "auto";
    /* Not on a plain left press: the click that follows still has to reach the
       canvas, and there is nothing on the background to select by dragging. */
    if(!bg){ sc.style.cursor = "grabbing"; e.preventDefault(); }
  });
  sc.addEventListener("pointermove", e=>{
    if(!drag) return;
    const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
    if(!drag.moved && Math.abs(dx) + Math.abs(dy) < 3) return;   /* a press is not a drag */
    if(!drag.moved){ drag.moved = true; sc.style.cursor = "grabbing"; }
    sc.scrollLeft = drag.l - dx;
    sc.scrollTop  = drag.t - dy;
  });
  const end = ()=>{ if(!drag) return; drag = null;
    sc.style.cursor = TOOL==="pan" ? "grab" : ""; sc.style.scrollBehavior = ""; };
  sc.addEventListener("pointerup", end);
  sc.addEventListener("pointercancel", end);
})();
document.addEventListener("keydown", e=>{
  if(e.target.closest("input, textarea, select")) return;
  if(e.key==="v" || e.key==="V") $('[data-tool="select"]')?.click();
  if(e.key==="h" || e.key==="H") $('[data-tool="pan"]')?.click();
});

/* ══ FLOATING PROPERTIES ═══════════════════════════════════════════════ */
$("#props-float").addEventListener("click", ()=>{
  const aside = $(".props");
  if(aside.classList.contains("floating")){ dockProps(); return; }
  const r = aside.getBoundingClientRect();
  aside.classList.add("floating");
  aside.style.cssText = `left:${Math.max(12, r.left-360)}px;top:${r.top+18}px;width:330px;height:min(560px,70vh)`;
  const bar = el("div","float-bar");
  bar.innerHTML = `<svg class="ico sm" viewBox="0 0 24 24"><path d="M5 9h14M5 15h14"/></svg>
    <span class="lbl" style="flex:1">${t("Properties","Propiedades")}</span>
    <button class="tb icon" id="props-dock"><svg class="ico sm" viewBox="0 0 24 24"><path d="M6 6l12 12M18 6 6 18"/></svg></button>`;
  aside.prepend(bar);
  $("#props-dock").addEventListener("click", dockProps);

  let drag = null;
  bar.addEventListener("pointerdown", e=>{
    if(e.target.closest("button")) return;
    const b = aside.getBoundingClientRect();
    drag = {x:e.clientX-b.left, y:e.clientY-b.top};
    bar.setPointerCapture(e.pointerId);
  });
  bar.addEventListener("pointermove", e=>{
    if(!drag) return;
    aside.style.left = Math.min(window.innerWidth-120, Math.max(0, e.clientX-drag.x))+"px";
    aside.style.top  = Math.min(window.innerHeight-60, Math.max(44, e.clientY-drag.y))+"px";
  });
  bar.addEventListener("pointerup", ()=>{ drag = null; });
});
function dockProps(){
  const aside = $(".props");
  aside.classList.remove("floating");
  aside.style.cssText = "";
  $(".float-bar")?.remove();
}

MODEL_HOOKS.push(paintDrawer);
RERENDER.push(paintDrawer);
setBaseline();

/* ══ BOOT ═══════════════════════════════════════════════════════════════ */
function counts(){
  const rules = MODEL.chains.reduce((a,c)=>a+c.rules.length,0);
  const tables = new Set(MODEL.chains.map(c=>c.table)).size;
  $("#st-counts").textContent = t(
    `${tables} tables · ${MODEL.chains.length} chains · ${rules} rules · ${MODEL.sets.length} sets`,
    `${tables} tablas · ${MODEL.chains.length} cadenas · ${rules} reglas · ${MODEL.sets.length} sets`);
  $("#kpi-rules").textContent = rules;
}
RERENDER.push(counts);
/* the status bar counts the ruleset, so it has to follow it */
MODEL_HOOKS.push(counts);

go("dash");
/* the screen may be gone by the time this lands */
setTimeout(()=>{ if($("#s-sim")?.classList.contains("on")) runSim(); },600);

/* ══ ANALYSER ═══════════════════════════════════════════════════════════
   Findings are derived from MODEL, never authored. The core relation is
   subsumption: rule A subsumes rule B when every packet matching B also
   matches A. If A comes first and terminates, B is dead code.           */

/* ══ FINDINGS · rendering and wiring ════════════════════════════════════ */
VFILTER = "all";
const SEV = {
  error:{cls:"v-drop",   col:"var(--v-drop)", nm:["error","error"]},
  warn: {cls:"v-warn",   col:"var(--warn)",   nm:["warning","aviso"]},
  hint: {cls:"v-neutral",col:"var(--t4)",     nm:["hint","sugerencia"]},
};
const tt = p => t(p[0],p[1]);
const CARET = '<svg class="ico tw" viewBox="0 0 24 24"><path d="m9 6 6 6-6 6"/></svg>';

function codeBlock(rows){
  return `<pre>${rows.map(([n,txt,kind])=>{
    const gut = `<span class="c-cm">${String(n).padStart(4," ")}  </span>`;
    const body = kind==="dead" ? `<span style="opacity:.5">${highlight(txt)}</span>`
                : kind==="pos" ? `<span style="color:var(--v-accept)">${highlight(txt)}</span>`
                : highlight(txt);
    const tag = kind==="dead" ? `  <span class="c-cm">${t("← never reached","← nunca se alcanza")}</span>` : "";
    return gut + body + tag;
  }).join("\n")}</pre>`;
}

function renderFindings(){
  setFindings(analyse()); FIND = findings.list;
  const n = s => FIND.filter(f=>f.sev===s).length;
  const errs = n("error"), warns = n("warn"), hints = n("hint");
  const fixable = FIND.filter(f=>f.fix).length;

  /* grade — errors dominate, hints barely register */
  const score = Math.max(0, 100 - errs*26 - warns*9 - hints*2);
  const grade = score>=93?"A":score>=85?"A−":score>=75?"B+":score>=65?"B":score>=50?"C":"D";
  const tone  = score>=85 ? ["--v-accept","71,224,130"]
              : score>=65 ? ["--v-reject","240,160,60"]
              :             ["--v-drop","250,90,90"];
  const gcol = tone[0];
  const g = $("#val-grade");
  g.textContent = grade;
  g.style.cssText = `background:rgba(${tone[1]},.1);border-color:rgba(${tone[1]},.28);color:var(${gcol})`;

  const rules = MODEL.chains.reduce((a,c)=>a+c.rules.filter(r=>r.on).length,0);
  $("#val-sub").textContent = t(
    `Checked ${rules} rules across ${MODEL.chains.length} chains · worst case ${worstCase()} evaluations per packet`,
    `${rules} reglas revisadas en ${MODEL.chains.length} cadenas · peor caso ${worstCase()} evaluaciones por paquete`);
  $("#val-fixall-t").textContent = fixable
    ? t(`Fix ${fixable} automatically`,`Corregir ${fixable} automáticamente`)
    : t("Nothing to fix","Nada que corregir");
  $("#val-fixall").disabled = !fixable;

  const tabs = [["all",t("All","Todo"),FIND.length,null],
                ["error",t("Errors","Errores"),errs,"var(--v-drop)"],
                ["warn",t("Warnings","Avisos"),warns,"var(--warn)"],
                ["hint",t("Hints","Sugerencias"),hints,"var(--t4)"]];
  $("#val-tabs").innerHTML = tabs.map(([k,label,count,col])=>
    `<button class="val-tab${k===VFILTER?" on":""}" data-vf="${k}">
       ${col?`<span style="color:${col}">●</span>`:""}${label}
       <span class="chip" style="height:17px">${count}</span></button>`).join("");

  const shown = FIND.filter(f=>VFILTER==="all" || f.sev===VFILTER);
  $("#findings").innerHTML = shown.length ? shown.map((f,idx)=>{
    const s = SEV[f.sev];
    return `<details class="finding" data-fi="${FIND.indexOf(f)}"${idx===0?" open":""}>
      <summary>
        <span class="sev" style="background:${s.col}"></span>
        <span class="pill ${f.sev==="error"?"v-drop":f.sev==="warn"?"v-warnp":"v-neutral"}"><span class="sw"></span>${tt(s.nm)}</span>
        <span class="ttl"><div class="h">${tt(f.title)}</div><div class="l">${f.where} · ${f.kind}</div></span>
        ${CARET}
      </summary>
      <div class="finding-body">
        <p>${tt(f.detail)}</p>
        ${f.code?codeBlock(f.code):""}
        <div class="acts">
          ${f.fix?`<button class="tb accent" data-fix="${FIND.indexOf(f)}">${tt(f.fix.label)}</button>`:""}
          ${f.chain?`<button class="tb" data-goto="${FIND.indexOf(f)}">${t("Go to rule","Ir a la regla")}</button>`:""}
          ${f.go?`<button class="tb" data-go="${f.go}">${t("Open in Set Manager","Abrir en el gestor de sets")}</button>`:""}
          <button class="tb" data-mute="${FIND.indexOf(f)}">${t("Suppress","Silenciar")}</button>
        </div>
      </div>
    </details>`;
  }).join("") : `
    <div style="text-align:center;padding:64px 24px">
      <div style="width:56px;height:56px;margin:0 auto 14px;border-radius:16px;display:grid;place-items:center;
                  background:rgba(71,224,130,.09);border:1px solid rgba(71,224,130,.24);color:var(--v-accept)">
        <svg class="ico lg" viewBox="0 0 24 24"><path d="m6 12 4 4 8-8"/></svg></div>
      <div style="font:600 14px var(--sans);margin-bottom:5px">${t("Nothing to report","Nada que reportar")}</div>
      <div style="font-size:12px;color:var(--t4)">${t("No findings at this severity.","Ningún hallazgo con esta severidad.")}</div>
    </div>`;

  /* ── optimiser mirror: only the findings that carry an automatic fix ── */
  const acts = FIND.filter(f=>f.fix);
  $("#opt-count").textContent = t(`${acts.length} suggestions`,`${acts.length} sugerencias`);
  $("#opt-applyall").disabled = !acts.length;
  $("#opt-panel").innerHTML = acts.map(f=>`
    <div class="opt-card">
      <div class="t">
        <span class="pill ${f.sev==="error"?"v-drop":f.sev==="warn"?"v-warnp":"v-accept"}"><span class="sw"></span>${f.kind}</span>
        <h4>${tt(f.title)}</h4>
        <button class="tb" style="height:23px" data-fix="${FIND.indexOf(f)}">${tt(f.fix.label)}</button>
      </div>
      <p>${tt(f.detail)}</p>
      ${f.code?`<div class="before-after">${codeBlock(f.code)}</div>`:""}
    </div>`).join("");

  /* ── badges everywhere agree with the analyser ── */
  const bad = errs + warns;
  const rb = $('.rb[data-go="validate"] .bdg');
  if(rb){ rb.textContent = bad; rb.style.display = bad?"":"none"; }
  const tbPill = $('#bar [data-go="validate"] .pill');
  if(tbPill){ tbPill.textContent = bad; tbPill.style.display = bad?"":"none"; }
  $("#st-problems").innerHTML = errs||warns
    ? t(`${errs} error${errs===1?"":"s"} · ${warns} warning${warns===1?"":"s"}`,
        `${errs} error${errs===1?"":"es"} · ${warns} aviso${warns===1?"":"s"}`)
    : t("No problems","Sin problemas");
  $("#st-worst").textContent = worstCase();
  const kg = $("#kpi-grade");
  if(kg){ kg.textContent = grade; kg.style.color = `var(${gcol})`; }
  const kb = $("#kpi-breakdown");
  if(kb) kb.innerHTML =
    `<span><span style="color:var(--v-drop)">●</span> ${errs} ${t("error"+(errs===1?"":"s"),"error"+(errs===1?"":"es"))}</span>
     <span><span style="color:var(--warn)">●</span> ${warns} ${t("warning"+(warns===1?"":"s"),"aviso"+(warns===1?"":"s"))}</span>
     <span><span style="color:var(--t4)">●</span> ${hints} ${t("hint"+(hints===1?"":"s"),"sugerencia"+(hints===1?"":"s"))}</span>`;
  const kw = $("#kpi-worst"); if(kw) kw.textContent = worstCase();
  const mb = $(".kpi .mini-bar i");
  if(mb) mb.style.width = Math.min(100, worstCase()/40*100).toFixed(0)+"%";

  /* ── carry the flags back onto the canvas: a finding is visible where the
        rule lives, not only in a panel you have to go looking for ── */
  $$(".rule").forEach(x=>x.classList.remove("warn","err"));
  FIND.forEach(f=>{
    if(!f.chain) return;
    const row = $(`.rule[data-chain="${UID(f.chain)}"][data-i="${f.i}"]`);
    if(row) row.classList.add(f.sev==="error"?"err":"warn");
  });
}
const findingsFor = (uid,i) => FIND.filter(f=>f.chain && UID(f.chain)===uid && f.i===i);

/* ── interactions ── */
document.addEventListener("click",e=>{
  const tab = e.target.closest("[data-vf]");
  if(tab){ VFILTER = tab.dataset.vf; renderFindings(); return; }

  const fx = e.target.closest("[data-fix]");
  if(fx){
    const f = FIND[+fx.dataset.fix];
    edit(tt(f.fix.label).toLowerCase(), f.fix.run);
    toast(t("Applied — Ctrl+Z to undo","Aplicado — Ctrl+Z para deshacer"));
    return;
  }
  const gt = e.target.closest("[data-goto]");
  if(gt){
    const f = FIND[+gt.dataset.goto];
    go("editor");
    setTimeout(()=>select(UID(f.chain), Math.min(f.i, f.chain.rules.length-1), true), 60);
    return;
  }
  const mu = e.target.closest("[data-mute]");
  if(mu){ mu.closest(".finding").style.display = "none"; return; }
});

$("#val-rerun").addEventListener("click",e=>{
  const ico = e.currentTarget.querySelector(".ico");
  ico.animate([{transform:"rotate(0)"},{transform:"rotate(360deg)"}],{duration:520,easing:"cubic-bezier(.23,1,.32,1)"});
  renderFindings();
});
const applyAll = ()=>{
  let n = 0;
  /* one edit() for the batch — "apply all" should undo as one action */
  edit(t("apply all suggestions","aplicar todas las sugerencias"), ()=>{
    /* apply one at a time, re-analysing between, since each fix shifts indices */
    for(let guard=0; guard<25; guard++){
      const f = analyse().find(x=>x.fix);
      if(!f) break;
      f.fix.run(); n++;
    }
  });
  toast(t(`${n} fixes applied — Ctrl+Z to undo`,`${n} correcciones aplicadas — Ctrl+Z para deshacer`));
};
$("#val-fixall").addEventListener("click",applyAll);
$("#opt-applyall").addEventListener("click",applyAll);

MODEL_HOOKS.push(renderFindings);
RERENDER.push(renderFindings);

applyLang();   /* paints every data-t/-tp/-tt and runs every RERENDER hook */

/* ══ CANVAS EDITING ═════════════════════════════════════════════════════ */

/* ── add / duplicate / delete ── */
function addRule(chainId){
  const ch = chainOf(chainId);
  edit(t("add rule","añadir regla"), ()=>{
    ch.rules.push(R("", ch.policy==="drop" ? "accept" : "drop", {pkts:0,bytes:0}));
  });
  select(chainId, ch.rules.length-1);
  const row = $(`.rule[data-chain="${chainId}"][data-i="${ch.rules.length-1}"]`);
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
ctxEl = null;
const killCtx = ()=>{ if(ctxEl){ ctxEl.remove(); ctxEl = null; } };
document.addEventListener("click", killCtx, true);
document.addEventListener("scroll", killCtx, true);
document.addEventListener("keydown", e=>{ if(e.key==="Escape") killCtx(); });

function openCtx(x, y, items){
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
    if(a.dataset.act==="new")   openChain(null);
    if(a.dataset.act==="props") openChain(cid);
    if(a.dataset.act==="del"){  openChain(cid); $("#ch-delete").click(); }
    if(a.dataset.act==="sim"){  go("sim"); runSim(); }
    killCtx();
  });
});

/* ── keyboard ── */
document.addEventListener("keydown", e=>{
  const typing = e.target.closest("input, textarea, select");
  const mod = e.ctrlKey || e.metaKey;

  if(mod && e.key.toLowerCase()==="z" && !e.shiftKey){ e.preventDefault(); undo(); return; }
  if(mod && (e.key.toLowerCase()==="y" || (e.shiftKey && e.key.toLowerCase()==="z"))){ e.preventDefault(); redo(); return; }
  /* rule shortcuts belong to the editor canvas only */
  if(typing || !SEL || !$("#s-editor").classList.contains("on")) return;

  const ch = chainOf(SEL.chainId);
  if(e.key==="Delete" || e.key==="Backspace"){ e.preventDefault(); deleteRule(SEL.chainId, SEL.i); return; }
  if(mod && e.key.toLowerCase()==="d"){ e.preventDefault(); duplicateRule(SEL.chainId, SEL.i); return; }
  if(mod && e.key==="Enter"){ e.preventDefault(); addRule(SEL.chainId); return; }
  if(e.altKey && e.key==="ArrowUp"){   e.preventDefault(); moveRule(SEL.chainId, SEL.i, SEL.i-1); return; }
  if(e.altKey && e.key==="ArrowDown"){ e.preventDefault(); moveRule(SEL.chainId, SEL.i, SEL.i+1); return; }
  if(e.key==="ArrowUp"   && SEL.i>0){                 e.preventDefault(); select(SEL.chainId, SEL.i-1); }
  if(e.key==="ArrowDown" && SEL.i<ch.rules.length-1){ e.preventDefault(); select(SEL.chainId, SEL.i+1); }
});

$("#undo").addEventListener("click", undo);
$("#redo").addEventListener("click", redo);

/* ══ DRAG & DROP ════════════════════════════════════════════════════════
   Two payloads share one pipeline: a library object (creates or amends a
   rule) and a rule being reordered (order is semantics, so this is an
   edit, not a cosmetic move).                                           */
DRAG = null;
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
    case "ME": return {expr:name==="limit rate" ? "limit rate 5/second burst 10 packets" : "limit rate over 100/second"};
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
      return {verdict:"dnat", to:""};
    }
    /* `pkts = 1` claimed one packet the rule had never seen, which is the lie
       the counter split was made to remove. `ctr` is the statement. */
    case "CN": return {ctr:true};
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
  return {x:(e.clientX - c.left)/zoom, y:(e.clientY - c.top)/zoom};
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
    openChain(null);
    $("#ch-name").value = named ? hook : "";
    $("#ch-hook").value = hook;
    if(DRAG?.n === "regular chain") $('#ch-kind [data-kind="regular"]')?.click();
    chSync();
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
    openChain(null); $("#ch-hook").value = hook; chSync();
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

CUR = snapshot();
syncHistUI();

/* ══ IMPORT ═════════════════════════════════════════════════════════════
   Parses `nft list ruleset` output. The expression is kept verbatim minus
   the counter and comment, which is what makes a byte-faithful round-trip
   possible — we re-emit what we were given, not our idea of it.         */

/* ══ IMPORT UI ═════════════════════════════════════════════════════════
   The rulesets on offer live in core/samples.js, where the tests can hold
   them to the same round-trip they promise the user.                     */

IMPORTED = null;
function reviewImport(){
  const text = $("#imp-text").value.trim();
  const side = $("#imp-side"), btn = $("#imp-go");
  if(!text){
    IMPORTED = null; btn.disabled = true;
    side.innerHTML = `<div class="imp-sec" style="border:none;text-align:center;padding:44px 20px">
      <div style="width:52px;height:52px;margin:0 auto 12px;border-radius:15px;display:grid;place-items:center;
                  border:1px dashed var(--line-2);color:var(--t4)">
        <svg class="ico lg" viewBox="0 0 24 24"><path d="M12 16V3"/><path d="m7 8 5-5 5 5"/><path d="M4 21h16"/></svg></div>
      <div style="font:600 12.5px var(--sans);color:var(--t2);margin-bottom:5px">${t("Nothing to read yet","Nada que leer todavía")}</div>
      <div style="font-size:11.5px;color:var(--t4);line-height:1.6">${t(
        "Paste a ruleset and eFeFlow will parse it, re-emit every rule, and show you where the two disagree before anything is imported.",
        "Pega un ruleset y eFeFlow lo analizará, reemitirá cada regla y te enseñará dónde discrepan antes de importar nada.")}</div>
    </div>`;
    return;
  }

  /* verify() checks the whole file, not only its rules. The rule-level count
     could report a clean 100% on a ruleset whose netdev chain had lost its
     device or whose flowtable had been dropped, because neither is a rule. */
  const rt = verify(text);
  const p = rt.parsed;
  const rules = p.chains.reduce((a,c)=>a+c.rules.length,0);
  IMPORTED = {p, rt};
  btn.disabled = !rules;
  $("#imp-go-t").textContent = t(`Import ${rules} rules`,`Importar ${rules} reglas`);

  const pct = rt.total ? Math.round(rt.ok/rt.total*100) : 0;
  const good = rt.diffs.length===0;
  const col = good ? ["71,224,130","--v-accept"] : pct>=90 ? ["240,193,60","--warn"] : ["250,90,90","--v-drop"];

  side.innerHTML = `
    <div class="imp-sec">
      <span class="lbl" style="display:block;margin-bottom:9px">${t("Round-trip check","Verificación de ida y vuelta")}</span>
      <div class="rt-badge">
        <div class="ring" style="background:rgba(${col[0]},.12);border:1px solid rgba(${col[0]},.3);color:var(${col[1]})">${pct}%</div>
        <div class="tx"><b>${rt.ok} / ${rt.total} ${t("lines","líneas")}</b>${
          good ? t("re-emit identically — rules, chain headers, sets and every object. Nothing was lost in translation.",
                   "se reemiten idénticas — reglas, cabeceras de cadena, sets y cada objeto. No se ha perdido nada en la traducción.")
               : t("re-emit identically. The rest are shown below.",
                   "se reemiten idénticas. El resto se muestra abajo.")}</div>
      </div>
      ${rt.diffs.slice(0,4).map(d=>`<div class="rt-diff">
        <div class="a">− ${esc(d.src)}</div><div class="b">+ ${esc(d.out)}</div></div>`).join("")}
      ${rt.diffs.length>4?`<div style="font-size:11px;color:var(--t4);margin-top:6px">
        + ${rt.diffs.length-4} ${t("more","más")}</div>`:""}
    </div>

    <div class="imp-sec">
      <span class="lbl" style="display:block;margin-bottom:7px">${t("Parsed","Analizado")}</span>
      <div class="imp-stat"><span class="k">${t("Tables","Tablas")}</span><span class="v">${new Set(p.chains.map(c=>c.table)).size}</span></div>
      <div class="imp-stat"><span class="k">${t("Chains","Cadenas")}</span><span class="v">${p.chains.length}</span></div>
      <div class="imp-stat"><span class="k">${t("Rules","Reglas")}</span><span class="v">${rules}</span></div>
      <div class="imp-stat"><span class="k">${t("Sets","Sets")}</span><span class="v">${p.sets.length}</span></div>
      ${p.objects.length?`<div class="imp-stat"><span class="k" title="${esc(t(
        "Flowtables, named counters and quotas, ct helpers — carried through unchanged.",
        "Flowtables, counters y quotas con nombre, helpers de ct — se conservan sin tocar."))}"
        >${t("Objects carried","Objetos conservados")}</span><span class="v">${p.objects.length}</span></div>`:""}
      ${p.errors.length?`<div class="imp-stat"><span class="k" style="color:var(--warn)">${t("Unparsed lines","Líneas no analizadas")}</span>
        <span class="v" style="color:var(--warn)">${p.errors.length}</span></div>`:""}
    </div>

    <div class="imp-sec" style="flex:1">
      <span class="lbl" style="display:block;margin-bottom:7px">${t("Chains found","Cadenas encontradas")}</span>
      ${p.chains.map(c=>`<div style="display:flex;align-items:center;gap:7px;padding:5px 0">
        <span style="color:var(--${c.policy==="drop"?"v-drop":"v-accept"});font-size:9px">◆</span>
        <span style="font:600 11.5px var(--mono);flex:1">${esc(c.id)}</span>
        <span class="chip" style="height:17px">${c.hook ? c.hook+" "+c.prio : t("regular","regular")}</span>
        <span style="font:500 10px var(--mono);color:var(--t4)">${c.rules.length}</span>
      </div>`).join("")}
      ${p.errors.length?`<div style="margin-top:10px;padding:9px 10px;border-radius:var(--r-sm);
        background:rgba(240,193,60,.08);border:1px solid rgba(240,193,60,.22)">
        <div style="font-size:11px;color:var(--t2);line-height:1.5">${t(
          "These lines were not understood and will be dropped:","Estas líneas no se entendieron y se descartarán:")}</div>
        ${p.errors.slice(0,3).map(e=>`<div class="mono" style="font-size:10.5px;color:var(--t3);margin-top:4px">
          ${t("line","línea")} ${e.ln}: ${esc(e.line.slice(0,54))}</div>`).join("")}
      </div>`:""}
    </div>`;
}

$("#imp-text").addEventListener("input", reviewImport);
/* Worked scenarios, so the import path can be tried without a host and so the
   shapes people actually need — port forwarding, a tunnel, a balancer — can be
   read as rules rather than described in a manual. */
function fillSamples(){
  const sel = $("#imp-sample"); if(!sel) return;
  const keep = sel.value;
  sel.innerHTML = [
    `<option value="">${esc(t("Load an example…","Cargar un ejemplo…"))}</option>`,
    ...SAMPLES.map(s=>`<option value="${esc(s.id)}">${esc(t(s.title.en, s.title.es))}</option>`),
  ].join("");
  sel.value = keep;                       /* a language switch is not a choice */
}
$("#imp-sample").addEventListener("change", e=>{
  const s = sampleById(e.target.value); if(!s) return;
  /* The description rides in as an nft comment. The parser skips `#` lines and
     so does the round-trip check, so it costs nothing, and it stays with the
     text if you paste it somewhere else — in whichever language you are in. */
  $("#imp-text").value =
    `# ${t(s.title.en, s.title.es)}\n# ${t(s.blurb.en, s.blurb.es)}\n\n${s.nft}`;
  reviewImport();
});
fillSamples();
onLangChange(fillSamples);
$("#imp-clear").addEventListener("click", ()=>{ $("#imp-text").value = ""; reviewImport(); });

$("#imp-go").addEventListener("click", ()=>{
  if(!IMPORTED) return;
  const {p, rt} = IMPORTED;
  /* The parse result is taken whole. Copying it field by field is how a chain
     lost the device it was attached to and a set lost its size the moment
     either grew a field the copy list had not heard of. */
  edit(t("import ruleset","importar ruleset"), ()=>{
    MODEL.chains  = p.chains;
    MODEL.sets    = p.sets;
    MODEL.objects = p.objects;
    MODEL.tables  = p.tables;
  });
  openProject();
  $$(".scrim").forEach(s=>s.classList.remove("on"));
  go("editor");
  setZoom(.72);
  toast(rt.diffs.length
    ? t(`Imported · ${rt.ok}/${rt.total} lines verified`, `Importado · ${rt.ok}/${rt.total} líneas verificadas`)
    : t(`Imported · all ${rt.total} lines verified`, `Importado · las ${rt.total} líneas verificadas`));
});

/* the toolbar Open button and the dashboard button both land here */
$$('[data-go="open"]').forEach(b=> b.dataset.go = "import");
const _go = go;
go = function(id){
  if(id==="import"){ $("#scrim-import").classList.add("on"); reviewImport(); $("#imp-text").focus(); return; }
  return _go(id);
};
reviewImport();
RERENDER.push(reviewImport);

/* ══ SET MANAGER ════════════════════════════════════════════════════════
   References are counted by scanning live rule expressions, so a set the
   ruleset stopped using reports zero the moment you delete the last rule. */
SETSEL = 0;
function refsTo(name){
  const out = [];
  MODEL.chains.forEach(ch=> ch.rules.forEach((r,i)=>{
    if(r.on && r.expr.includes("@"+name)) out.push({ch, r, i});
  }));
  return out;
}
const setIcon = s => s.kind==="map"
  ? "M5 8h6l3 4h5M5 16h6"
  : (s.f||"").includes("timeout") ? "M12 8v8m-4-4h8" : "M4 7h16M4 12h16M4 17h9";

function renderSets(){
  if(SETSEL >= MODEL.sets.length) SETSEL = Math.max(0, MODEL.sets.length-1);
  const list = $("#set-list");
  $("#set-count").textContent = MODEL.sets.length;

  list.innerHTML = MODEL.sets.length ? MODEL.sets.map((s,i)=>{
    const n = refsTo(s.n).length;
    return `<div class="set-item${i===SETSEL?" on":""}${n?"":" warnish"}" data-si="${i}">
      <div class="ic"><svg class="ico sm" viewBox="0 0 24 24"><path d="${setIcon(s)}"/>${
        (s.f||"").includes("timeout")?'<circle cx="12" cy="12" r="9"/>':""}</svg></div>
      <div><div class="nm">@${esc(s.n)}</div>
        <div class="ty">${esc(s.t)}${s.f?" · "+esc(s.f):""}${n?"":" · "+t("unused","sin usar")}</div></div>
      <div class="ct">${s.el.length>999?(s.el.length/1000).toFixed(1)+"k":s.el.length}</div>
    </div>`;
  }).join("") : `<div style="padding:34px 18px;text-align:center;font-size:12px;color:var(--t4);line-height:1.6">
      ${t("No sets in this ruleset.","Este ruleset no tiene sets.")}</div>`;

  const s = MODEL.sets[SETSEL];
  const main = $("#set-main"), refs = $("#set-refs");
  if(!s){
    main.innerHTML = `<div class="empty-props" style="height:100%">
      <div class="art"><svg viewBox="0 0 24 24" style="width:28px;height:28px;stroke:currentColor;fill:none;stroke-width:1.4"><path d="M4 7h16M4 12h16M4 17h9"/></svg></div>
      <h4>${t("No set selected","Ningún set seleccionado")}</h4>
      <p>${t("Sets turn repeated rules into one hash lookup. The optimiser will offer to create them for you.",
              "Los sets convierten reglas repetidas en una sola consulta hash. El optimizador se ofrecerá a crearlos.")}</p></div>`;
    refs.innerHTML = ""; $("#ref-count").textContent = "0";
    return;
  }

  const rs = refsTo(s.n);
  $("#ref-count").textContent = rs.length;
  /* A set's name, type and flags are as editable as its contents. They were
     read-only, which made a set you had just created impossible to correct. */
  const FLAGS = ["interval","timeout","constant","dynamic"];
  const TYPES = ["ipv4_addr","ipv6_addr","inet_service","ether_addr","inet_proto","ifname","mark"];
  main.innerHTML = `
    <div class="set-hero">
      <div class="r1">
        <span class="at">@</span><input class="set-name" id="set-name" value="${esc(s.n)}" spellcheck="false">
        <span class="pill ${s.kind==="map"?"v-snat":"v-dnat"}"><span class="sw"></span>${s.kind||"set"}</span>
        <div style="flex:1"></div>
        <button class="tb" id="set-del" style="color:var(--v-drop)"
          ${rs.length?`disabled title="${esc(t(`Referenced by ${rs.length} rules`,`Referenciado por ${rs.length} reglas`))}"`:""}>
          <svg class="ico" viewBox="0 0 24 24"><path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/></svg>${t("Delete set","Eliminar set")}</button>
      </div>
      <div class="set-props">
        <label class="fld"><span class="lbl">type</span>
          <select id="set-type">${TYPES.map(x=>
            `<option${x===s.t?" selected":""}>${x}</option>`).join("")}
            ${TYPES.includes(s.t)?"":`<option selected>${esc(s.t)}</option>`}</select></label>
        <div class="fld"><span class="lbl">flags</span>
          <div class="preset" id="set-flags">${FLAGS.map(f=>
            `<button data-flag="${f}"${(s.f||"").includes(f)?' class="on"':""}>${f}</button>`).join("")}</div></div>
      </div>
      <div class="decl">${highlight(`${s.kind==="map"?"map":"set"} ${s.n} { type ${s.t}${s.f?" ; flags "+s.f:""} ; elements = { … } }`)}</div>
    </div>
    <div class="elem-toolbar">
      <span class="lbl" style="flex:1">${s.el.length} ${t("elements","elementos")} · ${
        rs.length ? t(`referenced by ${rs.length} rules`,`referenciado por ${rs.length} reglas`)
                  : `<span style="color:var(--warn)">${t("never referenced","nunca referenciado")}</span>`}</span>
    </div>
    <div class="elem-grid" id="elem-grid">
      ${s.el.map((e,i)=>`<span class="elem">
        <input class="elem-in" data-edit="${i}" value="${esc(e)}" spellcheck="false"
               size="${Math.max(6, String(e).length)}">
        <button class="rm" data-el="${i}"><svg class="ico sm" viewBox="0 0 24 24"><path d="M6 6l12 12M18 6 6 18"/></svg></button></span>`).join("")}
      <input class="elem new" id="elem-add" style="width:170px;height:29px"
             placeholder="${t("+ add element…","+ añadir elemento…")}">
    </div>`;

  refs.innerHTML = rs.length ? rs.map(({ch,r,i})=>`
    <div class="ref" data-ref="${UID(ch)}:${i}">
      <div class="loc"><span style="color:var(--${VCOLOR[r.verdict]||"--t3"})">◆</span>${ch.table} / ${ch.id} · ${t("rule","regla")} ${i+1}</div>
      <div class="ex">${highlight(ruleLine(r)).replace(new RegExp("@"+s.n,"g"),`<mark>@${s.n}</mark>`)}</div>
    </div>`).join("") : `
    <div style="padding:32px 18px;text-align:center;font-size:11.5px;color:var(--t4);line-height:1.6">
      ${t("No rule uses this set. Its elements are loaded into the kernel on every reload for nothing.",
           "Ninguna regla usa este set. Sus elementos se cargan en el kernel en cada recarga para nada.")}</div>`;
}

document.addEventListener("click", e=>{
  const it = e.target.closest("[data-si]");
  if(it){ SETSEL = +it.dataset.si; renderSets(); return; }

  const rm = e.target.closest("[data-el]");
  if(rm){
    const s = MODEL.sets[SETSEL], i = +rm.dataset.el;
    edit(t("remove set element","quitar elemento del set"), ()=>{ s.el.splice(i,1); });
    return;
  }
  const fl = e.target.closest("#set-flags [data-flag]");
  if(fl){
    const s = MODEL.sets[SETSEL], f = fl.dataset.flag;
    const have = (s.f||"").split(",").map(x=>x.trim()).filter(Boolean);
    const next = have.includes(f) ? have.filter(x=>x!==f) : [...have, f];
    edit(t("set flags","flags del set"), ()=>{ s.f = next.join(", "); });
    return;
  }
  if(e.target.closest("#set-del")){
    const s = MODEL.sets[SETSEL];
    if(refsTo(s.n).length){
      toast(t(`@${s.n} is still used by ${refsTo(s.n).length} rules`,
              `@${s.n} lo usan todavía ${refsTo(s.n).length} reglas`));
      return;
    }
    edit(t("delete set","eliminar set"), ()=>{ MODEL.sets.splice(SETSEL,1); });
    SETSEL = Math.max(0, SETSEL-1);
    renderSets();
    return;
  }
  if(e.target.closest("#set-new")){
    edit(t("new set","nuevo set"), ()=>{
      MODEL.sets.push({n:"new_set_"+(MODEL.sets.length+1), table:MODEL.chains[0]?.table||"inet fw", t:"ipv4_addr", f:"interval", el:[]});
    });
    SETSEL = MODEL.sets.length-1; renderSets();
    return;
  }
  const ref = e.target.closest("[data-ref]");
  if(ref){
    const j = ref.dataset.ref.lastIndexOf(":");
    const cid = ref.dataset.ref.slice(0,j), i = ref.dataset.ref.slice(j+1);
    go("editor"); setTimeout(()=>select(cid, +i, true), 60);
  }
});
document.addEventListener("keydown", e=>{
  if(e.target.id!=="elem-add" || e.key!=="Enter") return;
  const v = e.target.value.trim(); if(!v) return;
  const s = MODEL.sets[SETSEL];
  edit(t("add set element","añadir elemento al set"), ()=>{ s.el.push(v); });
});

/* ── editing a set in place ──────────────────────────────────────────── */
document.addEventListener("change", e=>{
  const s = MODEL.sets[SETSEL];
  if(!s) return;

  if(e.target.id === "set-type"){
    edit(t("set type","tipo del set"), ()=>{ s.t = e.target.value; });
    return;
  }
  if(e.target.id === "set-name"){
    const next = e.target.value.trim().replace(/^@/, "");
    if(!next || next === s.n){ renderSets(); return; }
    if(MODEL.sets.some(x=>x!==s && x.n===next)){
      toast(t(`A set called ${next} already exists`, `Ya existe un set llamado ${next}`));
      renderSets(); return;
    }
    /* rename the references too, or the rules would point at nothing */
    const was = s.n, hits = refsTo(was).length;
    edit(t("rename set","renombrar set"), ()=>{
      s.n = next;
      MODEL.chains.forEach(ch=>ch.rules.forEach(r=>{
        r.expr = r.expr.split("@"+was).join("@"+next);
      }));
    });
    toast(hits
      ? t(`Renamed, and ${hits} rules updated`, `Renombrado, y ${hits} reglas actualizadas`)
      : t("Renamed","Renombrado"));
    return;
  }
  const ed = e.target.closest("[data-edit]");
  if(ed){
    const i = +ed.dataset.edit, next = ed.value.trim();
    if(next === s.el[i]) return;
    edit(t("edit set element","editar elemento del set"),
         ()=>{ if(next) s.el[i] = next; else s.el.splice(i,1); });
  }
});

/* hovering a set highlights every rule that uses it, on the canvas too */
document.addEventListener("mouseover", e=>{
  const it = e.target.closest("[data-si]");
  if(!it) return;
  const s = MODEL.sets[+it.dataset.si]; if(!s) return;
  const hits = new Set(refsTo(s.n).map(x=>UID(x.ch)+":"+x.i));
  $$(".rule").forEach(r=>r.classList.toggle("faded", !hits.has(r.dataset.chain+":"+r.dataset.i)));
});
document.addEventListener("mouseout", e=>{
  if(e.target.closest("[data-si]")) $$(".rule").forEach(r=>r.classList.remove("faded"));
});

/* ══ TOPOLOGY ═══════════════════════════════════════════════════════════
   Nothing is declared: the interfaces are whatever the rules mention, and
   an interface nobody references simply is not on the map.              */
const ZONES = [
  [/^(wan|ppp|eth0$|ge-|xe-)/, "WAN",       "z-wan",  "M3 12h18M12 3a15 15 0 0 1 0 18 15 15 0 0 1 0-18", "circle"],
  [/^(wg|tun|tap|ipsec|vti)/,  "VPN",       "z-vpn",  "M8 10V7a4 4 0 0 1 8 0v3", "lock"],
  [/^(docker|veth|cni|flannel|podman)/, "CONTAINER", "z-dock", "M2 16c4 4 15 3 19-4", "docker"],
  [/^(vlan|bond|team)/,        "SEGMENTED", "z-vlan", "M4 6h16M4 12h16M4 18h16", "lines"],
  [/^(br|lan|eth|en)/,         "LAN",       "z-lan",  "M8 20h8M12 16v4", "screen"],
];
const zoneOf = n => (ZONES.find(([re])=>re.test(n)) || [null,"OTHER","z-lan","M4 12h16",""]);

function interfaces(){
  const map = new Map();
  MODEL.chains.forEach(ch=> ch.rules.forEach(r=>{
    if(!r.on) return;
    for(const m of r.expr.matchAll(/\b(iif|oif|iifname|oifname)\s+"?([\w.@-]+)"?/g)){
      const dir = m[1].startsWith("i") ? "in" : "out", name = m[2];
      if(name==="lo") continue;
      const e = map.get(name) || {name, in:0, out:0, rules:0, verdicts:{}, chains:new Set()};
      e[dir]++; e.rules++;
      e.verdicts[r.verdict] = (e.verdicts[r.verdict]||0)+1;
      e.chains.add(ch.id);
      map.set(name, e);
    }
  }));
  return [...map.values()].sort((a,b)=>b.rules-a.rules);
}
const dominant = v => Object.entries(v).sort((a,b)=>b[1]-a[1])[0]?.[0] || "log";

TOPO_MODE = "zones";
/* hand-placed cards, keyed by mode so each view keeps its own arrangement */
const TOPO_POS = {};
let TOPO_PAIRS = null, TOPO_UNITS = [];
/* who is allowed to talk to whom, straight out of the rules that name both
   an input and an output interface */
function flows(){
  const m = new Map();
  MODEL.chains.forEach(ch=> ch.rules.forEach(r=>{
    if(!r.on) return;
    const i = r.expr.match(/\b(?:iif|iifname)\s+"?([\w.@-]+)"?/);
    const o = r.expr.match(/\b(?:oif|oifname)\s+"?([\w.@-]+)"?/);
    if(!i || !o) return;
    const k = i[1]+"→"+o[1];
    const e = m.get(k) || {from:i[1], to:o[1], n:0, verdicts:{}};
    e.n++; e.verdicts[r.verdict] = (e.verdicts[r.verdict]||0)+1;
    m.set(k, e);
  }));
  return [...m.values()];
}

/* zone view aggregates interfaces into the security zones they belong to */
function zoneGroups(){
  const g = new Map();
  interfaces().forEach(e=>{
    const [,zone,cls,path] = zoneOf(e.name);
    const z = g.get(zone) || {name:zone, cls, path, members:[], in:0, out:0, rules:0, verdicts:{}, chains:new Set()};
    z.members.push(e.name); z.in += e.in; z.out += e.out; z.rules += e.rules;
    Object.entries(e.verdicts).forEach(([v,n])=> z.verdicts[v] = (z.verdicts[v]||0)+n);
    e.chains.forEach(c=>z.chains.add(c));
    g.set(zone, z);
  });
  return [...g.values()].sort((a,b)=>b.rules-a.rules);
}

function renderTopo(){
  const nodes = $("#topo-nodes"), cv = $("#topo-canvas");
  TOPO_MODE = $("#topo-mode .on")?.dataset.tm || "zones";
  const flow = TOPO_MODE === "flow";
  const units = TOPO_MODE === "zones" ? zoneGroups() : interfaces();
  const tables = [...new Set(MODEL.chains.map(c=>c.table))];
  const pairs = flows();

  $("#topo-sub").textContent = flow
    ? t(`${pairs.length} interface pairs named by rules`, `${pairs.length} pares de interfaces nombrados por reglas`)
    : TOPO_MODE === "zones"
      ? t(`${units.length} zones · ${interfaces().length} interfaces`, `${units.length} zonas · ${interfaces().length} interfaces`)
      : t(`${units.length} interfaces · ${tables.length} tables`, `${units.length} interfaces · ${tables.length} tablas`);

  if(!units.length){
    nodes.innerHTML = `<div style="position:absolute;inset:0;display:grid;place-items:center;text-align:center">
      <div style="max-width:300px">
        <div style="width:56px;height:56px;margin:0 auto 14px;border-radius:16px;display:grid;place-items:center;
                    border:1px dashed var(--line-2);color:var(--t4)">
          <svg class="ico lg" viewBox="0 0 24 24"><path d="M12 7.5v4m0 0-5 5m5-5 5 5"/></svg></div>
        <div style="font:600 13px var(--sans);color:var(--t2);margin-bottom:6px">${t("No interfaces referenced","Ninguna interfaz referenciada")}</div>
        <div style="font-size:12px;color:var(--t4);line-height:1.6">${t(
          "Add an iifname or oifname match to a rule and the interface appears here.",
          "Añade una coincidencia iifname u oifname a una regla y la interfaz aparecerá aquí.")}</div>
      </div></div>`;
    $("#topo-wires").innerHTML = "";
    return;
  }

  const H = cv.offsetHeight || 620, W = cv.offsetWidth || 1000;
  const left  = units.filter(e=> e.in >= e.out);
  const right = units.filter(e=> e.in <  e.out);
  const laid = [...left.map(e=>({e, side:"l"})), ...right.map(e=>({e, side:"r"}))];
  TOPO_UNITS = units;
  const rules = MODEL.chains.reduce((a,c)=>a+c.rules.filter(r=>r.on).length,0);

  nodes.innerHTML = laid.map(({e})=>{
    const isZone = TOPO_MODE === "zones";
    const [,zone,cls,path] = isZone ? [0,e.name,e.cls,e.path] : zoneOf(e.name);
    const v = dominant(e.verdicts);
    const key = e.name;
    return `<div class="node" data-if="${esc(key)}">
      <div class="nh"><div class="zi ${cls}"><svg class="ico sm" viewBox="0 0 24 24"><path d="${path}"/></svg></div>
        <span class="nn">${esc(isZone ? e.name : e.name)}</span></div>
      <div class="nb">
        ${isZone
          ? `<div class="kv"><span>${t("members","miembros")}</span> <b>${e.members.join(" ")}</b></div>`
          : `<div class="kv"><span>${t("zone","zona")}</span> <b>${zone}</b></div>`}
        <div class="kv"><span>${t("rules","reglas")}</span> <b>${e.rules}</b></div>
        <div class="kv"><span>${t("direction","dirección")}</span> <b>${e.in?"in "+e.in:""}${e.in&&e.out?" · ":""}${e.out?"out "+e.out:""}</b></div>
      </div>
      <div class="nf"><span class="pill v-${v}"><span class="sw"></span>${VNAME[v]||v}</span>
        <span class="chip">${[...e.chains].slice(0,2).join(", ")}</span></div>
    </div>`;
  }).join("") + (flow ? "" : `
    <div class="node core" data-if="__core">
      <div class="nh"><div class="zi" style="background:var(--aqua-wash);border:1px solid var(--aqua-line);color:var(--aqua)">
        <svg class="ico sm" viewBox="0 0 24 24"><path d="M12 3 4 6v6c0 4.5 3.2 8.4 8 9.5 4.8-1.1 8-5 8-9.5V6z"/></svg></div>
        <span class="nn">${esc(tables[0]||"ruleset")}</span><span class="lbl" style="font-size:9px">${tables.length>1?"+"+(tables.length-1):"table"}</span></div>
      <div class="nb">
        <div class="kv"><span>${t("chains","cadenas")}</span> <b>${MODEL.chains.length}</b></div>
        <div class="kv"><span>${t("rules","reglas")}</span> <b>${rules}</b></div>
        <div class="kv"><span>sets</span> <b>${MODEL.sets.length}</b></div>
      </div>
      <div class="nf">${[...new Set(MODEL.chains.filter(c=>c.hook).map(c=>c.hook))]
        .map(h=>`<span class="chip">${h}</span>`).join("")}</div>
    </div>`);

  TOPO_PAIRS = flow ? pairs : null;
  /* Height is only knowable once the cards are in the document: they grow with
     their content, and guessing was what made them overlap. Measure, then place. */
  requestAnimationFrame(()=>{ placeTopo(laid, W, H); drawTopoWires(); });
}

/* Auto-layout, unless the card has been dragged — a hand-placed node stays put. */
function placeTopo(laid, W, H){
  const GUT = 22;
  for(const side of ["l", "r"]){
    const arr = laid.filter(n => n.side === side);
    const els = arr.map(n => $(`.node[data-if="${cssEsc(n.e.name)}"]`)).filter(Boolean);
    const total = els.reduce((a, n) => a + n.offsetHeight, 0) + GUT * Math.max(0, els.length - 1);
    let y = Math.max(14, (H - total) / 2);
    els.forEach((node, i) => {
      const saved = TOPO_POS[TOPO_MODE + ":" + arr[i].e.name];
      const x = side === "l" ? 52 : W - node.offsetWidth - 44;
      node.style.left = (saved ? saved.x : x) + "px";
      node.style.top  = (saved ? saved.y : y) + "px";
      y += node.offsetHeight + GUT;
    });
  }
  const core = $(".node.core");
  if(core){
    const saved = TOPO_POS[TOPO_MODE + ":__core"];
    core.style.left = (saved ? saved.x : W / 2 - core.offsetWidth / 2) + "px";
    core.style.top  = (saved ? saved.y : H / 2 - core.offsetHeight / 2) + "px";
  }
}

const TCOL = {accept:"var(--v-accept)", drop:"var(--v-drop)", reject:"var(--v-reject)",
              dnat:"var(--v-dnat)", snat:"var(--v-snat)", jump:"var(--v-jump)", log:"var(--v-log)"};

/* Reads every position straight out of the DOM, so a card being dragged pulls
   its wires with it — no cached geometry to fall out of step. */
function drawTopoWires(){
  const svg = $("#topo-wires"), cv = $("#topo-canvas");
  if(!svg || !cv || !cv.offsetWidth) return;
  svg.setAttribute("viewBox",`0 0 ${cv.offsetWidth} ${cv.offsetHeight}`);

  const box = key => {
    const n = $(`.node[data-if="${cssEsc(key)}"]`);
    if(!n) return null;
    return {x:n.offsetLeft, y:n.offsetTop, w:n.offsetWidth, h:n.offsetHeight};
  };
  const pairs = TOPO_PAIRS;

  /* rule-flow mode: interface → interface, straight from the rules */
  if(pairs){
    svg.innerHTML = `<defs><marker id="arw" viewBox="0 0 10 10" refX="9" refY="5"
        markerWidth="5" markerHeight="5" orient="auto-start-reverse">
        <path d="M0 0 10 5 0 10z" fill="context-stroke"/></marker></defs>` +
      pairs.map(p=>{
        const A = box(p.from), B = box(p.to);
        if(!A || !B) return "";
        const x1 = A.x + A.w, y1 = A.y + A.h/2;
        const x2 = B.x,       y2 = B.y + B.h/2;
        const dx = Math.max(70, Math.abs(x2-x1)*.45);
        const col = TCOL[dominant(p.verdicts)] || "var(--t3)";
        return `<path d="M${x1} ${y1} C${x1+dx} ${y1} ${x2-dx} ${y2} ${x2} ${y2}"
                  stroke="${col}" stroke-width="${Math.min(3.4, 1.2+Math.log2(1+p.n)).toFixed(1)}"
                  fill="none" opacity=".62" marker-end="url(#arw)" class="flow"/>
                <circle cx="${x1}" cy="${y1}" r="3.5" fill="${col}"/>`;
      }).join("");
    return;
  }

  const core = box("__core");
  if(!core){ svg.innerHTML = ""; return; }
  const cx = core.x + core.w/2, cy = core.y + core.h/2;

  svg.innerHTML = TOPO_UNITS.map(e=>{
    const B = box(e.name); if(!B) return "";
    /* which side of the core it sits on is decided now, not at layout time —
       drag a card across the middle and the wire re-routes */
    const isLeft = B.x + B.w/2 < cx;
    const x1 = isLeft ? B.x + B.w : B.x, y1 = B.y + B.h/2;
    const x2 = isLeft ? core.x : core.x + core.w, y2 = cy;
    const dx = Math.max(40, Math.abs(x2-x1)*.5);
    const col = TCOL[dominant(e.verdicts)] || "var(--t3)";
    const wgt = Math.min(3.4, 1 + Math.log2(1+e.rules));
    return `<path d="M${x1} ${y1} C${x1+(isLeft?dx:-dx)} ${y1} ${x2+(isLeft?-dx:dx)} ${y2} ${x2} ${y2}"
              stroke="${col}" stroke-width="${wgt.toFixed(1)}" fill="none" opacity=".5" class="flow"/>
            <circle cx="${x1}" cy="${y1}" r="3.5" fill="${col}"/>`;
  }).join("");
}

/* ── dragging ───────────────────────────────────────────────────────────
   Auto-layout is a starting point, not a verdict: a topology is something you
   arrange to match how you think about the network. */
(function topoDrag(){
  const cv = $("#topo-canvas");
  if(!cv) return;
  let d = null;

  cv.addEventListener("pointerdown", e=>{
    const n = e.target.closest(".node");
    if(!n || e.button !== 0) return;
    d = {n, dx: e.clientX - n.offsetLeft, dy: e.clientY - n.offsetTop, moved:false};
    n.setPointerCapture(e.pointerId);
    n.classList.add("dragging");
    e.preventDefault();
  });

  cv.addEventListener("pointermove", e=>{
    if(!d) return;
    d.moved = true;
    const x = Math.max(8, Math.min(cv.offsetWidth  - d.n.offsetWidth  - 8, e.clientX - d.dx));
    const y = Math.max(8, Math.min(cv.offsetHeight - d.n.offsetHeight - 8, e.clientY - d.dy));
    d.n.style.left = x + "px";
    d.n.style.top  = y + "px";
    drawTopoWires();
  });

  const end = ()=>{
    if(!d) return;
    if(d.moved)
      TOPO_POS[TOPO_MODE + ":" + d.n.dataset.if] = {x: d.n.offsetLeft, y: d.n.offsetTop};
    d.n.classList.remove("dragging");
    d = null;
    $("#topo-reset")?.classList.toggle("on", Object.keys(TOPO_POS).length > 0);
  };
  cv.addEventListener("pointerup", end);
  cv.addEventListener("pointercancel", end);
})();

$("#topo-reset")?.addEventListener("click", ()=>{
  Object.keys(TOPO_POS).forEach(k=>delete TOPO_POS[k]);
  $("#topo-reset").classList.remove("on");
  renderTopo();
});
$("#topo-mode").addEventListener("click", e=>{
  if(e.target.closest("[data-tm]")) requestAnimationFrame(renderTopo);
});

/* ══ DASHBOARD ═════════════════════════════════════════════════════════ */
function renderDash(){
  /* hook map — one column per hook, chains stacked by priority, each chain
     carrying a bar whose segments are its verdict mix */
  $("#hook-map").innerHTML = ["prerouting","input","forward","output","postrouting"].map(h=>{
    const cs = MODEL.chains.filter(c=>c.hook===h).sort((a,b)=>a.prio-b.prio);
    return `<div class="hm-col"><div class="lbl">${h}</div><div class="hm-stack">
      ${cs.length ? cs.map(c=>{
        const mix = {};
        c.rules.filter(r=>r.on).forEach(r=> mix[r.verdict] = (mix[r.verdict]||0)+1);
        const bars = Object.entries(mix).sort((a,b)=>b[1]-a[1]).map(([v,n])=>
          `<i style="flex:${n};background:var(${VCOLOR[v]||"--v-log"})"></i>`).join("");
        return `<div class="hm-ch" data-chain-go="${UID(c)}">
          <div class="n"><span style="color:var(--${c.policy==="drop"?"v-drop":"v-accept"});font-size:9px">◆</span>
            ${esc(c.id)}<span class="p">${c.prio>0?"+"+c.prio:c.prio}</span></div>
          <div class="hm-bars">${bars||'<i style="flex:1;background:var(--line-2)"></i>'}</div></div>`;
      }).join("") : `<div class="hm-empty">${t("no chain","sin cadena")}</div>`}
    </div></div>`;
  }).join("");

  /* version history is the real undo stack, newest first */
  const rows = [{label:t("Working tree","Árbol de trabajo"), now:true},
                ...HIST.past.slice().reverse().map(h=>({label:h.label}))].slice(0,6);
  $("#tl-history").innerHTML = rows.map((r,i)=>`
    <div class="tl-row">
      <span class="dot" style="${i===0
        ? "background:var(--aqua);box-shadow:0 0 0 3px rgba(57,213,255,.15)"
        : "background:var(--v-accept)"}"></span>
      <span class="msg">${i===0
        ? `<b>${esc(r.label)}</b> — ${HIST.past.length
            ? t(`${HIST.past.length} unsaved edits`,`${HIST.past.length} ediciones sin guardar`)
            : t("no changes since import","sin cambios desde la importación")}`
        : esc(r.label)}</span>
      <span class="ts">${i===0?t("now","ahora"):"−"+i}</span>
    </div>`).join("");

  /* sets ranked by how much of the ruleset leans on them */
  const max = Math.max(1, ...MODEL.sets.map(s=>refsTo(s.n).length));
  $("#dash-sets").innerHTML = MODEL.sets.length ? MODEL.sets.map((s,i)=>{
    const n = refsTo(s.n).length;
    return `<div class="lst-row" data-set-go="${i}">
      <span class="nm"${n?"":' style="color:var(--t3)"'}>@${esc(s.n)}</span>
      <span class="meta"${n?"":' style="color:var(--warn)"'}>${n? t(`${n} rules`,`${n} reglas`) : t("unused","sin usar")}</span>
      <span class="usebar"><i style="width:${n/max*100}%"></i></span></div>`;
  }).join("") : `<div style="padding:22px;text-align:center;font-size:11.5px;color:var(--t4)">${
      t("No sets defined","Sin sets definidos")}</div>`;
}
document.addEventListener("click", e=>{
  const c = e.target.closest("[data-chain-go]");
  if(c){ go("editor"); setTimeout(()=>{
    const row = $(`.rule[data-chain="${c.dataset.chainGo}"]`);
    if(row){ select(c.dataset.chainGo, 0); row.scrollIntoView({block:"center",inline:"center",behavior:"smooth"}); }
  },60); return; }
  const s = e.target.closest("[data-set-go]");
  if(s){ SETSEL = +s.dataset.setGo; go("sets"); }
});

/* ══ EXPORT ════════════════════════════════════════════════════════════ */
function download(name, text, mime){
  const url = URL.createObjectURL(new Blob([text], {type:mime||"text/plain;charset=utf-8"}));
  const a = el("a"); a.href = url; a.download = name;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(()=>URL.revokeObjectURL(url), 2000);
}

function exportPayload(){
  const fmt = $$("#scrim-export .choice").findIndex(c=>c.classList.contains("on"));
  const opt = $$("#scrim-export .sw-toggle").map(sw=>sw.classList.contains("on"));
  const [flush, comments, optimise] = opt;
  let lines = generate().slice();
  if(!flush) lines = lines.filter(l=>l!=="flush ruleset");
  if(!comments) lines = lines.map(l=>l.replace(/\s*comment "(?:[^"\\]|\\.)*"/,""));

  if(fmt===1){                                   /* incremental delta */
    const add = [];
    MODEL.chains.forEach(ch=> ch.rules.filter(r=>r.on).forEach(r=>
      add.push(`add rule ${ch.table} ${ch.id} ${ruleLine(r)}`)));
    return {name:PROJECT()+".delta.nft", mime:"text/plain",
            text:`# eFeFlow incremental delta\n# apply with: nft -f ${PROJECT()}.delta.nft\n\n`+add.join("\n")+"\n"};
  }
  if(fmt===2){                                   /* systemd bundle */
    return {name:PROJECT()+".systemd.txt", mime:"text/plain", text:
`# ── /etc/nftables.conf ───────────────────────────────────────────────
${lines.join("\n")}

# ── /etc/systemd/system/nftables.service ─────────────────────────────
[Unit]
Description=nftables ruleset (${PROJECT()})
Before=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/usr/sbin/nft -c -f /etc/nftables.conf
ExecStart=/usr/sbin/nft -f /etc/nftables.conf
ExecStop=/usr/sbin/nft flush ruleset

[Install]
WantedBy=multi-user.target
`};
  }
  if(fmt===3){                                   /* ansible */
    return {name:PROJECT()+".yml", mime:"text/yaml", text:
`- name: Deploy ${PROJECT()} nftables ruleset
  hosts: firewalls
  become: true
  vars:
    nft_sets:
${MODEL.sets.map(s=>`      ${s.n}: [${s.el.map(e=>`"${e}"`).join(", ")}]`).join("\n")}
  tasks:
    - name: Install ruleset
      ansible.builtin.copy:
        dest: /etc/nftables.conf
        validate: /usr/sbin/nft -c -f %s
        content: |
${lines.map(l=>"          "+l).join("\n")}
      notify: reload nftables
  handlers:
    - name: reload nftables
      ansible.builtin.systemd:
        name: nftables
        state: reloaded
`};
  }
  return {name:PROJECT()+".nft", mime:"text/plain", text:lines.join("\n")+"\n"};
}

function refreshExportStats(){
  const p = exportPayload();
  const rules = MODEL.chains.reduce((a,c)=>a+c.rules.filter(r=>r.on).length,0);
  const cards = $$("#scrim-export .card .num");
  if(cards.length===4){
    cards[0].textContent = p.text.split("\n").length;
    cards[1].textContent = rules;
    cards[2].textContent = MODEL.sets.length;
    cards[3].textContent = worstCase();
  }
}
$("#scrim-export").addEventListener("click", e=>{
  if(e.target.closest(".choice, .sw-toggle")) setTimeout(refreshExportStats, 0);
  const btns = $$("#scrim-export .modal-ft .tb");
  if(e.target.closest(".modal-ft .tb.pri")){
    const p = exportPayload(); download(p.name, p.text, p.mime);
    toast(t("Exported ","Exportado ")+p.name);
  } else if(e.target===btns[1] || (btns[1] && btns[1].contains(e.target))){
    const p = exportPayload();
    navigator.clipboard?.writeText(p.text);
    toast(t("Ruleset copied to clipboard","Ruleset copiado al portapapeles"));
  }
});
/* the code drawer's copy button */
$$(".dw-hd .tb.icon")[0]?.addEventListener("click", ()=>{
  navigator.clipboard?.writeText(generate().join("\n"));
  toast(t("Ruleset copied to clipboard","Ruleset copiado al portapapeles"));
});

/* ══ SAVE / OPEN PROJECT ═══════════════════════════════════════════════
   Both ends go through serialise/deserialise in core/project.js. They used to
   inline their own JSON here, which is how the two drifted apart from the pair
   the tests cover: the file kept the rules but silently dropped the interfaces
   and networks you had typed, and opening one never restored its name. */
$("#btn-save")?.addEventListener("click", async ()=>{
  const name = PROJECT() + ".efeflow.json";
  /* saveTextFile asks where; the browser fallback downloads. Either way it
     returns null when the user backs out, and a cancelled save is not a save. */
  const where = await native.saveTextFile(name, serialise(),
    [{name:"eFeFlow project", extensions:["json"]}]);
  if(!where) return;
  setProject({path: where, origin: where.split(/[\\/]/).pop(), dirty:false});
  showProject();
  toast(t("Saved to ","Guardado en ") + where);
});

const filePick = el("input"); filePick.type = "file";
filePick.accept = ".json,.nft,.conf,.txt";
document.body.appendChild(filePick);
filePick.style.display = "none";
filePick.addEventListener("change", ()=>{
  const f = filePick.files[0]; if(!f) return;
  const rd = new FileReader();
  rd.onload = ()=>{
    const text = String(rd.result);
    if(f.name.endsWith(".json")){
      try{
        const o = deserialise(text);
        edit(t("open project","abrir proyecto"), ()=>{
          MODEL.chains = o.chains; MODEL.sets = o.sets;
          MODEL.objects = o.objects; MODEL.tables = o.tables;
        });
        /* the name and the scratch lists are part of the project, not the
           ruleset, so they sit outside the undo snapshot */
        setProject({open:true, name:o.name, scratch:o.scratch, origin:f.name, dirty:false});
        showProject();
        /* Import is a scrim, not a screen, so go() changes what is underneath
           and leaves the overlay standing — with its Import button disabled,
           because the textarea it watches is still empty. The only way out was
           the close cross. Same two lines the Import button itself runs. */
        $$(".scrim").forEach(s=>s.classList.remove("on"));
        go("editor"); setZoom(.72);
        toast(t("Opened ","Abierto ")+f.name);
      }catch(err){ toast(t("Could not read that project file","No se pudo leer ese fichero de proyecto")); }
    } else {
      $("#imp-text").value = text; go("import"); reviewImport();
    }
    filePick.value = "";
  };
  rd.readAsText(f);
});
$("#imp-sample").insertAdjacentElement("beforebegin", (()=>{
  const b = el("button","tb"); b.textContent = t("Open file…","Abrir fichero…");
  b.addEventListener("click", ()=>filePick.click());
  return b;
})());

/* ══ COMMAND PALETTE ═══════════════════════════════════════════════════ */
const COMMANDS = () => [
  {t:t("New empty ruleset","Ruleset vacío nuevo"), k:"Ctrl N", d:"M12 5v14M5 12h14", go:()=>$("#btn-new").click()},
  {t:t("Rename the project","Renombrar el proyecto"), k:"F2", d:"M4 20h4L19 9a2.8 2.8 0 0 0-4-4L4 16z", go:beginRename},
  {t:t("Run packet simulation","Ejecutar simulación de paquete"), k:"Ctrl ⇧ R", d:"M5 3v18l15-9z", go:()=>{go("sim"); runSim();}},
  {t:t("Export nftables ruleset","Exportar el ruleset nftables"), k:"Ctrl E", d:"M12 3v13M7 11l5 5 5-5M4 21h16", go:()=>go("export")},
  {t:t("Import a ruleset","Importar un ruleset"), k:"", d:"M12 16V3M7 8l5-5 5 5M4 21h16", go:()=>go("import")},
  {t:t("Validate ruleset","Validar el ruleset"), k:"", d:"M12 3 4 6v6c0 4.5 3.2 8.4 8 9.5 4.8-1.1 8-5 8-9.5V6z", go:()=>go("validate")},
  {t:t("Apply all optimiser suggestions","Aplicar todas las sugerencias"), k:"", d:"m9 12 2 2 4-4", go:applyAll},
  {t:t("Undo last change","Deshacer el último cambio"), k:"Ctrl Z", d:"M9 14 4 9l5-5M4 9h11a5 5 0 0 1 0 10h-4", go:undo},
];
const fuzzy = (q,s) => s.toLowerCase().includes(q);

function renderPalette(){
  const q = $("#pal-input").value.toLowerCase().trim();
  const groups = [];

  const rules = [];
  MODEL.chains.forEach(ch=> ch.rules.forEach((r,i)=>{
    const line = ruleLine(r);
    if(!q || fuzzy(q,line) || fuzzy(q,ch.id))
      rules.push({title:line || t("(any packet)","(cualquier paquete)"),
                  sub:`${ch.table} / ${ch.id} · ${t("rule","regla")} ${i+1}`,
                  d:"M4 7h16M4 12h16M4 17h9", col:`var(${VCOLOR[r.verdict]||"--t3"})`,
                  go:()=>{ go("editor"); setTimeout(()=>select(UID(ch),i,true),60); }});
  }));
  if(rules.length) groups.push([t("Rules","Reglas"), rules.slice(0,6)]);

  const sets = MODEL.sets.map((s,i)=>({s,i})).filter(({s})=>!q||fuzzy(q,s.n)).map(({s,i})=>({
    title:"@"+s.n, sub:`${s.t}${s.f?" · "+s.f:""} · ${s.el.length} ${t("elements","elementos")} · ${refsTo(s.n).length} ${t("refs","refs")}`,
    d:"M4 7h16M4 12h16M4 17h9", col:"var(--v-dnat)",
    go:()=>{ SETSEL = i; go("sets"); }}));
  if(sets.length) groups.push([t("Sets","Sets"), sets.slice(0,4)]);

  const chains = MODEL.chains.filter(c=>!q||fuzzy(q,c.id)).map(c=>({
    title:c.id, sub:`${c.table} · ${c.hook?`hook ${c.hook} priority ${c.prio}`:t("regular chain","cadena regular")} · ${c.rules.length} ${t("rules","reglas")}`,
    d:"M9 6l6 6-6 6", col:"var(--aqua)",
    go:()=>{ go("editor"); setTimeout(()=>select(UID(c),0),60); }}));
  if(chains.length) groups.push([t("Chains","Cadenas"), chains.slice(0,4)]);

  const ifs = interfaces().filter(e=>!q||fuzzy(q,e.name)).map(e=>({
    title:e.name, sub:`${zoneOf(e.name)[1]} · ${e.rules} ${t("rules","reglas")}`,
    d:"M4 12h16", col:"var(--v-jump)", go:()=>go("topo")}));
  if(ifs.length) groups.push([t("Interfaces","Interfaces"), ifs.slice(0,3)]);

  const cmds = COMMANDS().filter(c=>!q||fuzzy(q,c.t)).map(c=>({
    title:c.t, sub:"", d:c.d, col:"var(--t3)", k:c.k, go:c.go}));
  if(cmds.length) groups.push([t("Commands","Comandos"), cmds]);

  PAL = groups.flatMap(([,items])=>items);
  PALI = 0;
  $(".palette .res").innerHTML = groups.length ? groups.map(([name,items])=>
    `<div class="pgh"><span class="lbl">${name}</span></div>` +
    items.map(it=>{
      const idx = PAL.indexOf(it);
      return `<div class="pr${idx===0?" on":""}" data-pi="${idx}">
        <div class="pi" style="color:${it.col}"><svg class="ico sm" viewBox="0 0 24 24"><path d="${it.d}"/></svg></div>
        <div class="pt">${esc(it.title)}${it.sub?`<small>${esc(it.sub)}</small>`:""}</div>
        ${it.k?`<kbd>${it.k}</kbd>`:idx===0?"<kbd>↵</kbd>":""}</div>`;
    }).join("")).join("") : `
    <div style="padding:40px 20px;text-align:center;color:var(--t4);font-size:12px">
      ${t("Nothing matches","Sin coincidencias")} “${esc(q)}”</div>`;
}
PAL = [], PALI = 0;
const palMove = d => {
  if(!PAL.length) return;
  PALI = (PALI + d + PAL.length) % PAL.length;
  $$(".pr").forEach(n=>n.classList.toggle("on", +n.dataset.pi===PALI));
  $$(".pr")[PALI]?.scrollIntoView({block:"nearest"});
};
$("#pal-input").addEventListener("input", renderPalette);
$("#pal-input").addEventListener("keydown", e=>{
  if(e.key==="ArrowDown"){ e.preventDefault(); palMove(1); }
  if(e.key==="ArrowUp"){ e.preventDefault(); palMove(-1); }
  if(e.key==="Enter"){
    e.preventDefault();
    const it = PAL[PALI];
    $$(".scrim").forEach(s=>s.classList.remove("on"));
    it?.go();
  }
});
$(".palette .res").addEventListener("click", e=>{
  const r = e.target.closest("[data-pi]"); if(!r) return;
  $$(".scrim").forEach(s=>s.classList.remove("on"));
  PAL[+r.dataset.pi]?.go();
});
const _go2 = go;
go = function(id){
  if(id==="open"){ $("#scrim-palette").classList.add("on"); $("#pal-input").value=""; renderPalette(); $("#pal-input").focus(); return; }
  if(id==="export"){ _go2("export"); refreshExportStats(); return; }
  return _go2(id);
};

/* ══ FIRST RUN ══════════════════════════════════════════════════════════
   The bundled ruleset is a fixture. Opening straight into it made it look
   like a loaded project, and a firewall you did not write is a confusing
   thing to be shown without explanation. */

function startEmpty(){
  /* The kept names belong to the project, so a new one starts without them —
     otherwise the interfaces of the box you just finished follow you into the
     next. Cleared before edit() so the render inside it sees the empty lists.
     They stay outside the undo snapshot, as everywhere else: the palette edits
     them without going through edit(), and a snapshot that owned them would let
     an unrelated undo quietly revert one. */
  setProject({open:true, name:"untitled", origin:null, path:null,
              scratch:{ifaces:[], networks:[]}});
  edit(t("new ruleset","ruleset nuevo"), ()=>{
    const e = blankRuleset();
    MODEL.chains = e.chains; MODEL.sets = e.sets;
    MODEL.objects = []; MODEL.tables = [];
  });
  showProject();
  go("editor");
}


function showProject(){
  /* With nothing open the name is empty, which left a folder icon over a gap
     that read as something failing to load. It says what it is instead. */
  const label = project.open ? project.name : t("no project","sin proyecto");
  const nm = $("#proj-name-t");
  if(nm){ nm.textContent = label; nm.classList.toggle("dimmer", !project.open); }
  const tb = $("#tb-proj");
  if(tb) tb.textContent = label;
  /* the table list was hard-coded to "inet fw", which stopped being true the
     moment anyone imported or started fresh */
  const tables = [...new Set(MODEL.chains.map(c=>c.table))];
  const tb2 = $("#proj-tables");
  if(tb2) tb2.textContent = tables.length
    ? "/ " + tables.slice(0,2).join(" · ") + (tables.length>2 ? ` +${tables.length-2}` : "")
    : "";

  /* Everywhere else the name or the origin was written out by hand. Each of
     those was a small lie the moment anything was imported or renamed. */
  const rules = MODEL.chains.reduce((a,c)=>a+c.rules.filter(r=>r.on).length,0);
  const dn = $("#dash-name");   if(dn) dn.textContent = label;
  const ds = $("#dash-sub");
  if(ds) ds.textContent = [
    tables.join(" · ") || t("no tables yet","aún sin tablas"),
    t(`${MODEL.chains.length} chains · ${rules} rules`,
      `${MODEL.chains.length} cadenas · ${rules} reglas`),
    project.origin
      ? t(`from ${project.origin}`, `desde ${project.origin}`)
      : t("not saved yet","sin guardar todavía"),
  ].join(" · ");
  const cf = $("#code-filename");
  if(cf) cf.textContent = t("Generated · ","Generado · ") + project.name + ".nft";
  const ap = $("#about-project"); if(ap) ap.textContent = label;

  /* What the branch indicator pretended to say. This one is true. */
  const sv = $("#st-saved-t");
  if(sv) sv.textContent = !project.open ? "—"
    : !project.path      ? t("not saved","sin guardar")
    : HIST.past.length   ? t(`${HIST.past.length} unsaved`, `${HIST.past.length} sin guardar`)
                         : t("saved","guardado");
  $$(".fname").forEach(n=> n.textContent = project.name + ".nft");
}

/* ── renaming ───────────────────────────────────────────────────────────
   The name is not decoration: it goes in the header comment of the generated
   ruleset and becomes the export filename. */
function beginRename(){
  if(!project.open) return;      /* there is nothing to name yet */
  const btn = $("#proj-name"), input = $("#proj-input");
  input.value = project.name;
  btn.style.display = "none";
  input.classList.add("on");
  input.focus();
  input.select();

  const commit = save=>{
    if(!input.classList.contains("on")) return;
    input.classList.remove("on");
    btn.style.display = "";
    const next = input.value.trim().replace(/[\r\n"]/g, "");
    if(save && next && next !== project.name){
      setProject({name: next});
      showProject();
      paintCode();        /* the header comment carries the name */
      toast(t(`Renamed to ${next}`, `Renombrado a ${next}`));
    }
    input.removeEventListener("blur", onBlur);
    input.removeEventListener("keydown", onKey);
  };
  const onBlur = ()=>commit(true);
  const onKey = e=>{
    if(e.key === "Enter"){ e.preventDefault(); commit(true); }
    if(e.key === "Escape"){ e.preventDefault(); commit(false); }
    e.stopPropagation();     /* keep Ctrl+N and friends out of the field */
  };
  input.addEventListener("blur", onBlur);
  input.addEventListener("keydown", onKey);
}

$("#proj-name").addEventListener("click", beginRename);
document.addEventListener("keydown", e=>{
  if(e.key === "F2" && !e.target.closest("input, textarea")){ e.preventDefault(); beginRename(); }
});

/* The first-run dialog and its opener lived here. Both are gone: the empty
   state offers the same choices, and it is what you are looking at rather
   than something laid over what you were looking at. */

/* The sample badge is the affordance, not just a label: it says what this is
   and clicking it offers the way out. A first-run dialog you can dismiss is
   not a way to get rid of something permanently. */

/* The app's own confirmation, not window.confirm: a native modal is blocked
   in some webviews and looks wrong against a frameless window. */
function confirmDialog(title, body, ok){
  return new Promise(resolve=>{
    $("#cf-title").textContent = title;
    $("#cf-body").textContent = body;
    $("#cf-yes").textContent = ok;
    const scrim = $("#scrim-confirm");
    scrim.classList.add("on");
    const done = v => { scrim.classList.remove("on"); cleanup(); resolve(v); };
    const onYes = ()=>done(true), onNo = ()=>done(false);
    const onKey = e => { if(e.key==="Escape") done(false); };
    function cleanup(){
      $("#cf-yes").removeEventListener("click", onYes);
      $("#cf-no").removeEventListener("click", onNo);
      document.removeEventListener("keydown", onKey);
    }
    $("#cf-yes").addEventListener("click", onYes);
    $("#cf-no").addEventListener("click", onNo);
    document.addEventListener("keydown", onKey);
  });
}

$("#btn-new").addEventListener("click", async ()=>{
  if(HIST.past.length){
    const go_ahead = await confirmDialog(
      t("Discard the current ruleset?","¿Descartar el ruleset actual?"),
      t("You have unsaved edits. Starting empty replaces them — Ctrl+Z will bring them back.",
        "Tienes ediciones sin guardar. Empezar en blanco las reemplaza — Ctrl+Z las recupera."),
      t("Start empty","Empezar en blanco"));
    if(!go_ahead) return;
  }
  startEmpty();
  toast(t("New ruleset — Ctrl+Z to bring the old one back",
          "Ruleset nuevo — Ctrl+Z recupera el anterior"));
});
document.addEventListener("keydown", e=>{
  if((e.ctrlKey||e.metaKey) && e.key.toLowerCase()==="n" && !e.target.closest("input,textarea")){
    e.preventDefault(); $("#btn-new").click();
  }
  /* Ctrl+S is the one shortcut everybody tries without being told. The browser
     would otherwise offer to save the page, which is never what was meant. */
  if((e.ctrlKey||e.metaKey) && !e.shiftKey && e.key.toLowerCase()==="s"){
    e.preventDefault(); $("#btn-save").click();
  }
});


/* ══ keep every derived view in step with the model ═════════════════════ */
[renderSets, renderTopo, renderDash].forEach(f=>{ MODEL_HOOKS.push(f); RERENDER.push(f); });
renderSets(); renderTopo(); renderDash();
/* ══ RENAMING WHAT THE RULES MENTION ════════════════════════════════════
   An interface or an address is not an object you can open and edit — it is
   a string repeated across rules. So the operation people actually want is
   "change it everywhere", and without it the only route was editing every
   rule by hand. */

/* A text prompt in the app's own chrome; window.prompt is blocked in webviews. */
function promptDialog(title, body, value, ok){
  return new Promise(resolve=>{
    $("#cf-title").textContent = title;
    $("#cf-body").innerHTML = "";
    const p = el("p"); p.textContent = body;
    p.style.cssText = "font-size:12.5px;line-height:1.6;color:var(--t2);margin-bottom:11px";
    const input = el("input"); input.type = "text"; input.value = value; input.spellcheck = false;
    $("#cf-body").append(p, input);
    $("#cf-yes").textContent = ok;
    const scrim = $("#scrim-confirm");
    scrim.classList.add("on");
    input.focus(); input.select();

    const done = v => {
      scrim.classList.remove("on");
      $("#cf-yes").removeEventListener("click", yes);
      $("#cf-no").removeEventListener("click", no);
      document.removeEventListener("keydown", key);
      $("#cf-body").innerHTML = "";
      resolve(v);
    };
    const yes = ()=>done(input.value.trim());
    const no  = ()=>done(null);
    const key = e=>{
      if(e.key==="Enter"){ e.preventDefault(); yes(); }
      if(e.key==="Escape"){ e.preventDefault(); no(); }
      e.stopPropagation();
    };
    $("#cf-yes").addEventListener("click", yes);
    $("#cf-no").addEventListener("click", no);
    document.addEventListener("keydown", key);
  });
}

/* Rewrites a bare token wherever the rules use it, quoted or not. */
function renameEverywhere(kind, from, to){
  const q = s => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const re = kind === "IF"
    ? new RegExp(`((?:iif|oif)(?:name)?\\s+)"?${q(from)}"?(?![\\w.-])`, "g")
    : new RegExp(`(\\bip6?\\s+[sd]addr\\s+(?:!=\\s*)?)${q(from)}(?![\\w.:/])`, "g");
  const sub = kind === "IF" ? `$1"${to}"` : `$1${to}`;

  let hits = 0;
  MODEL.chains.forEach(ch=> ch.rules.forEach(r=>{
    const next = r.expr.replace(re, sub);
    if(next !== r.expr){ r.expr = next; hits++; }
  }));
  return hits;
}

const usagesOf = (kind, name) => {
  const re = kind === "IF"
    ? new RegExp(`(?:iif|oif)(?:name)?\\s+"?${name.replace(/[.*+?^${}()|[\]\\]/g,"\\$&")}"?(?![\\w.-])`)
    : new RegExp(`\\bip6?\\s+[sd]addr\\s+(?:!=\\s*)?${name.replace(/[.*+?^${}()|[\]\\]/g,"\\$&")}(?![\\w.:/])`);
  const out = [];
  MODEL.chains.forEach(ch=> ch.rules.forEach((r,i)=>{ if(r.on && re.test(r.expr)) out.push({ch,i}); }));
  return out;
};

const scratchOf = kind => kind === "IF" ? project.scratch.ifaces : project.scratch.networks;

/* Kept names are not part of MODEL, so the model hooks that refresh the
   interface pickers never fire for them. Every edit to a kept list goes
   through here, or the palette and the pickers drift apart again. */
const scratchChanged = ()=>{ renderLibrary(); fillInterfaces(); };

/* Keeping a name to hand before any rule uses it. */
$("#lib-body").addEventListener("click", async e=>{
  const add = e.target.closest("[data-add]");
  if(!add) return;
  e.preventDefault();
  e.stopPropagation();          /* do not toggle the <details> */
  const kind = add.dataset.add;

  /* the vocabularies take a line rather than a bare name, because a service
     without its port is not a service */
  const spec = OWNABLE[kind];
  if(spec){
    const CAT = {SV:t("service","servicio"), PR:t("protocol","protocolo"), HL:t("helper","helper")};
    const line = await promptDialog(
      t(`Add a ${CAT[kind]}`, `Añadir un ${CAT[kind]}`),
      t(`${spec.hint.en}. Kept on this machine, so it is here in every project.`,
        `${spec.hint.es}. Se guarda en esta máquina, así que estará en todos tus proyectos.`),
      spec.example, t("Add","Añadir"));
    if(!line) return;
    const parsed = spec.parse(line);
    if(!parsed){
      toast(t(`Could not read “${line}” — try ${spec.example}`,
              `No se entiende «${line}» — prueba ${spec.example}`));
      return;
    }
    const list = ownOf(kind);
    const at = list.findIndex(x=>x.n === parsed.n);
    if(at >= 0) list[at] = parsed; else list.push(parsed);
    vocabChanged();
    toast(t(`${parsed.n} kept on this machine`, `${parsed.n} guardado en esta máquina`));
    return;
  }

  const name = await promptDialog(
    kind === "IF" ? t("Add an interface","Añadir interfaz") : t("Add a network","Añadir red"),
    kind === "IF"
      ? t("A name you expect to use, so it is there to drag onto a rule. It becomes real once a rule mentions it.",
          "Un nombre que piensas usar, para tenerlo a mano y arrastrarlo a una regla. Se vuelve real cuando una regla lo nombra.")
      : t("An address or range you work with, kept with the project.",
          "Una dirección o rango con el que trabajas, guardado con el proyecto."),
    kind === "IF" ? "eth1" : "10.10.0.0/24",
    t("Add","Añadir"));
  if(!name) return;
  const list = scratchOf(kind);
  if(!list.includes(name)) list.push(name);
  scratchChanged();
  toast(t(`${name} kept with the project`, `${name} guardado con el proyecto`));
});

document.addEventListener("contextmenu", e=>{
  const obj = e.target.closest("#lib-body .obj");
  if(!obj) return;
  const kind = $(".gl", obj).textContent.trim();

  /* A vocabulary entry you added is yours to change; a built-in one is not,
     but you can shadow it by adding the same name with a different port. */
  if(OWNABLE[kind]){
    const n = $(".nm", obj).textContent.trim();
    const list = ownOf(kind);
    const at = list.findIndex(x=>x.n === n);
    if(at < 0){
      e.preventDefault(); e.stopPropagation();
      const m0 = openCtx(e.clientX, e.clientY, [["shadow",
        t("Override with your own…","Sustituir por el tuyo…"), "M4 20h4L19 9a2.8 2.8 0 0 0-4-4L4 16z"]]);
      m0.addEventListener("click", async ev=>{
        if(!ev.target.closest("[data-act]")) return;
        killCtx();
        $(`[data-add="${kind}"]`)?.click();
      });
      return;
    }
    e.preventDefault(); e.stopPropagation();
    const spec = OWNABLE[kind];
    const cur = list[at];
    const asLine = cur.p ? `${cur.n} ${cur.p}/${cur.proto}` : cur.n;
    const m1 = openCtx(e.clientX, e.clientY, [
      ["edit", t("Edit","Editar"), "M4 20h4L19 9a2.8 2.8 0 0 0-4-4L4 16z"],
      ["drop", t("Remove from the list","Quitar de la lista"),
       "M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13", true],
    ]);
    m1.addEventListener("click", async ev=>{
      const a = ev.target.closest("[data-act]"); if(!a) return;
      const act = a.dataset.act; killCtx();
      if(act === "drop"){ list.splice(at,1); vocabChanged(); return; }
      const line = await promptDialog(t("Edit","Editar"),
        t(spec.hint.en, spec.hint.es), asLine, t("Save","Guardar"));
      if(!line) return;
      const parsed = spec.parse(line);
      if(!parsed){ toast(t(`Could not read “${line}”`,`No se entiende «${line}»`)); return; }
      list[at] = parsed;
      vocabChanged();
    });
    return;
  }

  if(kind !== "IF" && kind !== "NW") return;   /* the rest are closed by nftables */
  const name = $(".nm", obj).textContent.trim();
  const uses = usagesOf(kind, name);
  const kept = scratchOf(kind).includes(name);
  if(!uses.length && !kept) return;
  e.preventDefault();
  e.stopPropagation();

  const m = openCtx(e.clientX, e.clientY, uses.length ? [
    ["ren",  t(`Rename everywhere (${uses.length})`, `Renombrar en todo (${uses.length})`),
     "M4 20h4L19 9a2.8 2.8 0 0 0-4-4L4 16z"],
    ["show", t("Show the rules using it","Ver las reglas que lo usan"),
     "M2 12s4-7 10-7 10 7 10 7-4 7-10 7-10-7-10-7z"],
  ] : [
    ["edit", t("Edit","Editar"), "M4 20h4L19 9a2.8 2.8 0 0 0-4-4L4 16z"],
    ["drop", t("Remove from the list","Quitar de la lista"),
     "M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13", true],
  ]);
  m.addEventListener("click", async ev=>{
    const a = ev.target.closest("[data-act]"); if(!a) return;
    const act = a.dataset.act;
    killCtx();

    /* a name nobody uses yet is just a note, so it edits and deletes plainly */
    if(act === "drop"){
      const list = scratchOf(kind);
      list.splice(list.indexOf(name), 1);
      scratchChanged();
      return;
    }
    if(act === "edit"){
      const next = await promptDialog(
        kind === "IF" ? t("Edit interface","Editar interfaz") : t("Edit network","Editar red"),
        t("No rule uses it yet, so nothing else changes.",
          "Ninguna regla lo usa todavía, así que no cambia nada más."),
        name, t("Save","Guardar"));
      if(!next || next === name) return;
      const list = scratchOf(kind);
      list[list.indexOf(name)] = next;
      scratchChanged();
      return;
    }

    if(act === "show"){
      go("editor");
      const keys = new Set(uses.map(u=>UID(u.ch)+":"+u.i));
      $$(".rule").forEach(r=>r.classList.toggle("faded", !keys.has(r.dataset.chain+":"+r.dataset.i)));
      setTimeout(()=>$$(".rule").forEach(r=>r.classList.remove("faded")), 2600);
      select(UID(uses[0].ch), uses[0].i, true);
      return;
    }

    const next = await promptDialog(
      kind === "IF" ? t("Rename interface","Renombrar interfaz") : t("Change address","Cambiar dirección"),
      t(`${name} is named by ${uses.length} rule(s). Renaming rewrites all of them; Ctrl+Z undoes it.`,
        `${name} lo nombran ${uses.length} regla(s). Renombrar las reescribe todas; Ctrl+Z lo deshace.`),
      name, t("Rename","Renombrar"));
    if(!next || next === name) return;

    let hits = 0;
    edit(t("rename "+name, "renombrar "+name), ()=>{ hits = renameEverywhere(kind, name, next); });
    toast(t(`${name} → ${next} in ${hits} rules`, `${name} → ${next} en ${hits} reglas`));
  });
}, true);

/* ══ CHAINS ═════════════════════════════════════════════════════════════
   You could edit rules but never create the chain to put them in, which made
   a NAT ruleset impossible to build from scratch. */
let chEditing = null;   /* uid when editing, null when creating */

function chDraft(){
  return {
    id: $("#ch-name").value.trim(),
    table: $("#ch-table").value.trim(),
    kind: $("#ch-kind .on")?.dataset.kind || "base",
    type: $("#ch-type").value,
    hook: $("#ch-hook").value,
    prio: $("#ch-prio").value.trim(),
    policy: $("#ch-policy").value,
  };
}

function chSync(){
  const d = chDraft(), base = d.kind === "base";
  $("#ch-base").style.display = base ? "flex" : "none";
  $("#ch-kind-note").textContent = base
    ? t("Attached to a netfilter hook — packets enter it on their own.",
        "Enganchada a un hook de netfilter: los paquetes entran solos.")
    : t("Reached only by jump or goto from another chain.",
        "Solo se alcanza con jump o goto desde otra cadena.");

  const prio = /^-?\d+$/.test(d.prio) ? +d.prio : (PRIO_NAME[d.prio] ?? 0);
  $("#ch-preview").innerHTML = highlight(
    `table ${d.table || "?"} { chain ${d.id || "?"} { ` +
    (base ? `type ${d.type} hook ${d.hook} priority ${prio} ; policy ${d.policy} ; ` : "") + "} }");

  /* nftables allows one chain name per table, and nat chains only on the
     hooks that can translate */
  const clash = MODEL.chains.some(c => c.table === d.table && c.id === d.id && UID(c) !== chEditing);
  const badHook = base && d.type === "nat" &&
    !["prerouting","input","output","postrouting"].includes(d.hook);
  const warn = $("#ch-warn");
  const msg = !d.id || !d.table
    ? t("A chain needs a name and a table.","Una cadena necesita nombre y tabla.")
    : clash ? t(`${d.table} already has a chain called ${d.id}.`,
                `${d.table} ya tiene una cadena llamada ${d.id}.`)
    : badHook ? t("nat chains cannot attach to the forward hook.",
                  "Las cadenas nat no pueden engancharse al hook forward.")
    : "";
  warn.style.display = msg ? "" : "none";
  warn.textContent = msg;
  $("#ch-save").disabled = !!msg;
}

function openChain(uid){
  chEditing = uid || null;
  const ch = uid && chainOf(uid);
  $("#ch-title").textContent = ch
    ? t("Chain properties","Propiedades de la cadena")
    : t("New chain","Cadena nueva");
  $("#ch-save").textContent = ch ? t("Save","Guardar") : t("Create chain","Crear cadena");
  $("#ch-delete").style.display = ch ? "" : "none";

  const tables = [...new Set(MODEL.chains.map(c=>c.table))];
  $("#ch-tables").innerHTML = tables.map(x=>`<option value="${esc(x)}">`).join("");

  $("#ch-name").value  = ch ? ch.id : "";
  $("#ch-table").value = ch ? ch.table : (tables[0] || "inet filter");
  $("#ch-type").value  = ch?.type && ch.type !== "regular" ? ch.type : "filter";
  $("#ch-hook").value  = ch?.hook || "prerouting";
  $("#ch-prio").value  = ch && ch.prio !== null ? String(ch.prio) : "0";
  $("#ch-policy").value = ch?.policy || "accept";
  $$("#ch-kind button").forEach(b=>
    b.classList.toggle("on", b.dataset.kind === (ch && !ch.hook ? "regular" : "base")));

  chSync();
  $("#scrim-chain").classList.add("on");
  if(!ch) $("#ch-name").focus();
}

$("#chain-new").addEventListener("click", ()=>openChain(null));
$("#scrim-chain").addEventListener("input", chSync);
$("#scrim-chain").addEventListener("change", chSync);
$("#ch-kind").addEventListener("click", e=>{
  const b = e.target.closest("[data-kind]");
  if(b){ $$("#ch-kind button").forEach(x=>x.classList.toggle("on", x===b)); chSync(); }
});

$("#ch-save").addEventListener("click", ()=>{
  const d = chDraft();
  const base = d.kind === "base";
  const prio = /^-?\d+$/.test(d.prio) ? +d.prio : (PRIO_NAME[d.prio] ?? 0);
  const uid = chEditing;
  edit(uid ? t("edit chain","editar cadena") : t("new chain","cadena nueva"), ()=>{
    const ch = uid ? chainOf(uid) : {rules:[]};
    Object.assign(ch, {
      id:d.id, table:d.table,
      hook: base ? d.hook : null,
      prio: base ? prio : null,
      type: base ? d.type : "regular",
      policy: base ? d.policy : null,
    });
    if(!uid) MODEL.chains.push(ch);
  });
  $("#scrim-chain").classList.remove("on");
  go("editor");
  toast(uid ? t("Chain updated","Cadena actualizada")
            : t(`Added ${d.table} / ${d.id}`, `Añadida ${d.table} / ${d.id}`));
});

$("#ch-delete").addEventListener("click", async ()=>{
  const ch = chainOf(chEditing); if(!ch) return;
  const jumps = MODEL.chains.flatMap(c=>c.rules.filter(r=>
    (r.verdict==="jump"||r.verdict==="goto") && r.to===ch.id && c.table===ch.table));
  const ok = await confirmDialog(
    t(`Delete ${ch.id}?`, `¿Eliminar ${ch.id}?`),
    jumps.length
      ? t(`${jumps.length} rule(s) jump to this chain and would break. Ctrl+Z undoes this.`,
          `${jumps.length} regla(s) saltan a esta cadena y quedarían rotas. Ctrl+Z lo deshace.`)
      : t(`Its ${ch.rules.length} rule(s) go with it. Ctrl+Z undoes this.`,
          `Sus ${ch.rules.length} regla(s) se van con ella. Ctrl+Z lo deshace.`),
    t("Delete","Eliminar"));
  if(!ok) return;
  edit(t("delete chain","eliminar cadena"), ()=>{
    const i = MODEL.chains.indexOf(ch); if(i>=0) MODEL.chains.splice(i,1);
  });
  $("#scrim-chain").classList.remove("on");
});

document.addEventListener("keydown", e=>{
  if((e.ctrlKey||e.metaKey) && e.shiftKey && e.key.toLowerCase()==="n"
     && !e.target.closest("input,textarea")){ e.preventDefault(); openChain(null); }
});

/* ══ TARGET ═════════════════════════════════════════════════════════════
   The chip in the titlebar said "no local nft" and its tooltip suggested
   adding an SSH target, with nothing behind it. This is the something. */
let tgDraft = {...loadTarget()};

/* The chip shows where nft is configured to run — a setting, which exists
   whether or not it is reachable right now. Reachability is the colour and
   the tooltip, not a replacement for the answer. */
function paintTargetChip(state){
  const chip = $("#tb-target"), label = $("#tb-target-t");
  if(!chip) return;
  chip.classList.remove("live","remote");

  label.textContent = target.kind === "ssh"
    ? describe()
    : state?.ok ? state.version : t("no local nft","sin nft local");

  if(state?.ok){
    chip.classList.add(target.kind === "ssh" ? "remote" : "live");
    chip.title = t(`nft reachable — ${state.version}`, `nft accesible — ${state.version}`);
  } else {
    chip.title = (state?.why ? state.why + " · " : "")
      + t("click to choose where nft runs", "pulsa para elegir dónde se ejecuta nft");
  }
}

async function refreshTarget(){
  paintTargetChip(await probe());
}

function syncTargetForm(){
  $$("#scrim-target .choice").forEach(c=>
    c.classList.toggle("on", c.dataset.target === tgDraft.kind));
  $("#tg-fields").style.display = tgDraft.kind === "ssh" ? "flex" : "none";
  $("#tg-host").value = tgDraft.host || "";
  $("#tg-user").value = tgDraft.user || "";
  $("#tg-port").value = tgDraft.port || "";
  $("#tg-sudo").classList.toggle("on", !!tgDraft.sudo);
  $("#tg-preview").textContent = describe(tgDraft);
  $("#tg-local-note").textContent = !native.isDesktop()
    ? t("Unavailable in a browser.","No disponible en navegador.")
    : native.platform.local_nft_possible
      ? t("Linux — nft can run here.","Linux — nft puede ejecutarse aquí.")
      : t(`No nft on ${native.platform.os}. Use SSH.`, `No hay nft en ${native.platform.os}. Usa SSH.`);
}

function openTarget(){
  tgDraft = {...target};
  $("#tg-result").style.display = "none";
  syncTargetForm();
  $("#scrim-target").classList.add("on");
}

$("#tb-target").addEventListener("click", openTarget);
$("#scrim-target").addEventListener("click", e=>{
  const c = e.target.closest("[data-target]");
  if(c){ tgDraft.kind = c.dataset.target; syncTargetForm(); }
  if(e.target.closest("#tg-sudo")){ tgDraft.sudo = !tgDraft.sudo; syncTargetForm(); }
});
$$("#tg-host, #tg-user, #tg-port").forEach(n=>n.addEventListener("input", ()=>{
  tgDraft.host = $("#tg-host").value.trim();
  tgDraft.user = $("#tg-user").value.trim();
  tgDraft.port = $("#tg-port").value.trim();
  $("#tg-preview").textContent = describe(tgDraft);
}));

$("#tg-test").addEventListener("click", async ()=>{
  const box = $("#tg-result");
  box.style.display = "";
  box.className = "tg-result busy";
  box.textContent = t("Asking nft…","Preguntando a nft…");
  const r = await probe(tgDraft);
  box.className = "tg-result " + (r.ok ? "ok" : "bad");
  box.textContent = r.ok
    ? t(`Reachable · ${r.version}`, `Accesible · ${r.version}`)
    : r.why;
});

$("#tg-save").addEventListener("click", async ()=>{
  saveTarget(tgDraft);
  $("#scrim-target").classList.remove("on");
  await refreshTarget();
  toast(t(`nft will run on ${describe()}`, `nft se ejecutará en ${describe()}`));
});

/* ── the two things a target is for ── */
$("#imp-host")?.addEventListener("click", async ()=>{
  const r = await native.nftList(asTauriTarget());
  if(!r.ok){ toast(r.stderr.trim().split("\n")[0] || t("could not read","no se pudo leer")); return; }
  $("#imp-text").value = r.stdout;
  $("#imp-text").dispatchEvent(new Event("input", {bubbles:true}));
  toast(t(`Read from ${describe()}`, `Leído de ${describe()}`));
});

$("#val-nft")?.addEventListener("click", async ()=>{
  const btn = $("#val-nft"), was = btn.textContent;
  btn.textContent = t("Checking…","Comprobando…");
  const r = await native.nftCheck(generate().join("\n"), asTauriTarget());
  btn.textContent = was;
  const box = $("#val-nft-out");
  box.style.display = "";
  box.className = "nft-out " + (r.ok ? "ok" : "bad");
  box.textContent = r.ok
    ? t(`nft -c accepted the ruleset on ${describe()}.`,
        `nft -c aceptó el ruleset en ${describe()}.`)
    : (r.stderr || r.stdout).trim();
});

loadTarget();
refreshTarget();

/* the header follows the ruleset: chains, rules and tables all live there */
MODEL_HOOKS.push(showProject);
RERENDER.push(showProject);
showProject();

/* The first-run dialog used to open here, over a ruleset the user had not
   asked for. The empty state says the same three things without anything
   behind it to dismiss it onto. */

/* ══ INTERACTIVE TUTORIAL ═══════════════════════════════════════════════
   A spotlight and a card over the real interface, rather than a slideshow
   beside it. The hole takes no pointer events, so the control being pointed
   at stays usable — the user does the thing, and the step notices.

   A step that waits still offers Skip. A tutorial you cannot get out of is a
   trap, and someone who cannot find a control has already learned the worst
   possible lesson about the product. */
TOURI = -1;
let TOURBASE = null;

const tourOn = () => TOURI >= 0;

function startTour(){
  $$(".scrim").forEach(s=>s.classList.remove("on"));
  TOURI = 0;
  $("#tour").classList.add("on");
  paintTour();
}

function endTour(){
  TOURI = -1; TOURBASE = null;
  $("#tour").classList.remove("on");
  try{ localStorage.setItem("efeflow.tour","1"); }catch{ /* private mode */ }
}

function tourGo(n){
  if(n < 0) return;
  if(n >= TOUR.length) return endTour();
  TOURI = n;
  paintTour();
}

function paintTour(){
  const s = tourStep(TOURI); if(!s) return endTour();
  if(s.screen) go(s.screen);
  TOURBASE = s.baseline ? s.baseline(MODEL) : null;

  $("#tour-n").textContent = `${TOURI+1}/${TOUR.length}`;
  $("#tour-title").textContent = t(s.title.en, s.title.es);
  $("#tour-body").textContent  = t(s.body.en,  s.body.es);
  $("#tour-back").style.visibility = TOURI === 0 ? "hidden" : "";

  const last = TOURI === TOUR.length - 1;
  $("#tour-next").textContent = last ? t("Done","Listo")
                              : s.done ? t("Skip","Saltar")
                                       : t("Next","Siguiente");
  $("#tour-wait").textContent = s.done ? t("your turn","te toca") : "";
  $("#tour-wait").classList.toggle("on", !!s.done);

  requestAnimationFrame(placeTour);
}

/* The hole follows the target; the card avoids covering it. */
function placeTour(){
  const s = tourStep(TOURI); if(!s) return;
  const hole = $("#tour-hole"), card = $("#tour-card");
  if(!hole || !card) return;
  const el = s.target ? $(s.target) : null;

  if(!el){
    /* nothing to point at: dim everything and centre the card */
    hole.classList.add("blind");
    hole.style.left = "50%"; hole.style.top = "50%";
    hole.style.width = "0"; hole.style.height = "0";
    card.style.left = Math.max(12, (innerWidth - 352)/2) + "px";
    card.style.top  = Math.max(12, (innerHeight - (card.offsetHeight||190))/2) + "px";
    return;
  }

  hole.classList.remove("blind");
  el.scrollIntoView({block:"nearest", inline:"nearest"});
  const r = el.getBoundingClientRect(), pad = 6;
  hole.style.left   = (r.left - pad) + "px";
  hole.style.top    = (r.top  - pad) + "px";
  hole.style.width  = (r.width  + pad*2) + "px";
  hole.style.height = (r.height + pad*2) + "px";

  const cw = 352, ch = card.offsetHeight || 190;
  card.style.left = Math.min(Math.max(12, r.left + r.width/2 - cw/2), innerWidth - cw - 12) + "px";
  const below = r.bottom + 14;
  card.style.top = (below + ch > innerHeight - 12 ? Math.max(12, r.top - ch - 14) : below) + "px";
}

/* The step decides when it is finished, by looking at the ruleset. */
function tourCheck(){
  const s = tourStep(TOURI);
  if(!s || !s.done) return;
  if(s.done(MODEL, TOURBASE)) tourGo(TOURI + 1);
}
MODEL_HOOKS.push(tourCheck);
RERENDER.push(()=>{ if(tourOn()) requestAnimationFrame(placeTour); });
window.addEventListener("resize", ()=>{ if(tourOn()) placeTour(); });

$("#tour-next").addEventListener("click", ()=>tourGo(TOURI + 1));
$("#tour-back").addEventListener("click", ()=>tourGo(TOURI - 1));
$("#tour-x").addEventListener("click", endTour);
$("#g-tour-go").addEventListener("click", startTour);
document.addEventListener("keydown", e=>{ if(e.key === "Escape" && tourOn()) endTour(); });

/* ══ NO PROJECT ═════════════════════════════════════════════════════════
   Everything on every screen describes a ruleset, so booting with one nobody
   asked for was a small lie about what state you were in. The empty state is
   the entry point now — it replaced a first-run dialog that sat over a
   project called "untitled", which you then had to notice and get rid of. */
function paintEmpty(){
  const es = $("#empty-state"); if(!es) return;
  es.classList.toggle("on", !project.open);
}
function openProject(){
  if(project.open) return;
  setProject({open:true});
  paintEmpty();
}
MODEL_HOOKS.push(paintEmpty);
paintEmpty();

$("#es-new").addEventListener("click", ()=>{ startEmpty(); });
$("#es-import").addEventListener("click", ()=>go("import"));
$("#es-tour").addEventListener("click", ()=>{ startEmpty(); startTour(); });

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
