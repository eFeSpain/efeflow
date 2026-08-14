/* eFeFlow — the interface.
 *
 * Everything with a verdict in it lives in ./core: the parser, the generator,
 * the analyser and the packet evaluator are pure and covered by `npm test`.
 * This module is the part that has to touch the DOM. */

import {
  MODEL, R, UID, chainOf, blankRuleset, VCOLOR, VNAME, ruleLine,
} from "./core/model.js";
import { generate, generateWithMap } from "./core/generate.js";
import { parseNft, normalise } from "./core/parse.js";
import { diffLines } from "./core/diff.js";
import { PRIO_NAME, NAME_PRIO, readPriority } from "./core/priority.js";
import { PROJECT, project, setProject } from "./core/project.js";
import { TOUR, tourStep } from "./core/tour.js";
import { OWNABLE } from "./core/vocabulary.js";
import { readObject, editObject, refsToObject, OBJECT_FIELDS, OBJECT_TEMPLATE, OBJECT_KINDS } from "./core/objects.js";
import { reservedName } from "./core/lint.js";
import { FAMILIES, splitTable, joinTable, tableNames, readTable, writeTable,
         renameTable, removeTable, isDormant, dormantTables } from "./core/tables.js";
import { modelChanged, rerender, onModelChange, onRender, findings, onApplied } from "./core/bus.js";
import { t, lang, setLang, applyLang, onLangChange } from "./i18n.js";
import { target, loadTarget, saveTarget, asTauriTarget, describe, probe,
         hosts, forgetHost } from "./target.js";
import { asTarget, matching, label as hostLabel } from "./core/hosts.js";
import { applyWithNet, surgicalChanges, keep, rollBackNow, pendingRollback } from "./apply.js";
import { refreshCounters, checkDrift } from "./host.js";
import { applyPlan } from "./core/sync.js";
import { surgicalPlan } from "./core/surgical.js";
import * as native from "./native.js";
import { $, $$, esc, el, cssEsc, toast, highlight, setNavigator } from "./ui/shell.js";
import { UI } from "./ui/state.js";
import { placeChains, renderChains, drawWires, syncViewport } from "./ui/canvas.js";
import { renderSets, showSet, refsTo } from "./ui/sets.js";
import { edit, undo, snapshot, syncHistUI, setRepainter,
         state as hist, undoStack } from "./ui/history.js";
/* Where nft runs, and everything that reaches a machine, lives in its own
   module now. REACH is a live binding: read here, decided there. */
import { REACH, paintTargetChip, showRootHelp } from "./ui/host.js";
/* The packet simulator draws itself; these four are the handles the rest of
   the interface still holds — navigation re-runs it on arrival and stops it
   on the way out, and the vocabulary palette refreshes its interface list. */
import { runSim, stopSim, readForm, fillInterfaces } from "./ui/simulator.js";
/* The validation screen paints itself onto the bus; these three are what the
   properties panel, the raw-rule lint and the palette still say to it. */
import { findingsFor, tt, applyAll } from "./ui/findings.js";
/* In and out — import, export, and the project file. The navigator routes to
   these two; openProject and showProject travel back the other way, late. */
import { openImport, refreshExportStats, provideProject } from "./ui/project-io.js";
/* The editor owns select and the context menu; the chain dialog and the code
   pane have not moved out yet, so their three verbs travel back through
   provideEditor the way openProject does. */
import { EMPTY, select, openCtx, killCtx, renderLibrary, ownOf, vocabChanged,
         mergeVocab, fragment, provideEditor } from "./ui/editor.js";
import { interfaces, addresses, ifaceNames } from "./core/mentions.js";

/* Still the public face of these: a handful of tests reach for them here,
   and this file is what the application is. */
export { esc, toast };
export { paintTargetChip, showRootHelp };
export { addresses, ifaceNames };
export { fragment };

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
let CODE_VARIANT, BASELINE, DW_TAB, TOPO_MODE, PAL, PALI, TOURI;


/* Injected by vite from package.json. Falls back for the test harness, which
   evaluates these modules directly rather than through a build. */
const APP_VERSION = typeof __APP_VERSION__ === "string" ? __APP_VERSION__ : "dev";

/* the top-left badge carries the version beside BETA, from the same injected
   source as the About panel — so bumping the version moves both at once */
const betaBadge = $("#tb-beta");
if(betaBadge) betaBadge.textContent = `${APP_VERSION} ${t("beta","beta")}`;

/* the screens live at document root while authoring; dock them into the shell */
$$(".screen").forEach(s=>$("#screens").appendChild(s));
$$(".scrim").forEach(s=>document.body.appendChild(s));

/* ══ MODEL ══════════════════════════════════════════════════════════════
   Real nftables semantics: a chain is (hook, priority, policy); a rule is
   an ordered list of match expressions terminated by a verdict.          */
/* ══ HISTORY ════════════════════════════════════════════════════════════
   The gate itself is in ui/history.js — forty-eight of its callers were
   outside this file, which is a large part of why this file could not be
   broken up. What stays here is the half it cannot own: what to repaint once
   a change has landed. */
function refresh(keepSel){
  renderChains(); paintCode(); drawWires(); modelChanged();
  if(keepSel && UI.sel){
    const ch = chainOf(UI.sel.chainId);
    if(ch && ch.rules.length){ select(UI.sel.chainId, Math.min(UI.sel.i, ch.rules.length-1)); return; }
  }
  UI.sel = null; $("#props-body").innerHTML = EMPTY();
}
setRepainter(refresh);

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

setNavigator(go);
provideProject({ openProject, showProject });
provideEditor({ openChain, chSync, paintCode });
function go(id){
  if(id==="import"){ openImport(); return; }
  if(id==="export"){ $("#scrim-export").classList.add("on"); refreshExportStats(); return; }
  if(id==="about"){ $("#scrim-about").classList.add("on"); return; }
  if(id==="open"){ $("#scrim-palette").classList.add("on"); $("#pal-input").value=""; renderPalette(); $("#pal-input").focus(); return; }
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

/* ══ CODE GENERATION ════════════════════════════════════════════════════ */
/* Tables are discovered from the model, never assumed. Hard-coding them
   silently dropped every chain of an imported ruleset whose tables were
   named anything else. */
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

  /* The code screen shows whichever variant is chosen there, and repainting
     after an edit used to put the full ruleset back under a Delta tab that
     still said Delta. */
  const v = CODE_VARIANT || "full";
  const shown = v === "full" ? lines : codeLines(v);
  $("#codeout2").innerHTML = v === "full" ? html : shown.map((l,i)=>
    `<div class="ln"><span class="no">${i+1}</span><span class="tx">${highlight(l)}</span></div>`).join("");
  $("#code-lines").textContent = t(`${shown.length} lines`, `${shown.length} líneas`);
  $$(".dw-tab")[0].querySelector(".n").textContent = lines.length;
}
paintCode();
/* the line count is a sentence, so it has to be re-said in the other language */
RERENDER.push(paintCode);

/* click a code line → select the matching rule (round-trip both ways) */
document.addEventListener("click",e=>{
  const ln = e.target.closest("#codeout .ln, #codeout2 .ln"); if(!ln) return;
  /* the line knows which rule it came from; no need to search by text, which
     used to land on whichever chain happened to hold an identical rule first */
  if(ln.dataset.chain) select(ln.dataset.chain, +ln.dataset.i, true);
});

/* ══ CODE VARIANTS ═════════════════════════════════════════════════════
   Full is the ruleset, and it starts by emptying the kernel. Tables replaces
   only the ones this project owns, which is what you want on a host that also
   runs Docker or libvirt — and what the apply dialog sends by default. Delta
   is what you would send to a running box. Atomic is the same ruleset wrapped
   so a syntax error changes nothing. */
CODE_VARIANT = "full";
function codeLines(mode){
  const base = generate(MODEL, mode==="tables" ? {scope:"tables"} : undefined);
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
/* A ruleset that reached a host and stayed there: what is running is now what
   is here, so the drawer has a new baseline to diff against. The apply used to
   call this directly, which is one of the wires that kept it in this file. */
onApplied(setBaseline);

/* classic LCS diff — the rulesets are small enough that clarity wins */
DW_TAB = "code";
function paintDrawer(){
  const cur = codeLines(CODE_VARIANT);
  const diff = BASELINE ? diffLines(BASELINE.split("\n"), generate()) : [];
  const adds = diff.filter(d=>d[0]==="+").length, dels = diff.filter(d=>d[0]==="-").length;

  const tabs = $$(".dw-tab");
  tabs[0].querySelector(".n").textContent = cur.length;
  tabs[1].querySelector(".n").textContent = adds||dels ? `+${adds} −${dels}` : "—";
  tabs[2].querySelector(".n").textContent = findings.list.filter(f=>f.sev!=="hint").length;
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
          <span style="color:var(--t1)">${esc(tt(f.title))}</span>
          <span style="color:var(--t4)"> · ${esc(f.where)}</span></span>
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
  $$("#code-variant [data-cv]").forEach(x=>x.classList.toggle("on", x===b));
  paintCode();
});

/* ══ CANVAS TOOLS ══════════════════════════════════════════════════════ */
UI.tool = "select";
$(".cv-tools").addEventListener("click", e=>{
  const b = e.target.closest("[data-tool]"); if(!b) return;
  UI.tool = b.dataset.tool;
  $$("[data-tool]").forEach(x=>x.classList.toggle("on", x===b));
  $("#cscroll").style.cursor = UI.tool==="pan" ? "grab" : "";
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
    if(!(UI.tool==="pan" || middle || bg)) return;
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
    sc.style.cursor = UI.tool==="pan" ? "grab" : ""; sc.style.scrollBehavior = ""; };
  sc.addEventListener("pointerup", end);
  sc.addEventListener("pointercancel", end);
})();
document.addEventListener("keydown", e=>{
  /* the event target is not always an element — a key dispatched at the
     document itself threw here, taking every later handler with it */
  if(e.target?.closest?.("input, textarea, select")) return;
  if(e.key==="v" || e.key==="V") $('[data-tool="select"]')?.click();
  if(e.key==="h" || e.key==="H") $('[data-tool="pan"]')?.click();
});

/* ══ SIDE PANELS ════════════════════════════════════════════════════════
   The library and the properties panel took 564px between them, fixed. On a
   1440px laptop that left the canvas 828 — 57% of the window for the thing the
   window is about — and a ruleset wide enough to need the space scrolled
   sideways at every UI.zoom where a rule was still readable. Fit to view already
   apologised for it in a toast.

   Either one can be put away now, and the grid track goes with it rather than
   leaving a hole. Which is also what floating the properties panel should
   always have done: it left the 320px column standing, empty, and dropped the
   panel on top of the canvas — so it cost you the space twice. */
const PKEY = "efeflow.panels";
const PANELS = (()=>{
  try{ return {lib:true, props:true, ...JSON.parse(localStorage.getItem(PKEY) || "{}")}; }
  catch{ return {lib:true, props:true}; }   /* private mode, or a mangled value */
})();

function applyPanels(){
  const ed = $("#s-editor"), floating = $(".props").classList.contains("floating");
  ed.classList.toggle("lib-off", !PANELS.lib);
  ed.classList.toggle("props-off", !PANELS.props || floating);
  $("#cv-lib").classList.toggle("on", PANELS.lib);
  $("#cv-props").classList.toggle("on", PANELS.props && !floating);
  try{ localStorage.setItem(PKEY, JSON.stringify(PANELS)); }catch{ /* private mode */ }
  /* the wires and the minimap viewport are drawn against the space the canvas
     actually has, and it just changed */
  requestAnimationFrame(()=>{ drawWires(); syncViewport(); });
}

$("#cv-lib").addEventListener("click", ()=>{ PANELS.lib = !PANELS.lib; applyPanels(); });
$("#cv-props").addEventListener("click", ()=>{
  /* a floating panel is neither shown nor hidden here — it is somewhere else,
     so the first press brings it home */
  if($(".props").classList.contains("floating")){ dockProps(); return; }
  PANELS.props = !PANELS.props;
  applyPanels();
});
document.addEventListener("keydown", e=>{
  if(e.target?.closest?.("input, textarea, select")) return;
  if(e.key === "[") $("#cv-lib").click();
  if(e.key === "]") $("#cv-props").click();
});
applyPanels();

/* ══ FLOATING PROPERTIES ═══════════════════════════════════════════════ */
$("#props-float").addEventListener("click", ()=>{
  const aside = $(".props");
  if(aside.classList.contains("floating")){ dockProps(); return; }
  const r = aside.getBoundingClientRect();
  aside.classList.add("floating");
  /* where the column was, so nothing jumps — and the column closes behind it,
     so the canvas is the one that gains the width */
  aside.style.cssText = `left:${Math.max(12, r.left-10)}px;top:${r.top+18}px;width:330px;height:min(560px,70vh)`;
  applyPanels();
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
  /* coming home means being here: the column reopens whatever it was before */
  PANELS.props = true;
  applyPanels();
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

applyLang();   /* paints every data-t/-tp/-tt and runs every RERENDER hook */

hist.cur = snapshot();
syncHistUI();

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

/* Its own resize, now that the canvas no longer repaints it. */
window.addEventListener("resize", () => {
  if($("#s-topo").classList.contains("on")) renderTopo();
});
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
        return `<div class="hm-ch" data-chain-go="${esc(UID(c))}">
          <div class="n"><span style="color:var(--${c.policy==="drop"?"v-drop":"v-accept"});font-size:9px">◆</span>
            ${esc(c.id)}<span class="p">${c.prio>0?"+"+c.prio:c.prio}</span></div>
          <div class="hm-bars">${bars||'<i style="flex:1;background:var(--line-2)"></i>'}</div></div>`;
      }).join("") : `<div class="hm-empty">${t("no chain","sin cadena")}</div>`}
    </div></div>`;
  }).join("");

  /* version history is the real undo stack, newest first */
  const rows = [{label:t("Working tree","Árbol de trabajo"), now:true},
                ...undoStack().slice().reverse().map(h=>({label:h.label}))].slice(0,6);
  $("#tl-history").innerHTML = rows.map((r,i)=>`
    <div class="tl-row">
      <span class="dot" style="${i===0
        ? "background:var(--aqua);box-shadow:0 0 0 3px rgba(57,213,255,.15)"
        : "background:var(--v-accept)"}"></span>
      <span class="msg">${i===0
        ? `<b>${esc(r.label)}</b> — ${undoStack().length
            ? t(`${undoStack().length} unsaved edits`,`${undoStack().length} ediciones sin guardar`)
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
    const row = $(`.rule[data-chain="${cssEsc(c.dataset.chainGo)}"]`);
    if(row){ select(c.dataset.chainGo, 0); row.scrollIntoView({block:"center",inline:"center",behavior:"smooth"}); }
  },60); return; }
  const s = e.target.closest("[data-set-go]");
  if(s){ showSet(+s.dataset.setGo); go("sets"); }
});

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
    go:()=>{ showSet(i); go("sets"); }}));
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
    MODEL.objects = []; MODEL.tables = []; MODEL.prelude = []; MODEL.preludeAt = [];
  });
  showProject();
  go("editor");
}


function showProject(){
  /* The empty state hangs off `project.open`, which is not part of MODEL and
     therefore has no hook of its own. Opening a file set it open *after* the
     edit() that fills the model, so the repaint inside edit() still saw a
     closed project and nothing repainted afterwards: the ruleset loaded
     correctly and sat behind an overlay that never came down. Every path that
     changes the project ends here, so this is the one place that cannot be
     forgotten by the next one. */
  paintEmpty();
  /* With nothing open the name is empty, which left a folder icon over a gap
     that read as something failing to load. It says what it is instead. */
  const label = project.open ? project.name : t("no project","sin proyecto");
  const nm = $("#proj-name-t");
  if(nm){ nm.textContent = label; nm.classList.toggle("dimmer", !project.open); }
  const tb = $("#tb-proj");
  if(tb) tb.textContent = label;
  /* the table list was hard-coded to "inet fw", which stopped being true the
     moment anyone imported or started fresh. It was also read-only text over
     the one level of nftables nothing here could edit — so each name is the
     way into its properties now, and a parked table says so where it is named. */
  const tables = tableNames(MODEL);
  const tb2 = $("#proj-tables");
  /* with nothing open there is nothing to list, and a lone + beside "no
     project" is an offer to configure a ruleset that does not exist yet */
  if(tb2) tb2.innerHTML = !tables.length ? ""
    : `<span class="dimmer">/</span>`
    + tables.slice(0,2).map(n=>{
        const off = isDormant(MODEL, n);
        return `<button class="tbl-chip${off?" off":""}" data-table="${esc(n)}" title="${esc(off
          ? t(`${n} is dormant — nothing in it is running. Click to edit.`,
              `${n} está dormant — nada de lo que contiene se aplica. Clic para editar.`)
          : t(`${n} — click for its properties`, `${n} — clic para sus propiedades`))}"
          >${esc(n)}${off?`<span class="zz">dormant</span>`:""}</button>`;
      }).join(`<span class="dimmer">·</span>`)
    + (tables.length>2 ? `<span class="dimmer">+${tables.length-2}</span>` : "")
    + `<button class="tbl-chip add" data-table-new title="${esc(
         t("New table","Tabla nueva"))}">+</button>`;

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

  /* the version package.json holds, injected at build time, plus the beta the
     badge and the README both say out loud */
  const av = $("#about-version");
  if(av) av.textContent = `${APP_VERSION} · ${t("beta","beta")}`;

  /* What the branch indicator pretended to say. This one is true. */
  const sv = $("#st-saved-t");
  if(sv) sv.textContent = !project.open ? "—"
    : !project.path      ? t("not saved","sin guardar")
    : undoStack().length   ? t(`${undoStack().length} unsaved`, `${undoStack().length} sin guardar`)
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
  if(undoStack().length){
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
    dev: $("#ch-dev").value.trim(),
    prio: $("#ch-prio").value.trim(),
    comment: $("#ch-comment").value.trim(),
    offload: $("#ch-offload").classList.contains("on"),
    policy: $("#ch-policy").value,
  };
}

/* The two hooks that sit on a device rather than on the machine. */
const ON_DEVICE = h => h === "ingress" || h === "egress";
/* `device "eth0"`, or `devices = { eth0, eth1 }` for more than one */
/* `comment` and `flags offload` are the two chain statements this panel owns.
   Rebuilding the list as "everything else, and then ours" moved them to the
   end of a chain that had written them first — a diff produced by a dialog
   nobody changed anything in. Each keeps the place it had; only one that was
   not there before is appended. */
function chainExtra(was, d){
  const comment = d.comment ? `comment "${d.comment.replace(/"/g, "")}"` : null;
  const out = [];
  let hadComment = false, hadOffload = false;
  for(const l of was){
    if(/^comment\s/.test(l)){
      hadComment = true;
      if(comment) out.push(comment);
      continue;
    }
    if(/^flags\b.*\boffload\b/.test(l)){
      hadOffload = true;
      /* kept verbatim while it is on, so a flag sharing the line survives */
      if(d.offload){ out.push(l); continue; }
      const rest = l.replace(/^flags\s+/, "").split(",")
        .map(x => x.trim()).filter(x => x && x !== "offload");
      if(rest.length) out.push(`flags ${rest.join(",")}`);
      continue;
    }
    out.push(l);
  }
  if(comment && !hadComment) out.push(comment);
  if(d.offload && !hadOffload) out.push("flags offload");
  return out;
}

const deviceClause = dev => {
  const names = dev.split(",").map(x=>x.trim().replace(/^"|"$/g,"")).filter(Boolean);
  if(!names.length) return "";
  return names.length === 1 ? `device "${names[0]}"` : `devices = { ${names.join(", ")} }`;
};

function chSync(){
  const d = chDraft(), base = d.kind === "base";
  $("#ch-base").style.display = base ? "flex" : "none";
  $("#ch-kind-note").textContent = base
    ? t("Attached to a netfilter hook — packets enter it on their own.",
        "Enganchada a un hook de netfilter: los paquetes entran solos.")
    : t("Reached only by jump or goto from another chain.",
        "Solo se alcanza con jump o goto desde otra cadena.");

  const onDev = base && ON_DEVICE(d.hook);
  $("#ch-dev-fld").style.display = onDev ? "" : "none";

  /* what generate.js will write, which is the text when there is one */
  const p = readPriority(d.prio);
  const prio = p.name ?? p.prio;
  const dev = onDev ? deviceClause(d.dev) : "";
  $("#ch-preview").innerHTML = highlight(
    `table ${d.table || "?"} { chain ${d.id || "?"} { ` +
    (base ? `type ${d.type} hook ${d.hook} ${dev ? dev + " " : ""}priority ${prio} ; policy ${d.policy} ; ` : "") + "} }");

  /* nftables allows one chain name per table, nat chains only on the hooks
     that can translate, and an ingress or egress chain only on a device */
  const clash = MODEL.chains.some(c => c.table === d.table && c.id === d.id && UID(c) !== chEditing);
  const badHook = base && d.type === "nat" &&
    !["prerouting","input","output","postrouting"].includes(d.hook);
  const badFamily = onDev && !/^netdev\s/.test(d.table);
  const warn = $("#ch-warn");
  const msg = !d.id || !d.table
    ? t("A chain needs a name and a table.","Una cadena necesita nombre y tabla.")
    : clash ? t(`${d.table} already has a chain called ${d.id}.`,
                `${d.table} ya tiene una cadena llamada ${d.id}.`)
    : badHook ? t("nat chains cannot attach to the forward hook.",
                  "Las cadenas nat no pueden engancharse al hook forward.")
    : badFamily ? t(`The ${d.hook} hook only exists in a netdev table — try "netdev ${d.table.split(" ").pop()}".`,
                    `El hook ${d.hook} solo existe en una tabla netdev — prueba "netdev ${d.table.split(" ").pop()}".`)
    : onDev && !dev ? t(`An ${d.hook} chain has to name the device it attaches to.`,
                        `Una cadena ${d.hook} tiene que nombrar el dispositivo al que se engancha.`)
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
  /* the device clause is held verbatim, so it is unwrapped for the field and
     wrapped again on save */
  $("#ch-dev").value = (ch?.dev || "").replace(/^device\s+/, "")
    .replace(/^devices\s*=\s*\{\s*|\s*\}$/g, "").replace(/"/g, "");
  /* nft prints a priority by name, so every imported chain carries one and
     showing the number instead threw away the text the file has to keep */
  $("#ch-prio").value  = ch?.prioName ?? (ch && ch.prio !== null ? String(ch.prio) : "0");
  $("#ch-policy").value = ch?.policy || "accept";
  /* both live in ch.extra, the verbatim list of chain statements that are not rules */
  /* `comments+` is `comment` followed by one or more `s`, which is a lost
     backslash. The prefix was therefore never stripped: the field showed
     `comment "the front door` — opening quote and all — and saving wrote that
     back inside another comment. Twice through the dialog and it had grown
     two prefixes, on a panel nobody had changed anything in. */
  $("#ch-comment").value = ((ch?.extra||[]).find(l=>/^comment\s/.test(l))||"")
    .replace(/^comment\s+"?|"$/g, "");
  /* `\b` written as an actual backspace character, so this pattern could
     never match anything: the toggle stayed off on every imported chain
     that had the flag, and saving the panel then took `flags offload`
     out of the chain. The switch moved and the rule did not — with
     hardware offload quietly turned off on the way. */
  $("#ch-offload").classList.toggle("on",
    (ch?.extra||[]).some(l=>/^flags\b.*\boffload\b/.test(l)));
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
/* A global handler already flips every .sw-toggle; flipping it again here
   cancelled it out. All this one owes is the preview refresh. */
$("#ch-offload").addEventListener("click", ()=>chSync());

$("#ch-save").addEventListener("click", ()=>{
  const d = chDraft();
  const base = d.kind === "base";
  /* Both halves, or the two disagree: the panel wrote the number and left the
     text alone, so moving an imported chain from `priority filter` to 50 moved
     it on the canvas and changed nothing in the export. Typing a number is how
     the name comes off. */
  const { prio, name: prioName } = readPriority(d.prio);
  /* A name nft keeps for itself is refused here rather than at export. The
     analyser reports it either way, but by then the chain exists, the canvas
     has drawn it, and the file that will not load looks finished. */
  const taken = reservedName(d.id);
  if(taken){
    toast(t(`nftables keeps "${taken}" for itself — no chain can be called that`,
            `nftables se reserva "${taken}" — ninguna cadena puede llamarse así`));
    $("#ch-name").focus();
    return;
  }
  const uid = chEditing;
  edit(uid ? t("edit chain","editar cadena") : t("new chain","cadena nueva"), ()=>{
    const ch = uid ? chainOf(uid) : {rules:[]};
    Object.assign(ch, {
      id:d.id, table:d.table,
      hook: base ? d.hook : null,
      dev: base && ON_DEVICE(d.hook) ? deviceClause(d.dev) : null,
      prio: base ? prio : null,
      prioName: base ? prioName : null,
      type: base ? d.type : "regular",
      policy: base ? d.policy : null,
      /* everything else in extra is kept as it came; only these two are ours */
      extra: chainExtra(ch.extra || [], d),
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

/* ══ TABLES ═════════════════════════════════════════════════════════════
   Tables were the one level of nftables with no editor at all. They were
   discovered from the chains filed under them, which meant an imported
   `flags dormant` round-tripped invisibly: the ruleset was parked and every
   screen here read it as running. */
let tblEditing = null;   /* full name when editing, null when creating */

const tblDraft = () => ({
  family: $("#tbl-family").value,
  name:   $("#tbl-name").value.trim(),
  comment:$("#tbl-comment").value.trim(),
  dormant:$("#tbl-dormant").classList.contains("on"),
});

function tblSync(){
  const d = tblDraft();
  const full = joinTable(d.family, d.name);
  const body = [
    ...(d.dormant ? ["flags dormant"] : []),
    ...(d.comment ? [`comment "${d.comment.replace(/"/g,"")}"`] : []),
  ].join(" ; ");
  $("#tbl-preview").innerHTML = highlight(`table ${full || "?"} { ${body}${body?" ":""}}`);

  $("#tbl-dormant-note").textContent = d.dormant
    ? t("Loaded and not running: nftables unregisters every base chain, so nothing in this table sees a packet.",
        "Cargada y sin aplicarse: nftables desregistra todas sus cadenas base, así que nada de esta tabla ve un paquete.")
    : t("Attached to its hooks — the chains in it filter traffic.",
        "Enganchada a sus hooks: las cadenas que contiene filtran tráfico.");

  /* what it takes with it, which is the whole point of asking before deleting */
  const info = tblEditing ? readTable(MODEL, tblEditing) : null;
  $("#tbl-holds").textContent = info && (info.chains || info.sets || info.objects)
    ? t(`Holds ${info.chains} chain(s), ${info.rules} rule(s), ${info.sets} set(s) and ${info.objects} object(s).`,
        `Contiene ${info.chains} cadena(s), ${info.rules} regla(s), ${info.sets} set(s) y ${info.objects} objeto(s).`)
    : "";

  const clash = full !== tblEditing && tableNames(MODEL).includes(full);
  const msg = !d.name ? t("A table needs a name.","Una tabla necesita un nombre.")
    : /\s/.test(d.name) ? t("A table name is one word.","El nombre de una tabla es una sola palabra.")
    : clash ? t(`${full} already exists.`, `${full} ya existe.`)
    : "";
  const warn = $("#tbl-warn");
  warn.style.display = msg ? "" : "none";
  warn.textContent = msg;
  $("#tbl-save").disabled = !!msg;
}

function openTable(full){
  tblEditing = full && tableNames(MODEL).includes(full) ? full : null;
  const info = tblEditing ? readTable(MODEL, tblEditing) : null;
  $("#tbl-title").textContent = info
    ? t("Table properties","Propiedades de la tabla")
    : t("New table","Tabla nueva");
  $("#tbl-save").textContent = info ? t("Save","Guardar") : t("Create table","Crear tabla");
  $("#tbl-delete").style.display = info ? "" : "none";

  $("#tbl-family").value  = info ? info.family : "inet";
  $("#tbl-name").value    = info ? info.name : "";
  $("#tbl-comment").value = info ? info.comment : "";
  $("#tbl-dormant").classList.toggle("on", !!info?.dormant);

  tblSync();
  $("#scrim-table").classList.add("on");
  if(!info) $("#tbl-name").focus();
}

$("#scrim-table").addEventListener("input", tblSync);
$("#scrim-table").addEventListener("change", tblSync);
/* The global .sw-toggle handler flips it, and it is on the document, so it runs
   after this one — reading the class here would read the state it just left.
   The export dialog waits a turn for the same reason. */
$("#tbl-dormant").addEventListener("click", ()=>setTimeout(tblSync, 0));

$("#tbl-save").addEventListener("click", ()=>{
  const d = tblDraft();
  const full = joinTable(d.family, d.name);
  const was = tblEditing;
  edit(was ? t("edit table","editar tabla") : t("new table","tabla nueva"), ()=>{
    if(was && was !== full) renameTable(MODEL, was, full);
    writeTable(MODEL, full, {dormant:d.dormant, comment:d.comment});
  });
  $("#scrim-table").classList.remove("on");
  toast(was
    ? (d.dormant ? t(`${full} is dormant — nothing in it is running`,
                     `${full} está dormant — nada de lo que contiene se aplica`)
                 : t("Table updated","Tabla actualizada"))
    : t(`Added table ${full}`, `Añadida la tabla ${full}`));
});

$("#tbl-delete").addEventListener("click", async ()=>{
  const full = tblEditing; if(!full) return;
  const info = readTable(MODEL, full);
  const ok = await confirmDialog(
    t(`Delete ${full}?`, `¿Eliminar ${full}?`),
    t(`Its ${info.chains} chain(s), ${info.rules} rule(s), ${info.sets} set(s) and ${info.objects} object(s) go with it. Ctrl+Z undoes this.`,
      `Sus ${info.chains} cadena(s), ${info.rules} regla(s), ${info.sets} set(s) y ${info.objects} objeto(s) se van con ella. Ctrl+Z lo deshace.`),
    t("Delete","Eliminar"));
  if(!ok) return;
  edit(t("delete table","eliminar tabla"), ()=>{ removeTable(MODEL, full); });
  $("#scrim-table").classList.remove("on");
});

/* Two ways in, both of them places that already named the table: the header
   beside the project, and the Tables shelf of the palette. */
document.addEventListener("click", e=>{
  const chip = e.target?.closest?.("[data-table],[data-table-new]");
  if(chip){ openTable(chip.hasAttribute("data-table-new") ? null : chip.dataset.table); return; }
  const row = e.target?.closest?.('.cat[data-kind="TB"] .obj:not(.ph)');
  if(row) openTable($(".nm", row).textContent.trim());
});

/* the header follows the ruleset: chains, rules and tables all live there */
MODEL_HOOKS.push(showProject);
RERENDER.push(showProject);
showProject();

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

