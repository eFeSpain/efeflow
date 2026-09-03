/* The validation screen: core/analyse.js, drawn — and every place its verdict
 * shows up, kept in agreement.
 *
 * Findings are derived from MODEL, never authored. The core relation is
 * subsumption: rule A subsumes rule B when every packet matching B also
 * matches A. If A comes first and terminates, B is dead code. All of that
 * reasoning lives in core/analyse.js; this file owns the list, the grade, the
 * optimiser mirror, and the badges — rail, status bar, dashboard KPIs, and
 * the flags carried back onto the canvas rules — which are one number told in
 * five places, so they are painted by one function.
 *
 * The list itself lives on the bus (`findings.list`), not here: the
 * properties panel names a rule's findings and the palette applies every fix,
 * and neither should have to reach into this screen for them.
 */
import { MODEL, UID } from "../core/model.js";
import { analyse, worstCase, criteria } from "../core/analyse.js";
import { findings, setFindings, onModelChange, onRender } from "../core/bus.js";
import { t } from "../i18n.js";
import { $, $$, esc, cssEsc, toast, highlight, go, select } from "./shell.js";
import { edit } from "./history.js";

let VFILTER = "all";
const SEV = {
  error:{cls:"v-drop",   col:"var(--v-drop)", nm:["error","error"]},
  warn: {cls:"v-warn",   col:"var(--warn)",   nm:["warning","aviso"]},
  hint: {cls:"v-neutral",col:"var(--t4)",     nm:["hint","sugerencia"]},
};
export const tt = p => t(p[0],p[1]);
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

export function renderFindings(){
  setFindings(analyse());
  const FIND = findings.list;
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

  const live = MODEL.chains.flatMap(c=>c.rules.filter(r=>r.on));
  const rules = live.length;
  /* The simulator says which part of a verdict it assumed. This is the same
     admission from the other screen: a rule carrying a match nothing here can
     read is one this list is silent about, and silence that looks like a clean
     bill of health is the thing worth avoiding. */
  const unread = live.filter(r=>criteria(r.expr)._opaque).length;
  $("#val-sub").textContent = t(
    `Checked ${rules} rules across ${MODEL.chains.length} chains · worst case ${worstCase()} evaluations per packet`,
    `${rules} reglas revisadas en ${MODEL.chains.length} cadenas · peor caso ${worstCase()} evaluaciones por paquete`)
    + (unread ? t(` · ${unread} carrying a match this cannot read, and left alone`,
                  ` · ${unread} con una coincidencia que no sabe leer, y no las juzga`) : "");
  $("#val-fixall-t").textContent = fixable
    ? t(`Fix ${fixable} automatically`,`Corregir ${fixable} automáticamente`)
    : t("Nothing to fix","Nada que corregir");
  /* its label came only from paintApplyForm, so until the dialog had been
     opened once the button on this screen read as an em dash */
  $("#val-apply-t").textContent = t("Apply…","Aplicar…");
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
        <span class="ttl"><div class="h">${esc(tt(f.title))}</div><div class="l">${esc(f.where)} · ${f.kind}</div></span>
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
        <h4>${esc(tt(f.title))}</h4>
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
  /* the button beside it read "Syntax valid" in green as literal text,
     whatever the linter had found — it reports the syntax findings now */
  const syn = FIND.filter(f=>f.kind==="syntax").length;
  const ss = $("#st-syntax");
  if(ss){
    ss.querySelector(".sw").style.background = syn ? "var(--v-drop)" : "var(--v-accept)";
    $("#st-syntax-t").textContent = syn
      ? t(`${syn} syntax error${syn===1?"":"s"}`, `${syn} error${syn===1?"":"es"} de sintaxis`)
      : t("Syntax valid","Sintaxis válida");
  }
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
    const row = $(`.rule[data-chain="${cssEsc(UID(f.chain))}"][data-i="${f.i}"]`);
    if(row) row.classList.add(f.sev==="error"?"err":"warn");
  });
}
export const findingsFor = (uid,i) => findings.list.filter(f=>f.chain && UID(f.chain)===uid && f.i===i);

/* ── interactions ── */
document.addEventListener("click",e=>{
  const tab = e.target.closest("[data-vf]");
  if(tab){ VFILTER = tab.dataset.vf; renderFindings(); return; }

  const fx = e.target.closest("[data-fix]");
  if(fx){
    const f = findings.list[+fx.dataset.fix];
    edit(tt(f.fix.label).toLowerCase(), f.fix.run);
    toast(t("Applied — Ctrl+Z to undo","Aplicado — Ctrl+Z para deshacer"));
    return;
  }
  const gt = e.target.closest("[data-goto]");
  if(gt){
    const f = findings.list[+gt.dataset.goto];
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
export const applyAll = ()=>{
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

onModelChange(renderFindings);
onRender(renderFindings);
