/* How a ruleset gets in and out: the import dialog, the export dialog, and
 * the project file.
 *
 * Three doors on one wall. Import parses `nft list ruleset` output and proves
 * the round-trip line by line before anything replaces the user's work;
 * export is the same model leaving in four shapes; save/open is the project
 * file that carries what the ruleset alone does not — the name, and the
 * interfaces and networks kept by hand.
 *
 * The two project-lifecycle calls this cannot make itself — openProject and
 * showProject, which own the no-project state and the titlebar — stay in the
 * composition root and arrive through provideProject(), the same late-binding
 * arrangement shell.js uses for select and openCtx.
 */
import { MODEL, ruleLine } from "../core/model.js";
import { generate } from "../core/generate.js";
import { verify } from "../core/parse.js";
import { worstCase } from "../core/analyse.js";
import { SAMPLES, sampleById } from "../core/samples.js";
import { PROJECT, serialise, deserialise, setProject } from "../core/project.js";
import { onRender } from "../core/bus.js";
import { t, onLangChange } from "../i18n.js";
import { asTauriTarget, describe } from "../target.js";
import * as native from "../native.js";
import { $, $$, esc, el, toast, go } from "./shell.js";
import { edit } from "./history.js";
import { resetView } from "./canvas.js";
import { REACH, reaching } from "./host.js";

const hooks = { openProject(){}, showProject(){} };
export const provideProject = (h) => Object.assign(hooks, h);

/* ══ IMPORT ═════════════════════════════════════════════════════════════
   Parses `nft list ruleset` output. The expression is kept verbatim minus
   the counter and comment, which is what makes a byte-faithful round-trip
   possible — we re-emit what we were given, not our idea of it.         */

/* ══ IMPORT UI ═════════════════════════════════════════════════════════
   The rulesets on offer live in core/samples.js, where the tests can hold
   them to the same round-trip they promise the user.                     */

let IMPORTED = null;
export function reviewImport(){
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
      ${p.prelude.length?`<div class="imp-stat"><span class="k" title="${esc(t(
        "The define and include lines above the first table, written back above it.",
        "Las líneas define e include de encima de la primera tabla, reescritas encima de ella."))}"
        >${t("Definitions kept","Definiciones conservadas")}</span><span class="v">${p.prelude.length}</span></div>`:""}
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
    MODEL.prelude = p.prelude;
    MODEL.preludeAt = p.preludeAt || [];
  });
  hooks.openProject();
  $$(".scrim").forEach(s=>s.classList.remove("on"));
  go("editor");
  requestAnimationFrame(()=>requestAnimationFrame(resetView));
  toast(rt.diffs.length
    ? t(`Imported · ${rt.ok}/${rt.total} lines verified`, `Importado · ${rt.ok}/${rt.total} líneas verificadas`)
    : t(`Imported · all ${rt.total} lines verified`, `Importado · las ${rt.total} líneas verificadas`));
});

/* the toolbar Open button and the dashboard button both land here */
$$('[data-go="open"]').forEach(b=> b.dataset.go = "import");
/* what go("import") does — the navigator owns the routing, this owns the scrim */
export function openImport(){
  $("#scrim-import").classList.add("on"); reviewImport(); $("#imp-text").focus();
}
reviewImport();
onRender(reviewImport);


/* ────────── */
/* ══ EXPORT ════════════════════════════════════════════════════════════ */
function download(name, text, mime){
  const url = URL.createObjectURL(new Blob([text], {type:mime||"text/plain;charset=utf-8"}));
  const a = el("a"); a.href = url; a.download = name;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(()=>URL.revokeObjectURL(url), 2000);
}

/* The toggles are found by name rather than by position: the flush one used to
   be first, and everything after it was read by index. */
const exOn = id => !!$("#" + id)?.classList.contains("on");
const exScope = () => $("#ex-scope .on")?.dataset.scope || "tables";

function exportPayload(){
  const fmt = $$("#scrim-export .choice").findIndex(c=>c.classList.contains("on"));
  let lines = generate(MODEL, {scope: exScope()}).slice();
  if(!exOn("ex-comments")) lines = lines.map(l=>l.replace(/\s*comment "(?:[^"\\]|\\.)*"/,""));

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

export function refreshExportStats(){
  const p = exportPayload();
  const tables = [...new Set(MODEL.chains.map(c=>c.table))];
  $("#ex-scope-note").textContent = exScope()==="tables"
    ? t(`Replaces ${tables.join(", ")}. Anything else on the host is left alone.`,
        `Reemplaza ${tables.join(", ")}. Cualquier otra cosa de la máquina se queda como está.`)
    : t("flush ruleset: empties the kernel first, deleting anything eFeFlow did not write.",
        "flush ruleset: vacía el kernel primero, borrando todo lo que no haya escrito eFeFlow.");
  const rules = MODEL.chains.reduce((a,c)=>a+c.rules.filter(r=>r.on).length,0);
  const cards = $$("#scrim-export .card .num");
  if(cards.length===4){
    cards[0].textContent = p.text.split("\n").length;
    cards[1].textContent = rules;
    cards[2].textContent = MODEL.sets.length;
    cards[3].textContent = worstCase();
  }
}
/* The last toggle was read by nothing at all. `nft -c` is the authority on
   whether a ruleset loads, and running it before writing the file is the whole
   point of having a host configured — so when one is reachable and the toggle
   is on, the export waits for its answer. */
async function exportChecked(){
  const p = exportPayload();
  const wanted = exOn("ex-check");
  /* only the nft formats are something nft can be asked about */
  const nftSource = /\.nft$/.test(p.name);
  if(wanted && nftSource && REACH?.ok){
    const r = await reaching(
      t(`checking on ${describe()}…`, `comprobando en ${describe()}…`),
      ()=> native.nftCheck(p.text, asTauriTarget()));
    if(!r.ok){
      toast(t(`nft -c refused it on ${describe()} — nothing was written`,
              `nft -c lo rechazó en ${describe()} — no se ha escrito nada`));
      const box = $("#val-nft-out");
      if(box){ box.style.display = ""; box.className = "nft-out bad"; box.textContent = (r.stderr||r.stdout).trim(); }
      go("validate");
      return;
    }
  }
  download(p.name, p.text, p.mime);
  toast(t("Exported ","Exportado ")+p.name);
}

$("#scrim-export").addEventListener("click", e=>{
  const sc = e.target.closest("#ex-scope [data-scope]");
  if(sc){ $$("#ex-scope [data-scope]").forEach(x=>x.classList.toggle("on", x===sc)); refreshExportStats(); return; }
  if(e.target.closest(".choice, .sw-toggle")) setTimeout(refreshExportStats, 0);
  const btns = $$("#scrim-export .modal-ft .tb");
  if(e.target.closest(".modal-ft .tb.pri")){
    exportChecked();
  } else if(e.target===btns[1] || (btns[1] && btns[1].contains(e.target))){
    const p = exportPayload();
    navigator.clipboard?.writeText(p.text);
    toast(t("Ruleset copied to clipboard","Ruleset copiado al portapapeles"));
  }
});
/* the code drawer's copy button */
$$(".dw-hd .tb.icon")[0]?.addEventListener("click", ()=>{
  /* with the newline nft needs at the end, because what this is for is pasting
     it into a file and running it */
  navigator.clipboard?.writeText(generate().join("\n") + "\n");
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
  hooks.showProject();
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
          MODEL.objects = o.objects; MODEL.tables = o.tables; MODEL.prelude = o.prelude;
          MODEL.preludeAt = o.preludeAt || [];
        });
        /* the name and the scratch lists are part of the project, not the
           ruleset, so they sit outside the undo snapshot */
        setProject({open:true, name:o.name, scratch:o.scratch, origin:f.name, dirty:false});
        hooks.showProject();
        /* Import is a scrim, not a screen, so go() changes what is underneath
           and leaves the overlay standing — with its Import button disabled,
           because the textarea it watches is still empty. The only way out was
           the close cross. Same two lines the Import button itself runs. */
        $$(".scrim").forEach(s=>s.classList.remove("on"));
        go("editor"); requestAnimationFrame(()=>requestAnimationFrame(resetView));
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

