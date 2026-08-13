/* The packet simulator: core/simulate.js, drawn.
 *
 * The trace is evaluated against the same MODEL the code is emitted from, so
 * a verdict here is the verdict the exported ruleset produces. Everything
 * with an opinion about the packet lives in core/simulate.js; this file owns
 * the lane, the trace, the verdict banner, and the form that describes the
 * packet — the parts that shipped broken once while every core test passed,
 * because a parameter named `t` shadowed the translation helper inside a
 * handler whose exception went nowhere.
 *
 * Moved out of app.js as one piece. The only thing it left behind was
 * ifaceNames(), which was never the simulator's: it is a reading of the
 * ruleset, three other screens want it too, and it lives with its kind in
 * core/mentions.js now.
 */
import { MODEL, UID, VNAME, ruleLine } from "../core/model.js";
import { evaluate, PRESETS, packet } from "../core/simulate.js";
import { onModelChange } from "../core/bus.js";
import { ifaceNames } from "../core/mentions.js";
import { t, lang } from "../i18n.js";
import { $, $$, esc, el, cssEsc, highlight, go } from "./shell.js";

/* ── render + animate ── */
const lane = $("#lane"), traceEl = $("#trace"), pkt = $("#pkt"), vb = $("#vb");
function renderLane(res){
  lane.innerHTML = res.steps.map(h=>`
    <div class="hop" data-chain="${esc(UID(h.chain))}" style="${h.depth?`margin-left:${h.depth*22}px`:""}">
      <span class="knob"></span>
      <div class="hop-t">
        <span class="h">${h.chain.hook || (lang() === "es"?"salto":"jump")}</span>
        <span class="c">${esc(h.chain.id)}</span>
        ${h.chain.prio!==null?`<span class="chip">prio ${h.chain.prio}</span>`:""}
        ${h.chain.policy?`<span class="pill ${h.chain.policy==="drop"?"v-drop":"v-accept"}"><span class="sw"></span>policy ${h.chain.policy}</span>`:""}
      </div>
      ${h.evs.map(e=>`
        <div class="ev${e.unsure?" guessed":""}" data-chain="${esc(UID(h.chain))}" data-i="${e.i}"${
          e.unsure ? ` title="${esc(t(
            `Taken as matching. Nothing evaluated ${e.unsure.join(", ")}.`,
            `Se da por coincidente. Nada ha evaluado ${e.unsure.join(", ")}.`))}"` : ""}>
          <span class="g"></span>
          <span class="x">${e.r.expr ? highlight(e.r.expr) : `<span class="c-cm">${t("any packet","cualquier paquete")}</span>`}</span>
          ${e.unsure?`<span class="chip guess">?</span>`:""}
          <span class="pill v-${e.r.verdict}"><span class="sw"></span>${VNAME[e.r.verdict]}</span>
        </div>`).join("")}
      ${h.policy?`<div class="ev" data-policy="1"><span class="g"></span>
        <span class="x"><span class="c-cm">${t("fall through to chain policy","cae a la política de la cadena")}</span></span>
        <span class="pill v-${h.policy}"><span class="sw"></span>${VNAME[h.policy]}</span></div>`:""}
    </div>`).join("");
}

let timers = [];
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

/* Changing the packet no longer runs the trace — reported from the running
   app: "cada vez que cambio un parámetro me dispara la simulación, y no".
   But the verdict on screen describes the packet that was simulated, and the
   form now describes another one — leaving the banner standing unmarked would
   be the worst thing this screen can do: a confident answer to a question
   nobody is asking any more. So the stage says so, dimmed under a bar that
   names the way forward, until Simular (or Enter, or arriving afresh) runs
   the packet the form actually describes. */
function staleSim(){
  stopSim();
  const stage = $(".sim-stage");
  if(!stage || !$("#lane .hop")) return;   /* nothing simulated yet — nothing is stale */
  let bar = $("#sim-stale");
  if(!bar){
    bar = el("div","glass"); bar.id = "sim-stale";
    bar.addEventListener("click", ()=>{ readForm(); runSim(); });
    stage.appendChild(bar);
  }
  bar.innerHTML = `<svg class="ico sm" viewBox="0 0 24 24"><path d="M12 9v4m0 4h.01M10.3 3.9 2.4 17a2 2 0 0 0 1.7 3h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/></svg>
    <span>${t("The packet changed — this trace is the old one. Press Simulate.",
              "El paquete ha cambiado — este trazado es el anterior. Pulsa Simular.")}</span><kbd>↵</kbd>`;
  $("#s-sim")?.classList.add("stale");
}

/* Leaving the screen stops the trace. It used to keep firing its chain of
   timers into a pane nobody was looking at. */
export function stopSim(){
  (timers || []).forEach(clearTimeout);
  timers = [];
  STEP.stop();
}

export function runSim(){
  stopSim();
  $("#s-sim")?.classList.remove("stale");
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
    $$(`.hop[data-chain="${cssEsc(UID(h.chain))}"] .ev`, lane).forEach((node,k)=>{
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
        const hop = $(`.hop[data-chain="${cssEsc(UID(f.h.chain))}"]`, lane);
        hop.classList.add("done");
        $$(".hk").forEach(k=>k.classList.toggle("lit", k.dataset.hook===f.h.chain.hook));
        push("", stamp(), `${t("enter","entra en")} <b>${esc(f.h.chain.table)} / ${esc(f.h.chain.id)}</b>${f.h.chain.hook?` · hook ${f.h.chain.hook} prio ${f.h.chain.prio}`:""}`);
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
      const cvRow = $(`.rule[data-chain="${cssEsc(node.dataset.chain)}"][data-i="${node.dataset.i}"]`);
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
    /* No chain at all is a real answer here: a ruleset that holds none stops
       nothing, and the simulator used to throw on it rather than say so. */
    const ch = res.final.chain;
    const loc = ch
      ? `<code>${esc(ch.table)} / ${esc(ch.id)}</code>`
      : `<code>${esc(t("no chain", "ninguna cadena"))}</code>`;
    /* The verdict is only the verdict your ruleset gives you if everything on
       the way to it was actually evaluated. Where it was not, say so here
       rather than let the banner speak for a guess. */
    const guessed = res.sure ? "" : `
      <div class="vb-guess">
        <svg class="ico sm" viewBox="0 0 24 24"><path d="M12 9v4m0 4h.01M10.3 3.9 2.4 17a2 2 0 0 0 1.7 3h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/></svg>
        <span>${t(
          `Assumed, not evaluated: ${res.unsure.map(u=>`<code>${esc(u)}</code>`).join(", ")}. The packet was taken as matching those, so this verdict is a guess where they are concerned.`,
          `Asumido, no evaluado: ${res.unsure.map(u=>`<code>${esc(u)}</code>`).join(", ")}. El paquete se ha dado por coincidente con eso, así que este veredicto es una suposición en esa parte.`)}</span>
      </div>`;
    /* Chains that were skipped because their table is parked. Without this the
       trace of a dormant ruleset is a short walk to accept with no explanation
       — which is exactly what the kernel does, and exactly what nobody expects
       to be looking at. */
    const parked = (res.parked || []).length ? `
      <div class="vb-guess">
        <svg class="ico sm" viewBox="0 0 24 24"><path d="M12 9v4m0 4h.01M10.3 3.9 2.4 17a2 2 0 0 0 1.7 3h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/></svg>
        <span>${t(
          `Not walked: ${res.parked.map(x=>`<code>${esc(x)}</code>`).join(", ")} ${res.parked.length===1?"is":"are"} dormant, so ${res.parked.length===1?"its":"their"} chains are not registered and no packet enters them.`,
          `Sin recorrer: ${res.parked.map(x=>`<code>${esc(x)}</code>`).join(", ")} ${res.parked.length===1?"está":"están"} dormant, así que sus cadenas no están registradas y ningún paquete entra en ellas.`)}</span>
      </div>` : "";
    $("#vb-why").innerHTML = (!ch
      ? t("This ruleset has no chains, so nothing looks at the packet at all. Import one, or draw a chain on the canvas.",
          "Este ruleset no tiene ninguna cadena, así que nada mira el paquete. Importa uno, o dibuja una cadena en el lienzo.")
      : res.final.policy
      ? t(`No rule in ${loc} matched — the packet fell through to the chain policy.`,
          `Ninguna regla de ${loc} ha coincidido — el paquete cae a la política de la cadena.`)
      : t(`Matched rule ${res.final.i+1} in ${loc}: <code>${esc(ruleLine(res.final.r))}</code>`,
          `Coincide la regla ${res.final.i+1} de ${loc}: <code>${esc(ruleLine(res.final.r))}</code>`))
      + guessed + parked;
    vb.classList.toggle("unsure", !res.sure);
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
export function fillInterfaces(){
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
export function readForm(){
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
  syncForm(); staleSim();
});
$("#sim-flags").addEventListener("click", e=>{
  const b = e.target.closest("[data-flag]"); if(!b) return;
  const f = b.dataset.flag;
  packet.flags = packet.flags.includes(f) ? packet.flags.filter(x=>x!==f) : [...packet.flags, f];
  syncForm(); staleSim();
});
$("#opt-ct").addEventListener("click", ()=>{ packet.tracked = !packet.tracked; syncForm(); staleSim(); });
$("#opt-nat").addEventListener("click", ()=>{ packet.nat = !packet.nat; syncForm(); staleSim(); });
$("#opt-step").addEventListener("click", ()=>{ packet.step = !packet.step; syncForm(); staleSim(); });
$$("#s-sim input[type=text], #s-sim select").forEach(n=>{
  n.addEventListener("change", ()=>{ readForm(); syncForm(); staleSim(); });
});
$(".sim-form .panel-hd .tb").addEventListener("click", ()=>{
  Object.assign(packet, {...PRESETS.ssh}); syncForm(); staleSim();
});

$("#run-sim").addEventListener("click", ()=>{ readForm(); runSim(); });
$$("[data-preset]").forEach(b=>b.addEventListener("click",()=>{
  Object.assign(packet, {...PRESETS[b.dataset.preset], flags:[...PRESETS[b.dataset.preset].flags]});
  $$("[data-preset]").forEach(x=>x.style.cssText="");
  b.style.cssText = "color:var(--aqua);border-color:var(--aqua-line);background:var(--aqua-wash)";
  syncForm(); staleSim();
}));
document.addEventListener("keydown",e=>{
  const onSim = $("#s-sim").classList.contains("on");
  if(e.key==="Enter" && onSim && !e.target?.closest?.("input")) runSim();
  if(e.code==="Space" && onSim && STEP.waiting && !e.target?.closest?.("input,textarea")){
    e.preventDefault(); STEP.next();
  }
  if((e.ctrlKey||e.metaKey) && e.shiftKey && e.key.toLowerCase()==="r"){ e.preventDefault(); go("sim"); runSim(); }
});
fillInterfaces(); syncForm();
onModelChange(fillInterfaces);
