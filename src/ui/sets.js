/* Sets, maps and named objects — the things a rule points at.
 *
 * A set is not a rule and does not live on the canvas, so it had a screen of
 * its own from the start; it simply did not have a file. Four hundred and
 * ninety-six lines of app.js, needing four names from the rest of it and
 * giving back none, which made it the second thing to move out.
 *
 * What it asks the application to do rather than doing itself — go to a
 * screen, put the cursor on a rule, open and close the context menu — it asks
 * through the shell. The canvas and the properties panel are what actually do
 * those, and this file has no business knowing that.
 */
import { MODEL, UID, ruleLine, VCOLOR } from "../core/model.js";
import { OBJECT_FIELDS, OBJECT_TEMPLATE, OBJECT_KINDS,
         readObject, editObject, refsToObject, escapeRe } from "../core/objects.js";
import { reservedName } from "../core/lint.js";
import { t } from "../i18n.js";
import { $, $$, esc, el, toast, go, select, openCtx, killCtx, highlight } from "./shell.js";
import { edit } from "./history.js";
/* Which row of the list is open. The dashboard and the command palette both
   jump straight to one, so they set it before coming here. */
export let SETSEL = 0;
export const showSet = (i) => { SETSEL = i; };

/* ══ SET MANAGER ════════════════════════════════════════════════════════
   References are counted by scanning live rule expressions, so a set the
   ruleset stopped using reports zero the moment you delete the last rule. */
SETSEL = 0;
/* `@blocklist` must not match inside `@blocklist_v6`, and a name is table-scoped
   — so the reference is a whole word (`\b` after it fails against a following
   word char like `_`) and, when a table is given, only that table's rules count.
   A substring scan mangled both on rename and inflated the delete guard. */
const refWord = name => "@" + escapeRe(name) + "\\b";

/* The first `prefix_N` no set or object in this table already holds. Numbering
   by count reused a live name after a create/delete/create, and nft refuses a
   duplicate on load. */
function freshName(prefix, table){
  const taken = new Set([...MODEL.sets, ...MODEL.objects]
    .filter(x => x.table === table).map(x => x.n ?? x.name));
  let k = 1; while(taken.has(`${prefix}_${k}`)) k++;
  return `${prefix}_${k}`;
}
export function refsTo(name, table){
  const re = new RegExp(refWord(name));
  const out = [];
  MODEL.chains.forEach(ch=>{
    if(table && ch.table !== table) return;
    ch.rules.forEach((r,i)=>{ if(r.on && re.test(r.expr||"")) out.push({ch, r, i}); });
  });
  return out;
}
/* A map's type reads `ipv4_addr : inet_service`. Held as one string it is
   faithful and uneditable, so the editor splits it and puts it back. */
const splitMapType = s => {
  if(s.kind !== "map") return [s.t, ""];
  const i = s.t.indexOf(":");
  return i < 0 ? [s.t.trim(), ""] : [s.t.slice(0, i).trim(), s.t.slice(i + 1).trim()];
};
const joinMapType = (key, value) => (value ? `${key} : ${value}` : key);

/* A list to choose from is only right when the thing is a name from that list.
   `typeof` takes an expression, and a concatenation is two types joined by a
   dot — neither is in any list, and both are text. */
const typeControl = (id, value, list, decl) =>
  decl === "typeof" || value.includes(".")
    ? `<input type="text" id="${id}" value="${esc(value)}" spellcheck="false"
         placeholder="${decl === "typeof" ? "ip saddr . tcp dport" : "ipv4_addr . inet_service"}">`
    : `<select id="${id}">${list.map(x =>
        `<option${x===value?" selected":""}>${x}</option>`).join("")}
        ${list.includes(value)||!value?"":`<option selected>${esc(value)}</option>`}</select>`;

/* the declaration as nft would print it, which is what the preview shows */
const setDecl = s => {
  const body = [`${s.decl || "type"} ${s.t}`];
  if(s.f) body.push(`flags ${s.f}`);
  for(const [k, v] of Object.entries(s.attr || {}))
    if(v) body.push(k === "auto-merge" ? "auto-merge" : `${k} ${v}`);
  if(s.el.length) body.push("elements = { … }");
  return `${s.kind === "map" ? "map" : "set"} ${s.n} { ${body.join(" ; ")} }`;
};

const setIcon = s => s.kind==="map"
  ? "M5 8h6l3 4h5M5 16h6"
  : (s.f||"").includes("timeout") ? "M12 8v8m-4-4h8" : "M4 7h16M4 12h16M4 17h9";

/* The editor for a flowtable, a counter, a quota, a ct helper — and for a kind
   nobody here has heard of.
 *
 * Same split as the rule editor: fields for what people change, the source
 * underneath for everything else. A `ct timeout` gets no fields and is still
 * editable, which is the whole reason the body is the thing being kept rather
 * than a parse of it. */
const OBJ_LABEL = {
  hook: () => "hook", priority: () => t("priority","prioridad"),
  devices: () => t("devices","dispositivos"),
  packets: () => t("packets","paquetes"), bytes: () => "bytes",
  mode: () => t("mode","modo"), amount: () => t("amount","cantidad"),
  unit: () => t("unit","unidad"),
  type: () => t("helper","helper"), protocol: () => t("protocol","protocolo"),
};
const OBJ_CHOICES = {
  hook: ["ingress","egress","prerouting","input","forward","output","postrouting"],
  mode: ["over","until"],
  unit: ["bytes","kbytes","mbytes"],
  protocol: ["tcp","udp","sctp","dccp"],
};

function renderObjectEditor(o, main, refs){
  const f = readObject(o);
  const fields = OBJECT_FIELDS[o.kind] || [];
  const rs = refsToObject(o, MODEL.chains);
  $("#ref-count").textContent = rs.length;

  const field = k => OBJ_CHOICES[k]
    ? `<label class="fld"><span class="lbl">${OBJ_LABEL[k]()}</span>
         <select id="obj-${k}">${OBJ_CHOICES[k].map(x=>
           `<option${x===f[k]?" selected":""}>${x}</option>`).join("")}
           ${OBJ_CHOICES[k].includes(f[k])||!f[k]?"":`<option selected>${esc(f[k])}</option>`}</select></label>`
    : `<label class="fld"><span class="lbl">${OBJ_LABEL[k]()}</span>
         <input type="text" id="obj-${k}" value="${esc(f[k])}" spellcheck="false"
           ${k==="devices"?'list="dl-ifaces" placeholder="eth0, eth1"':""}></label>`;

  main.innerHTML = `
    <div class="set-hero">
      <div class="r1">
        <input class="set-name" id="obj-name" value="${esc(o.name)}" spellcheck="false">
        <span class="pill v-aqua"><span class="sw"></span>${esc(o.kind)}</span>
        <div style="flex:1"></div>
        <button class="tb" id="obj-del" style="color:var(--v-drop)"
          ${rs.length?`disabled title="${esc(t(`Referenced by ${rs.length} rules`,`Referenciado por ${rs.length} reglas`))}"`:""}>
          <svg class="ico" viewBox="0 0 24 24"><path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/></svg>${t("Delete","Eliminar")}</button>
      </div>
      ${fields.length?`<div class="set-props">${fields.map(field).join("")}</div>`:""}
      <div class="decl">${highlight(`${o.kind} ${o.name} { ${o.body.join(" ; ")} }`)}</div>
    </div>
    <div class="elem-toolbar">
      <span class="lbl" style="flex:1">${t("Source","Código")} · ${
        rs.length ? t(`referenced by ${rs.length} rule${rs.length===1?"":"s"}`,`referenciado por ${rs.length} regla${rs.length===1?"":"s"}`)
                  : `<span style="color:var(--warn)">${t("never referenced","nunca referenciado")}</span>`}</span>
    </div>
    <div style="padding:12px 16px">
      <!-- the body as it will be written out. A kind with no fields above is
           edited entirely here, which is why it is not tucked away. -->
      <textarea id="obj-body" spellcheck="false" rows="${Math.max(4, o.body.length+1)}"
        style="width:100%;font:450 12px/1.7 var(--mono);color:var(--t1);background:var(--sunken);
               border:1px solid var(--line);border-radius:var(--r-sm);padding:9px 11px;resize:vertical"
        >${esc(o.body.join("\n"))}</textarea>
      <div id="obj-warn" style="margin-top:8px"></div>
    </div>`;

  refs.innerHTML = rs.length ? rs.map(({ch,r,i})=>`
    <div class="ref" data-ref="${esc(UID(ch))}:${i}">
      <div class="loc"><span style="color:var(--${VCOLOR[r.verdict]||"--t3"})">◆</span>${esc(ch.table)} / ${esc(ch.id)} · ${t("rule","regla")} ${i+1}</div>
      <div class="ex">${highlight(ruleLine(r))}</div>
    </div>`).join("") : `
    <div style="padding:32px 18px;text-align:center;font-size:11.5px;color:var(--t4);line-height:1.6">
      ${t(`No rule names this ${o.kind}. It is loaded into the kernel on every reload for nothing.`,
           `Ninguna regla nombra este ${o.kind}. Se carga en el kernel en cada recarga para nada.`)}</div>`;

  objWarn(o);
}

/* A flowtable with no device is the one template that ships incomplete, on
   purpose — naming a device the user does not have is the thing the palette
   was cleaned of. Say it rather than emit a ruleset nft refuses. */
function objWarn(o){
  const box = $("#obj-warn");
  if(!box) return;
  const f = readObject(o);
  const msg = o.kind === "flowtable" && !f.devices
    ? t("A flowtable has to name at least one device, or nft will not take it.",
        "Un flowtable tiene que nombrar al menos un dispositivo, o nft no lo acepta.")
    : !o.name
      ? t("This object has no name, so no rule can reach it.",
          "Este objeto no tiene nombre, así que ninguna regla puede alcanzarlo.")
      : "";
  box.innerHTML = msg
    ? `<div class="raw-lint"><svg class="ico sm" viewBox="0 0 24 24"><path d="M12 9v4m0 4h.01M10.3 3.9 2.4 17a2 2 0 0 0 1.7 3h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/></svg><span>${esc(msg)}</span></div>`
    : "";
}

/* The list is everything the table holds that is not a chain. Sets first, so
   an index into MODEL.sets is still an index into this — the code that jumps
   here from a rule or a finding keeps working unchanged. */
const nSets = () => MODEL.sets.length;
const curSet = () => (SETSEL < nSets() ? MODEL.sets[SETSEL] : null);
const curObj = () => (SETSEL >= nSets() ? MODEL.objects[SETSEL - nSets()] : null);

export function renderSets(){
  const total = nSets() + MODEL.objects.length;
  if(SETSEL >= total) SETSEL = Math.max(0, total-1);
  const list = $("#set-list");
  $("#set-count").textContent = total;

  const setRows = MODEL.sets.map((s,i)=>{
    const n = refsTo(s.n, s.table).length;
    return `<div class="set-item${i===SETSEL?" on":""}${n?"":" warnish"}" data-si="${i}">
      <div class="ic"><svg class="ico sm" viewBox="0 0 24 24"><path d="${setIcon(s)}"/>${
        (s.f||"").includes("timeout")?'<circle cx="12" cy="12" r="9"/>':""}</svg></div>
      <div><div class="nm">@${esc(s.n)}</div>
        <div class="ty">${esc(s.t)}${s.f?" · "+esc(s.f):""}${n?"":" · "+t("unused","sin usar")}</div></div>
      <div class="ct">${s.el.length>999?(s.el.length/1000).toFixed(1)+"k":s.el.length}</div>
    </div>`;
  });
  const objRows = MODEL.objects.map((o,k)=>{
    const i = nSets()+k, n = refsToObject(o, MODEL.chains).length;
    return `<div class="set-item${i===SETSEL?" on":""}${n?"":" warnish"}" data-si="${i}">
      <div class="ic"><svg class="ico sm" viewBox="0 0 24 24"><path d="M12 3 4 7v10l8 4 8-4V7z"/><path d="M4 7l8 4 8-4"/></svg></div>
      <div><div class="nm">${esc(o.name || o.kind)}</div>
        <div class="ty">${esc(o.kind)}${n?"":" · "+t("unused","sin usar")}</div></div>
      <div class="ct">${o.body.length}</div>
    </div>`;
  });

  list.innerHTML = total ? setRows.concat(objRows).join("")
    : `<div style="padding:34px 18px;text-align:center;font-size:12px;color:var(--t4);line-height:1.6">
        ${t("Nothing in this table but chains.","Esta tabla no tiene más que cadenas.")}</div>`;

  const main = $("#set-main"), refs = $("#set-refs");
  const o = curObj();
  if(o) return renderObjectEditor(o, main, refs);

  const s = curSet();
  if(!s){
    main.innerHTML = `<div class="empty-props" style="height:100%">
      <div class="art"><svg viewBox="0 0 24 24" style="width:28px;height:28px;stroke:currentColor;fill:none;stroke-width:1.4"><path d="M4 7h16M4 12h16M4 17h9"/></svg></div>
      <h4>${t("Nothing selected","Nada seleccionado")}</h4>
      <p>${t("Sets turn repeated rules into one hash lookup. Flowtables, counters and ct helpers live here too.",
              "Los sets convierten reglas repetidas en una sola consulta hash. Los flowtables, counters y helpers de ct también viven aquí.")}</p></div>`;
    refs.innerHTML = ""; $("#ref-count").textContent = "0";
    return;
  }

  const rs = refsTo(s.n, s.table);
  $("#ref-count").textContent = rs.length;
  /* A set's name, type and flags are as editable as its contents. They were
     read-only, which made a set you had just created impossible to correct. */
  const FLAGS = ["interval","timeout","constant","dynamic"];
  const TYPES = ["ipv4_addr","ipv6_addr","inet_service","ether_addr","inet_proto","ifname","mark"];
  /* A map's type is `key : value`, and the value side takes what a set's key
     side does plus the verdicts — which is what makes a verdict map. */
  const MAP_VALUES = [...TYPES, "verdict"];
  const ATTR_HINT = {timeout:"1h", "gc-interval":"10s", size:"65536"};
  const [keyT, valT] = splitMapType(s);
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
      <!-- The keyword decides whether what follows is a name or an expression,
           so it has to be something you can set. A set declared with typeof
           used to show its whole expression as an extra entry in a list of
           scalar type names, and picking any of them left "typeof ipv4_addr"
           behind — which nft rejects. An editor may not damage what it has no
           way of representing. -->
      <div class="fld" style="max-width:190px"><span class="lbl">${t("declared as","declarado como")}</span>
        <div class="seg" id="set-decl">
          <button data-decl="type"${(s.decl||"type")==="type"?' class="on"':""}>type</button>
          <button data-decl="typeof"${s.decl==="typeof"?' class="on"':""}>typeof</button>
        </div></div>
      <div class="set-props">
        <label class="fld"><span class="lbl">${s.kind==="map"?t("key type","tipo de clave"):"type"}</span>
          ${typeControl("set-type", keyT, TYPES, s.decl)}</label>
        ${s.kind==="map"?`
        <label class="fld"><span class="lbl">${t("value type","tipo de valor")}</span>
          ${typeControl("set-vtype", valT, MAP_VALUES, s.decl)}</label>`:""}
        <div class="fld"><span class="lbl">flags</span>
          <div class="preset" id="set-flags">${FLAGS.map(f=>
            `<button data-flag="${f}"${(s.f||"").includes(f)?' class="on"':""}>${f}</button>`).join("")}</div></div>
      </div>
      <!-- size, timeout, gc-interval, policy and auto-merge were read from an
           imported set and written back out untouched, but there was no way to
           change one or to give a set you had just made a timeout. -->
      <div class="set-props">
        ${["timeout","gc-interval","size"].map(k=>`
        <label class="fld"><span class="lbl">${k}</span>
          <input type="text" id="set-a-${k}" value="${esc(s.attr?.[k] ?? "")}"
                 placeholder="${esc(ATTR_HINT[k])}" spellcheck="false"></label>`).join("")}
        <label class="fld"><span class="lbl">policy</span>
          <select id="set-a-policy">${["","performance","memory"].map(x=>
            `<option${x===(s.attr?.policy ?? "")?" selected":""}>${x}</option>`).join("")}</select></label>
        <div class="fld"><span class="lbl">auto-merge</span>
          <div class="preset"><button id="set-a-automerge"${s.attr?.["auto-merge"]?' class="on"':""}>auto-merge</button></div></div>
      </div>
      <div class="decl">${highlight(setDecl(s))}</div>
    </div>
    <div class="elem-toolbar">
      <span class="lbl" style="flex:1">${s.el.length} ${t("elements","elementos")} · ${
        rs.length ? t(`referenced by ${rs.length} rule${rs.length===1?"":"s"}`,`referenciado por ${rs.length} regla${rs.length===1?"":"s"}`)
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
    <div class="ref" data-ref="${esc(UID(ch))}:${i}">
      <div class="loc"><span style="color:var(--${VCOLOR[r.verdict]||"--t3"})">◆</span>${esc(ch.table)} / ${esc(ch.id)} · ${t("rule","regla")} ${i+1}</div>
      <div class="ex">${highlight(ruleLine(r)).replace(new RegExp(refWord(s.n),"g"),`<mark>@${esc(s.n)}</mark>`)}</div>
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
    const s = curSet(); if(!s) return;
    const i = +rm.dataset.el;
    edit(t("remove set element","quitar elemento del set"), ()=>{ s.el.splice(i,1); });
    return;
  }
  const fl = e.target.closest("#set-flags [data-flag]");
  if(fl){
    const s = curSet(); if(!s) return;
    const f = fl.dataset.flag;
    const have = (s.f||"").split(",").map(x=>x.trim()).filter(Boolean);
    const next = have.includes(f) ? have.filter(x=>x!==f) : [...have, f];
    edit(t("set flags","flags del set"), ()=>{ s.f = next.join(", "); });
    return;
  }
  const dc = e.target.closest("#set-decl [data-decl]");
  if(dc){
    const s = curSet(); if(!s) return;
    /* switching the keyword changes what the value means, not the value: what
       was there stays there until you change it */
    edit(t("set declaration","declaración del set"), ()=>{ s.decl = dc.dataset.decl; });
    return;
  }
  if(e.target.closest("#set-a-automerge")){
    const s = curSet(); if(!s) return;
    edit(t("auto-merge","auto-merge"), ()=>{
      s.attr = {...s.attr, "auto-merge": !s.attr?.["auto-merge"]};
    });
    return;
  }
  if(e.target.closest("#set-del")){
    const s = curSet(); if(!s) return;
    if(refsTo(s.n, s.table).length){
      toast(t(`@${s.n} is still used by ${refsTo(s.n, s.table).length} rules`,
              `@${s.n} lo usan todavía ${refsTo(s.n, s.table).length} reglas`));
      return;
    }
    edit(t("delete set","eliminar set"), ()=>{ MODEL.sets.splice(SETSEL,1); });
    SETSEL = Math.max(0, SETSEL-1);
    renderSets();
    return;
  }
  /* A map could be imported, listed and referenced, and not made: this button
     produced a set whatever you meant. Maps are how a ruleset says "this port
     goes to that host" or "this source gets that verdict", so not being able
     to write one left a whole shape of ruleset out of reach. */
  const nw = e.target.closest("#set-new, #map-new");
  if(nw){
    const map = nw.id === "map-new";
    const kind = map ? "map" : "set";
    const table = MODEL.chains[0]?.table || "inet fw";
    const n = freshName(`new_${kind}`, table);
    edit(t(`new ${kind}`, `${kind} nuevo`), ()=>{
      MODEL.sets.push({
        n, kind, table,
        t: map ? "ipv4_addr : inet_service" : "ipv4_addr",
        f: map ? "" : "interval", el: [], attr: {},
      });
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
  const s = curSet(); if(!s) return;
  edit(t("add set element","añadir elemento al set"), ()=>{ s.el.push(v); });
});

/* ── editing an object in place ──────────────────────────────────────── */
document.addEventListener("click", e=>{
  /* the kinds this knows how to start you off with; anything else you get by
     importing it, and can then edit like the rest */
  if(e.target.closest("#obj-new")){
    const b = e.target.closest("#obj-new").getBoundingClientRect();
    const m = openCtx(b.left, b.bottom + 4, OBJECT_KINDS.map(k =>
      [k, k, "M12 3 4 7v10l8 4 8-4V7z"]));
    m.addEventListener("click", ev=>{
      const a = ev.target.closest("[data-act]"); if(!a) return;
      const kind = a.dataset.act;
      const table = MODEL.chains[0]?.table || "inet fw";
      const n = freshName(`new_${kind.replace(/\W+/g,"_")}`, table);
      edit(t(`new ${kind}`, `${kind} nuevo`), ()=>{
        MODEL.objects.push({ table, kind, name: n, body: [...(OBJECT_TEMPLATE[kind]||[])] });
      });
      SETSEL = nSets() + MODEL.objects.length - 1;
      killCtx(); renderSets();
    });
    return;
  }
  if(e.target.closest("#obj-del")){
    const o = curObj(); if(!o) return;
    const rs = refsToObject(o, MODEL.chains);
    if(rs.length){
      toast(t(`${o.name} is still named by ${rs.length} rules`,
              `${o.name} lo nombran todavía ${rs.length} reglas`));
      return;
    }
    const k = MODEL.objects.indexOf(o);
    edit(t(`delete ${o.kind}`, `eliminar ${o.kind}`), ()=>{ MODEL.objects.splice(k,1); });
    SETSEL = Math.max(0, SETSEL-1);
    renderSets();
  }
});

document.addEventListener("change", e=>{
  const o = curObj();
  if(!o || !e.target.id?.startsWith("obj-")) return;
  const key = e.target.id.slice(4);

  if(key === "name"){
    const next = e.target.value.trim();
    if(!next || next === o.name){ renderSets(); return; }
    const was = o.name, hits = refsToObject(o, MODEL.chains).length;
    /* the same promise the set editor makes: rename it and the rules follow */
    edit(t(`rename ${o.kind}`, `renombrar ${o.kind}`), ()=>{
      o.name = next;
      const atRe = new RegExp(refWord(was), "g");
      MODEL.chains.forEach(ch=>{ if(ch.table !== o.table) return;
        ch.rules.forEach(r=>{
          r.expr = r.expr.replace(atRe, `@${next}`).split(`"${was}"`).join(`"${next}"`);
        });
      });
    });
    toast(hits ? t(`Renamed, and ${hits} rules updated`, `Renombrado, y ${hits} reglas actualizadas`)
               : t("Renamed","Renombrado"));
    return;
  }

  if(key === "body"){
    const body = e.target.value.split("\n").map(l=>l.trim()).filter(Boolean);
    edit(t(`edit ${o.kind}`, `editar ${o.kind}`), ()=>{ o.body = body; });
    return;
  }

  if((OBJECT_FIELDS[o.kind] || []).includes(key)){
    const v = e.target.value.trim();
    edit(t(`edit ${o.kind}`, `editar ${o.kind}`), ()=>{ o.body = editObject(o, {[key]: v}); });
  }
});

/* ── editing a set in place ──────────────────────────────────────────── */
document.addEventListener("change", e=>{
  const s = curSet();
  if(!s) return;

  /* a map's type is `key : value`, and both halves are edited separately */
  if(e.target.id === "set-type" || e.target.id === "set-vtype"){
    const [keyT, valT] = splitMapType(s);
    const next = e.target.id === "set-type"
      ? joinMapType(e.target.value, valT)
      : joinMapType(keyT, e.target.value);
    edit(t("set type","tipo del set"), ()=>{ s.t = next; });
    return;
  }
  if(e.target.id.startsWith("set-a-")){
    const key = e.target.id.slice(6);
    const v = e.target.value.trim();
    edit(t(`set ${key}`, `${key} del set`), ()=>{
      s.attr = {...s.attr};
      if(v) s.attr[key] = v; else delete s.attr[key];
    });
    return;
  }
  if(e.target.id === "set-name"){
    const next = e.target.value.trim().replace(/^@/, "");
    if(!next || next === s.n){ renderSets(); return; }
    if(MODEL.sets.some(x=>x!==s && x.n===next)){
      toast(t(`A set called ${next} already exists`, `Ya existe un set llamado ${next}`));
      renderSets(); return;
    }
    const taken = reservedName(next);
    if(taken){
      toast(t(`nftables keeps "${taken}" for itself — no set can be called that`,
              `nftables se reserva "${taken}" — ningún set puede llamarse así`));
      renderSets(); return;
    }
    /* rename the references too, or the rules would point at nothing */
    const was = s.n, hits = refsTo(was, s.table).length;
    const re = new RegExp(refWord(was), "g");
    edit(t("rename set","renombrar set"), ()=>{
      s.n = next;
      MODEL.chains.forEach(ch=>{
        if(ch.table !== s.table) return;
        ch.rules.forEach(r=>{ r.expr = r.expr.replace(re, "@"+next); });
      });
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
  const hits = new Set(refsTo(s.n, s.table).map(x=>UID(x.ch)+":"+x.i));
  $$(".rule").forEach(r=>r.classList.toggle("faded", !hits.has(r.dataset.chain+":"+r.dataset.i)));
});
document.addEventListener("mouseout", e=>{
  if(e.target.closest("[data-si]")) $$(".rule").forEach(r=>r.classList.remove("faded"));
});

