/* The canvas: chains placed where netfilter would run them.
 *
 * A chain's position is not a layout choice — it is (hook, priority), which is
 * the only thing that decides the order a packet meets them in. So the canvas
 * is a reading of the ruleset rather than a drawing of it, and moving a card
 * means changing a priority.
 *
 * It owns where things are (POS), how the lanes are packed (LANES) and the
 * scale — everything else it needs is the model, and it announces what it has
 * drawn rather than calling into other screens. The one wire that had to be
 * cut first was a resize handler that repainted the topology screen: that
 * screen registers its own now.
 */
import { MODEL, UID, VCOLOR, VNAME, ruleLine, chainOf, fmtN, fmtB, jumpTarget } from "../core/model.js";
import { NAME_PRIO } from "../core/priority.js";
import { isDormant } from "../core/tables.js";
import { findings, onRender, onModelChange } from "../core/bus.js";
import { wirePlan, reachable } from "../core/topology.js";
import { t } from "../i18n.js";
import { $, $$, esc, el, cssEsc, highlight, toast, go } from "./shell.js";
import { UI } from "./state.js";

/* Where each chain sits, and how many lanes deep the rail had to go. Nothing
   outside this file has an opinion about either. */
let POS = {}, LANES = {};
/* The wire plan, cached from the last renderChains — see there for why. */
let _wires = [];

/* ══ CANVAS · chains anchored at (hook, priority) ═══════════════════════ */
/* Left to right in the order a packet meets them. `ingress` and `egress` are
   netdev hooks: they run on a device before netfilter has seen the packet at
   all, and after it has finished with it, so they are the two ends of the
   field — and without a column of their own they landed on top of prerouting.
   They only take one when something is attached to them, the way the tables
   and sets lists only show what the ruleset has. */
const CORE_HOOKS = ["prerouting","input","forward","output","postrouting"];
const COL = 304, GUT = 64;
export let HOOK_X = {};

function hookColumns(){
  const used = new Set(MODEL.chains.map(c=>c.hook).filter(Boolean));
  return [...(used.has("ingress") ? ["ingress"] : []), ...CORE_HOOKS,
          ...(used.has("egress")  ? ["egress"]  : [])];
}

/* The canvas is as wide as the hooks in use, so nothing may assume the 1680 it
   used to be — the wires, the minimap and its viewport all did, and every one
   of them was drawn against the wrong scale the moment a netdev column
   appeared. */
const canvasW = () => parseInt($("#canvas").style.width) || 1680;

function renderHookRail(){
  const cols = hookColumns();
  HOOK_X = Object.fromEntries(cols.map((h,i)=>[h, GUT + i*COL + 24]));
  const width = GUT + cols.length*COL + 96;

  const rail = $(".hookrail");
  rail.style.width = width + "px";
  rail.style.gridTemplateColumns = `${GUT}px repeat(${cols.length},1fr)`;
  rail.innerHTML = `<div class="rl"><span class="lbl" style="font-size:9px">PRIO</span></div>`
    + cols.map(h=>`<div class="hk" data-hook="${h}"><span class="hn"></span>${h}</div>`).join("");
  $("#canvas").style.width = width + "px";
  return cols;
}
/* nft prints priorities by name; both directions are needed for round-trip */

const ruler = $("#ruler");
POS = {}, LANES = [];
/* chains the user has placed by hand, keyed by table/chain */
const CHAIN_POS = {};

/* x is the hook, y is the priority — the canvas is a field, not a freeform
   board. Only the column is decided here; the rows need real heights. */
function layout(){
  renderHookRail();
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
export function placeChains(){
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

UI.zoom = 1;
const chainsEl = $("#chains");
export function renderChains(){
  layout();
  chainsEl.innerHTML = MODEL.chains.length ? "" :
    `<div class="empty-canvas">${esc(t(
      "No chains yet — add one, or open a ruleset to read.",
      "Aún no hay cadenas — añade una, o abre un ruleset para leerlo."))}</div>`;
  const live = reachable(MODEL.chains);
  /* The wire plan depends on the model, not on where the cards sit — so it is
     computed once here, where every model change lands, and reused by drawWires
     through a drag or a resize instead of being rebuilt on every pointermove. */
  _wires = wirePlan(MODEL.chains);
  MODEL.chains.forEach(ch=>{
    const p = POS[UID(ch)]; if(!p) return;
    /* a base chain in a dormant table is never registered with netfilter, so
       this card is loaded and filtering nothing — it has to look like it */
    const parked = isDormant(MODEL, ch.table);
    /* a regular chain nobody jumps to is loaded and never entered */
    const dead = !ch.hook && !live.has(UID(ch));
    const node = el("div","chain"+(parked?" parked":"")+(dead?" unreachable":"")
                             +(HOT.nodes.has(UID(ch))?" hot":""));
    node.dataset.chain = UID(ch);
    node.style.left = p.x+"px";   /* the row comes from placeChains, after measuring */
    const polPill = ch.policy
      ? `<span class="pill ${ch.policy==="drop"?"v-drop":"v-accept"}"><span class="sw"></span>policy ${ch.policy}</span>`
      : `<span class="pill v-neutral">${t("regular","regular")}</span>`;
    node.innerHTML = `
      <div class="chain-hd">
        <span style="color:var(--${ch.policy==="drop"?"v-drop":"v-accept"});font-size:9px">◆</span>
        <span class="cn">${esc(ch.id)}</span><span class="fam">${esc(ch.table.split(" ")[0])}</span>
      </div>
      <div class="chain-meta">
        ${ch.hook?`<span class="chip">hook ${ch.hook}</span><span class="chip">prio ${ch.prio}</span>`:`<span class="chip">${t("no hook","sin hook")}</span>`}
        ${polPill}
        ${parked?`<span class="chip parked" title="${esc(t(
            `${ch.table} is dormant — this chain is loaded and sees no packets`,
            `${ch.table} está dormant — esta cadena está cargada y no ve ningún paquete`))}">dormant</span>`:""}
        ${dead?`<span class="chip dead" title="${esc(t(
            "No hook and nothing jumps here — this chain is loaded and never entered",
            "Sin hook y nadie salta aquí — esta cadena está cargada y no se entra nunca"))}">${t("unreachable","inalcanzable")}</span>`:""}
      </div>
      <div class="chain-rules"></div>
      <div class="chain-ft">
        <button class="addrule"><svg class="ico sm" viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg>${t("Add rule","Añadir regla")}</button>
        <span class="lbl" style="font-size:9px">${ch.rules.length}</span>
      </div>`;
    const list = $(".chain-rules",node);
    ch.rules.forEach((r,i)=>{
      /* a jump or goto whose target is gone (or in another table) lands nowhere;
         no wire is drawn for it, so the rule itself has to show it is broken */
      const broken = (r.verdict==="jump"||r.verdict==="goto") && !jumpTarget(ch, r.to);
      const row = el("div","rule"+(r.on?"":" off")+(broken?" broken":""));
      if(broken) row.title = t(`${r.verdict} ${r.to||"?"} — no chain by that name in ${ch.table.split(" ")[0]} ${ch.table.split(" ").slice(1).join(" ")}`,
                               `${r.verdict} ${r.to||"?"} — no hay ninguna cadena así en ${ch.table}`);
      row.dataset.chain = UID(ch); row.dataset.i = i;
      row.draggable = true;
      row.style.color = `var(${VCOLOR[r.verdict]})`;
      const body = r.expr ? esc(r.expr).replace(/@(\w+)/g,'<span class="s">@$1</span>')
                                        .replace(/\b(ct|tcp|udp|ip|ip6|meta|iif|oif|iifname|oifname|limit|log)\b/g,'<span class="k">$1</span>')
                          : `<span class="dimmer">${t("any packet","cualquier paquete")}</span>`;
      /* Once a host has been asked, a zero means something. A rule that counts
         and still reads zero has matched nothing since the ruleset was loaded;
         a rule with no `counter` is not cold, it is unmeasured, and marking
         those the same way would condemn perfectly busy rules. */
      const cold = MODEL.counters && r.on && r.ctr && !r.pkts;
      if(cold) row.classList.add("cold");
      row.innerHTML = `
        <span class="gut"></span>
        <span class="idx">${i+1}</span>
        <span class="expr">${body}</span>
        <span class="rt">
          ${r.pkts?`<span class="ctr">${fmtN(r.pkts)}<br>${fmtB(r.bytes)}</span>`
                 :cold?`<span class="ctr cold" title="${esc(t(
                     "Nothing has matched this since the ruleset was loaded",
                     "Nada ha casado con esta desde que se cargó el ruleset"))}">0</span>`:""}
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
  /* the verdict colours, and — since the wires carry meaning too — what a solid
     line and a dashed one each say */
  const wireKey = MODEL.chains.some(c=>c.hook) ? `
    <div class="row wk"><svg viewBox="0 0 22 6"><line x1="1" y1="3" x2="21" y2="3"/></svg>${t("packet path","recorrido")}</div>
    <div class="row wk"><svg viewBox="0 0 22 6"><line x1="1" y1="3" x2="21" y2="3" stroke-dasharray="3 3"/></svg>${t("jump / goto","salto / goto")}</div>` : "";
  $("#legend").innerHTML = rows.map(v =>
    `<div class="row" style="color:var(${VCOLOR[v]})"><i></i>${VNAME[v]}</div>`).join("") + wireKey;
  $("#legend").style.display = (rows.length || wireKey) ? "" : "none";
}
renderChains();
onRender(()=>{ renderChains(); drawWires(); });
/* A lit packet path is only true of the ruleset it was traced through; once a
   rule changes it is the old packet's route, so it goes — the same reason the
   simulator dims a stale trace. */
onModelChange(()=>clearLit());

/* The wires and reachability are the model as a graph, with no DOM in them, so
   they live in core/topology.js and are checked on their own. */

/* The path a simulated packet took, mirrored onto the topology — the chains it
   entered and the wires between them — set by the simulator and cleared when
   the trace goes stale. Kept in the module so a re-render re-applies it. */
let HOT = { nodes: new Set(), edges: new Set() };
export function litPath(uids){
  const list = [...new Set(uids)];
  HOT = { nodes: new Set(list), edges: new Set() };
  for(let i=1;i<list.length;i++){ HOT.edges.add(list[i-1]+">"+list[i]); HOT.edges.add(list[i]+">"+list[i-1]); }
  $$(".chain").forEach(n=>n.classList.toggle("hot", HOT.nodes.has(n.dataset.chain)));
  drawWires();
}
export function clearLit(){
  if(!HOT.nodes.size && !HOT.edges.size) return;
  HOT = { nodes: new Set(), edges: new Set() };
  $$(".chain").forEach(n=>n.classList.remove("hot"));
  drawWires();
}
export function drawWires(){
  const svg = $("#wires");
  const h = parseInt($("#canvas").style.height) || 920;
  const w = canvasW();
  svg.setAttribute("viewBox",`0 0 ${w} ${h}`);
  svg.setAttribute("width",String(w)); svg.setAttribute("height",String(h));
  /* an arrowhead so a wire says which way the packet goes, not just that two
     chains are joined; three of them, so a path, a jump and the lit trace read
     apart at a glance */
  let out = `<defs>${["wm","wm-jump","wm-act"].map(id=>
    `<marker id="${id}" markerWidth="8" markerHeight="8" refX="6.2" refY="3" orient="auto">
       <path d="M0 0 6 3 0 6z"/></marker>`).join("")}</defs>`;
  /* straight from the DOM, so a card being dragged pulls its wires with it */
  _wires.forEach(([a,b,jump])=>{
    const A = $(`.chain[data-chain="${cssEsc(a)}"]`), B = $(`.chain[data-chain="${cssEsc(b)}"]`);
    if(!A||!B) return;
    const hot = HOT.edges.has(a+">"+b) || HOT.edges.has(b+">"+a);
    const cxA = A.offsetLeft + A.offsetWidth/2, cxB = B.offsetLeft + B.offsetWidth/2;
    const cls = hot ? "act" : jump ? "jump" : "";
    const marker = hot ? "wm-act" : jump ? "wm-jump" : "wm";
    let d;
    /* A parent and the chain it jumps to usually share a column — the child is
       hung directly under it. Loop out the right edge and back into the left and
       the wire crosses everything between them; drop it straight down instead. */
    if(Math.abs(cxA - cxB) < 40){
      const down = B.offsetTop >= A.offsetTop;
      const y1 = down ? A.offsetTop + A.offsetHeight : A.offsetTop;
      const y2 = down ? B.offsetTop : B.offsetTop + B.offsetHeight;
      const dy = Math.max(28, Math.abs(y2 - y1) * .5) * (down ? 1 : -1);
      d = `M${cxA} ${y1} C${cxA} ${y1+dy} ${cxB} ${y2-dy} ${cxB} ${y2}`;
    } else {
      const left = cxA <= cxB;
      const x1 = left ? A.offsetLeft + A.offsetWidth : A.offsetLeft;
      const y1 = A.offsetTop + A.offsetHeight/2;
      const x2 = left ? B.offsetLeft : B.offsetLeft + B.offsetWidth;
      const y2 = B.offsetTop + B.offsetHeight/2;
      const dx = Math.max(46, Math.abs(x2-x1)*.55) * (left ? 1 : -1);
      d = `M${x1} ${y1} C${x1+dx} ${y1} ${x2-dx} ${y2} ${x2} ${y2}`;
    }
    out += `<path class="${cls}" marker-end="url(#${marker})" d="${d}"`
         + `${jump && !hot?' stroke-dasharray="4 5"':''}/>`;
  });
  svg.innerHTML = out;
}
/* A drag fires pointermove many times a frame and a resize fires in bursts;
   coalesce to one repaint per frame rather than one per event. */
let _wireRaf = 0;
export function drawWiresSoon(){
  if(_wireRaf) return;
  _wireRaf = requestAnimationFrame(()=>{ _wireRaf = 0; drawWires(); });
}
requestAnimationFrame(drawWires);
/* Only the wires. The topology screen also redraws on a resize, and it says so
   itself — a canvas that reaches across to repaint another screen is a wire
   that has to be cut before either can be a file of its own. */
window.addEventListener("resize", drawWiresSoon);

/* minimap mirrors the real chain positions and the real viewport */
function renderMinimap(){
  const mm = $("#mm"), sc = $("#cscroll");
  const H = parseInt($("#canvas").style.height) || 920;
  const SX = 176/canvasW(), SY = 104/H;
  mm.innerHTML = MODEL.chains.map(ch=>{
    const node = $(`.chain[data-chain="${cssEsc(UID(ch))}"]`);
    if(!node) return "";
    return `<div class="blk${UI.sel && UI.sel.chainId===UID(ch)?" a":""}"
             style="left:${node.offsetLeft*SX}px;top:${node.offsetTop*SY}px;
             width:${node.offsetWidth*SX}px;height:${Math.max(2,node.offsetHeight*SY)}px"></div>`;
  }).join("") + `<div class="vp" id="mm-vp"></div>`;
  syncViewport();
}
export function syncViewport(){
  const sc = $("#cscroll"), vp = $("#mm-vp");
  if(!vp) return;
  const H = parseInt($("#canvas").style.height) || 920;
  vp.style.cssText = `left:${sc.scrollLeft/UI.zoom/canvasW()*176}px;top:${sc.scrollTop/UI.zoom/H*104}px;
    width:${Math.min(176, sc.clientWidth/UI.zoom/canvasW()*176)}px;
    height:${Math.min(104, sc.clientHeight/UI.zoom/H*104)}px`;
}
$("#cscroll").addEventListener("scroll", syncViewport, {passive:true});
/* click the minimap to jump there */
$("#mm").addEventListener("pointerdown", e=>{
  const b = $("#mm").getBoundingClientRect();
  const H = parseInt($("#canvas").style.height) || 920;
  const sc = $("#cscroll");
  sc.scrollTo({left:(e.clientX-b.left)/176*canvasW()*UI.zoom - sc.clientWidth/2,
               top:(e.clientY-b.top)/104*H*UI.zoom - sc.clientHeight/2, behavior:"smooth"});
});

/* ── chains are draggable by their header ───────────────────────────────
   Not by the body: rules there are draggable in their own right, for
   reordering. The header is the handle, which is also where you would grab a
   window. Auto-layout still owns everything you have not touched. */
(function chainDrag(){
  const scroll = $("#cscroll");
  let d = null;

  scroll.addEventListener("pointerdown", e=>{
    if(e.button !== 0 || UI.tool === "pan") return;
    const grip = e.target.closest(".chain-hd, .chain-meta");
    if(!grip || e.target.closest("button")) return;
    const node = grip.closest(".chain");
    d = {node, dx: e.clientX/UI.zoom - node.offsetLeft, dy: e.clientY/UI.zoom - node.offsetTop, moved:false};
    node.setPointerCapture(e.pointerId);
    node.classList.add("dragging");
    e.preventDefault();
  });

  scroll.addEventListener("pointermove", e=>{
    if(!d) return;
    d.moved = true;
    const x = Math.max(70, e.clientX/UI.zoom - d.dx);
    const y = Math.max(46, e.clientY/UI.zoom - d.dy);
    d.node.style.left = x + "px";
    d.node.style.top  = y + "px";
    drawWiresSoon();
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

/* UI.zoom
   The second argument is the point to keep still. Scaling from the corner is
   what a transform does on its own, and it throws whatever you were looking at
   off the screen — the further you are from the origin, the further it goes.
   Zooming towards the pointer is the whole difference between a canvas that
   feels steered and one that feels thrown. */
function setZoom(z, anchor){
  const sc = $("#cscroll");
  const prev = UI.zoom;
  UI.zoom = Math.min(1.6,Math.max(.4,z));
  $("#canvas").style.transform = `scale(${UI.zoom})`;
  $("#canvas").style.transformOrigin = "0 0";
  $("#zl").textContent = Math.round(UI.zoom*100)+"%";
  if(anchor && sc && prev){
    const r = sc.getBoundingClientRect();
    /* where the anchor sits on the canvas, in unscaled coordinates */
    const cx = (sc.scrollLeft + anchor.x - r.left) / prev;
    const cy = (sc.scrollTop  + anchor.y - r.top)  / prev;
    sc.scrollLeft = cx * UI.zoom - (anchor.x - r.left);
    sc.scrollTop  = cy * UI.zoom - (anchor.y - r.top);
  }
  syncViewport();
}
const zoomCentre = ()=>{
  const sc = $("#cscroll"); if(!sc) return undefined;
  const r = sc.getBoundingClientRect();
  return {x:r.left + sc.clientWidth/2, y:r.top + sc.clientHeight/2};
};
/* Fit, meaning fit.
 *
 * This button set the UI.zoom to 72% and called that "fit to view", which is a
 * fixed number wearing the name of a measurement: on a wide ruleset it left
 * two chains off the right-hand edge, and on a narrow one it shrank three
 * cards for no reason. Measure what is placed and pick the UI.zoom that shows it.
 *
 * From the origin rather than from the leftmost card, so the priority ruler
 * and the hook rail stay in frame — they are how the canvas is read. */
function fitToView(){
  const sc = $("#cscroll");
  const cards = $$(".chain", chainsEl);
  if(!sc || !sc.clientWidth || !cards.length) return setZoom(.72);

  const PAD = 28;
  let right = 0, bottom = 0;
  for(const n of cards){
    right  = Math.max(right,  (parseFloat(n.style.left) || 0) + n.offsetWidth);
    bottom = Math.max(bottom, (parseFloat(n.style.top)  || 0) + n.offsetHeight);
  }
  if(!right || !bottom) return setZoom(.72);          /* nothing measurable yet */

  /* never magnify: a two-chain ruleset at 160% is not a view of anything */
  const want = Math.min(sc.clientWidth / (right + PAD), sc.clientHeight / (bottom + PAD), 1);
  setZoom(want);
  sc.scrollLeft = 0;
  sc.scrollTop = 0;
  syncViewport();

  /* setZoom will not go below 40%, past which nothing on a card can be read.
     A ruleset too big for the space left beside the panels therefore does not
     all fit, and a button called Fit owes you that rather than leaving you to
     spot the chain missing off the edge. */
  if(want < UI.zoom - 0.001)
    toast(t("As far out as it goes — this ruleset does not fit beside the panels at a readable size",
            "Hasta aquí llega — este ruleset no cabe junto a los paneles a un tamaño legible"));
}

/* Where a ruleset opens: readable, at the beginning of the packet's path.
 *
 * Not fitToView. Fitting a real ruleset into the space left between the
 * library and the properties panel lands around 40%, where the whole layout is
 * visible and not one rule is legible — an overview is a thing you ask for,
 * not a thing to be dropped into. */
export function resetView(){
  setZoom(.72);
  const sc = $("#cscroll");
  if(sc){ sc.scrollLeft = 0; sc.scrollTop = 0; }
  syncViewport();
}

$("#zi").onclick = ()=>setZoom(UI.zoom+.1, zoomCentre());
$("#zo").onclick = ()=>setZoom(UI.zoom-.1, zoomCentre());
$("#zf").onclick = fitToView;
/* the tooltip has promised this shortcut for as long as the button has existed */
document.addEventListener("keydown", e=>{
  if(e.key === "!" || (e.shiftKey && e.key === "1")){
    /* `?.` because a keydown can arrive with the document as its target, and
       a document has no closest() to ask */
    if(e.target?.closest?.("input, textarea, select, [contenteditable]")) return;
    if(!$("#s-editor").classList.contains("on")) return;
    e.preventDefault();
    fitToView();
  }
});
/* The wheel zooms. It used to scroll, and UI.zoom only with Ctrl held — but this
   is a canvas laid out in two dimensions, where scrolling by wheel reaches
   almost nothing and the thing you actually want is to get closer. Ctrl still
   works, for the hands that learned it. Shift scrolls sideways. */
$("#cscroll").addEventListener("wheel", e=>{
  if(e.shiftKey && !e.ctrlKey) return;              /* leave horizontal scroll alone */
  e.preventDefault();
  const step = e.deltaMode === 1 ? e.deltaY * 0.02 : e.deltaY * 0.0015;
  setZoom(UI.zoom - step, {x:e.clientX, y:e.clientY});
}, {passive:false});

