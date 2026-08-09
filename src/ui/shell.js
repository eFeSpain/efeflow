/* The half-dozen things every screen uses, so that a screen can be a file.
 *
 * These were declared at the top of app.js and reached by everything below
 * them, which is a large part of why everything below them had to stay in the
 * same file. There is nothing clever here: two query helpers, an escape, a
 * builder, and the toast. What matters is that they now have an address.
 */

export const $ = (s, r = document) => r.querySelector(s);
export const $$ = (s, r = document) => [...r.querySelectorAll(s)];

/* Text on its way into markup. The quotes matter as much as the angle
   brackets: nearly every use of this is inside an attribute, and without them
   a name out of somebody else's project file closes the attribute and opens a
   tag. Exported so a test can hold it to that. */
export const esc = (s) => String(s ?? "")
  .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
  .replace(/"/g, "&quot;").replace(/'/g, "&#39;");

export const el = (tag, c, h) => {
  const n = document.createElement(tag);
  if (c) n.className = c;
  if (h != null) n.innerHTML = h;
  return n;
};

/* chain and interface keys contain "/" and spaces, so they need escaping
   before they go into an attribute selector. */
export const cssEsc = (s) =>
  (typeof window !== "undefined" && window.CSS && CSS.escape)
    ? CSS.escape(s)
    : String(s).replace(/["\\]/g, "\\$&");

/* Going to a screen.
 *
 * `go` itself cannot live here: arriving somewhere re-measures the canvas,
 * redraws the topology and re-runs the simulator, and those belong to the
 * screens that own them. What lives here is the name, so that a module which
 * only wants to send somebody to the validation screen does not have to be in
 * the same file as the thing that lays out chains. The composition root hands
 * over the real one once, at boot. */
let goImpl = () => {};
export const setNavigator = (fn) => { goImpl = fn; };
export const go = (id) => goImpl(id);

/* The same arrangement, for three more things a screen asks the application to
 * do rather than does itself: put the cursor on that rule, open a menu here,
 * take it away. The canvas and the properties panel implement them; the set
 * manager and the palette only need to be able to say them.
 *
 * A short and named list on purpose. Every entry is a wire that would
 * otherwise have to be a shared file, and a long one would mean this had
 * turned into somewhere to put anything. */
const late = { select: () => {}, openCtx: () => {}, killCtx: () => {} };
export const provide = (what) => Object.assign(late, what);
export const select = (...a) => late.select(...a);
export const openCtx = (...a) => late.openCtx(...a);
export const killCtx = (...a) => late.killCtx(...a);

/* nftables source, coloured.
 *
 * Pure, and needs nothing but `esc` — which is why it sits with the other
 * primitives rather than with the code panel that used to own it. Three
 * screens paint a rule: the code pane, the properties panel and the set
 * manager. */
const TOKEN = /(#.*$)|("(?:[^"\\]|\\.)*")|(@[A-Za-z_]\w*)|\b(accept|drop|reject|jump|goto|return|continue|masquerade|redirect|dnat|snat)\b|\b(table|chain|set|map|type|hook|priority|policy|elements|flags|comment|flush|ruleset|include|define)\b|\b(ct|meta|tcp|udp|icmp|ipv6-icmp|ip|ip6|inet|iif|oif|iifname|oifname|saddr|daddr|sport|dport|state|status|l4proto|limit|log|counter|rate|burst|prefix|to|with|filter|nat|srcnat|dstnat)\b|\b(\d[\w./:]*)\b/gm;
const CLS = ["c-cm", "c-str", "c-st", "c-vd", "c-kw", "c-mt", "c-nm"];

export function highlight(line) {
  let out = "", last = 0, m;
  TOKEN.lastIndex = 0;
  while ((m = TOKEN.exec(line))) {
    out += esc(line.slice(last, m.index));
    let cls = "c-nm";
    for (let g = 1; g <= 7; g++) if (m[g] !== undefined) { cls = CLS[g - 1]; break; }
    if (cls === "c-vd" && /^(drop|reject)$/.test(m[0])) cls = "c-vdd";
    out += `<span class="${cls}">${esc(m[0])}</span>`;
    last = m.index + m[0].length;
  }
  return out + esc(line.slice(last));
}

let toastT = null;
export function toast(msg) {
  let n = $("#toast");
  if (!n) {
    n = el("div", "glass");
    n.id = "toast";
    /* Reported from the running app: "me sale un mensaje que no me da tiempo
       a leer bien". Clicking it away is the other half of the fix below —
       once a message can last eleven seconds, it has to be dismissible. */
    n.addEventListener("click", () => n.classList.remove("on"));
    document.body.appendChild(n);
  }
  n.textContent = msg;
  n.classList.add("on");
  clearTimeout(toastT);
  /* 2.2s is right for "Exported fw.nft" and nowhere near enough for a
     sentence explaining a permission. Scaled to roughly a reading pace, with
     the old duration as the floor so nothing short got slower. */
  toastT = setTimeout(() => n.classList.remove("on"),
                      Math.min(11000, Math.max(2200, String(msg).length * 55)));
}
