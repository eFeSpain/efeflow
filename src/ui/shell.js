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
