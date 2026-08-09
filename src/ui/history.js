/* The gate every change goes through.
 *
 * Nothing writes MODEL directly: a mutation is a function handed to edit(),
 * which photographs the ruleset before and after and keeps the pair. The
 * snapshot is the whole thing rather than a per-field diff, which is cheap at
 * this size and removes the entire class of bug that per-field diffing invites
 * — including the one where an undo forgets the flowtables and deletes them.
 *
 * It lives here because it is the one function the whole interface shares:
 * forty-eight calls from outside the file it used to be declared in, which is
 * a large part of why that file could not be broken up. What it cannot own is
 * what happens *after* a change lands — repainting the canvas, the code panel
 * and the wires belongs to the screens that draw them. So the composition root
 * hands that over once, the same way it hands over the navigator.
 */
import { MODEL } from "../core/model.js";
import { t } from "../i18n.js";
import { $, toast } from "./shell.js";

const HIST = { past: [], future: [], max: 80 };

/* Everything the ruleset is made of, including the parts nothing edits. */
export const snapshot = () => JSON.stringify(
  { c: MODEL.chains, s: MODEL.sets, o: MODEL.objects, tb: MODEL.tables, pr: MODEL.prelude });

function restore(str) {
  const o = JSON.parse(str);
  MODEL.chains = o.c;
  MODEL.sets = o.s;
  MODEL.objects = o.o || [];
  MODEL.tables = o.tb || [];
  MODEL.prelude = o.pr || [];
}

/* What to do once the ruleset has changed under everybody. Registered at boot
   by the screens that own the drawing. */
let repaint = () => {};
export const setRepainter = (fn) => { repaint = fn; };

/* The last snapshot taken, and an edit begun but not yet committed. Both are
   read by the screens that start an edit before they know it will finish — a
   drag, or a source box that has been focused. */
export const state = { cur: null, pending: null };

/* Exported because one screen begins an edit and finishes it much later: the
   properties panel photographs the ruleset when a field takes focus and only
   knows whether anything changed when it loses it. */
export function pushHist(before, label) {
  if (before === snapshot()) return false;
  HIST.past.push({ s: before, label });
  if (HIST.past.length > HIST.max) HIST.past.shift();
  HIST.future.length = 0;
  state.cur = snapshot();
  syncHistUI();
  return true;
}

/** label is what the user would call the change — it surfaces in the tooltip */
export function edit(label, fn, keepSel) {
  const before = state.cur ?? snapshot();
  fn();
  if (pushHist(before, label)) repaint(keepSel);
}

export function undo() {
  if (!HIST.past.length) return;
  const e = HIST.past.pop();
  HIST.future.push({ s: snapshot(), label: e.label });
  restore(e.s);
  state.cur = e.s;
  syncHistUI();
  repaint(true);
  toast(t("Undone: ", "Deshecho: ") + e.label);
}

export function redo() {
  if (!HIST.future.length) return;
  const e = HIST.future.pop();
  HIST.past.push({ s: snapshot(), label: e.label });
  restore(e.s);
  state.cur = e.s;
  syncHistUI();
  repaint(true);
  toast(t("Redone: ", "Rehecho: ") + e.label);
}

export function syncHistUI() {
  const u = $("#undo"), r = $("#redo");
  if (!u) return;
  u.disabled = !HIST.past.length;
  r.disabled = !HIST.future.length;
  u.title = HIST.past.length
    ? t("Undo ", "Deshacer ") + HIST.past.at(-1).label + " — Ctrl+Z"
    : t("Nothing to undo", "Nada que deshacer");
  r.title = HIST.future.length
    ? t("Redo ", "Rehacer ") + HIST.future.at(-1).label + " — Ctrl+Y"
    : t("Nothing to redo", "Nada que rehacer");
  const d = $(".dot-live");
  if (d) d.style.opacity = HIST.past.length ? "1" : ".25";
}

/** Whether there is anything to undo — the dot in the titlebar asks. */
export const dirty = () => HIST.past.length > 0;

/* What has been done, for the screens that recount it rather than change it:
   the command palette lists the last few labels, and the first-run screen says
   how many edits are unsaved. Read only — everything that adds to it is here. */
export const undoStack = () => HIST.past;
