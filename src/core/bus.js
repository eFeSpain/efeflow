/* Everything that derives from the ruleset subscribes here. Nothing writes
   MODEL directly — mutations go through history.edit(), which fires this once
   the change has landed, so no view can ever describe a ruleset that is no
   longer being edited. */

const modelHooks = [];
const langHooks = [];

export const onModelChange = (fn) => (modelHooks.push(fn), fn);
export const onRender = (fn) => (langHooks.push(fn), fn);

export const modelChanged = () => modelHooks.forEach((f) => f());
export const rerender = () => langHooks.forEach((f) => f());

/* Current analyser output. The canvas, the properties panel and the drawer all
   read this, so a flagged rule is flagged everywhere at once. */
export const findings = { list: [] };
export const setFindings = (list) => (findings.list = list);

/* A ruleset reached a host and stayed there.
 *
 * Two screens care and neither is the one that did it: the diff drawer takes a
 * new baseline, because what is running is now what is here, and the first-run
 * screen steps aside for a project that plainly exists. Announcing it here is
 * what lets the host code be a module of its own — it would otherwise have to
 * reach up into both of them, which is the shape that kept everything in one
 * five-thousand-line file. */
const appliedHooks = [];
export const onApplied = (fn) => (appliedHooks.push(fn), fn);
export const applied = () => appliedHooks.forEach((f) => f());
