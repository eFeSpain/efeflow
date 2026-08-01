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
