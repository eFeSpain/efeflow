/* The project is the thing being edited: a name, a ruleset, and where it came
   from. Kept apart from MODEL so the native layer can own the file path
   without the pure core knowing anything about a filesystem. */
import { MODEL } from "./model.js";

export const project = {
  name: "edge-fw-01",
  path: null,          // filesystem path once saved or opened
  origin: null,        // { kind: 'file' | 'local' | 'ssh', detail }
  dirty: false,
};

export const PROJECT = () => project.name;

export function setProject(patch) {
  Object.assign(project, patch);
}

/* What gets written to a .efeflow.json */
export const serialise = () =>
  JSON.stringify(
    { app: "eFeFlow", v: 1, name: project.name, chains: MODEL.chains, sets: MODEL.sets },
    null,
    2,
  );

export function deserialise(text) {
  const o = JSON.parse(text);
  if (!o || !Array.isArray(o.chains)) throw new Error("not an eFeFlow project");
  return { name: o.name || "imported", chains: o.chains, sets: o.sets || [] };
}
