/* The project is the thing being edited: a name, a ruleset, and where it came
   from. Kept apart from MODEL so the native layer can own the file path
   without the pure core knowing anything about a filesystem. */
import { MODEL } from "./model.js";

export const project = {
  /* Nothing is open at boot. Everything that names the project reads `open`
     first, so an empty application says so rather than inventing a name. */
  open: false,
  name: "",
  path: null,          // filesystem path once saved or opened
  origin: null,        // { kind: 'file' | 'local' | 'ssh', detail }
  dirty: false,

  /* Names you keep to hand before any rule mentions them: the interfaces on
     the box you are writing for, the ranges your network actually uses. They
     are not nftables objects — nftables has no concept of a declared
     interface — so they live with the project, not with the ruleset. */
  scratch: { ifaces: [], networks: [] },
};

export const PROJECT = () => project.name;

export function setProject(patch) {
  Object.assign(project, patch);
}

/* What gets written to a .efeflow.json */
export const serialise = () =>
  JSON.stringify(
    {
      app: "eFeFlow",
      v: 1,
      name: project.name,
      scratch: project.scratch,
      chains: MODEL.chains,
      sets: MODEL.sets,
    },
    null,
    2,
  );

export function deserialise(text) {
  const o = JSON.parse(text);
  if (!o || !Array.isArray(o.chains)) throw new Error("not an eFeFlow project");
  return {
    name: o.name || "imported",
    chains: o.chains,
    sets: o.sets || [],
    scratch: { ifaces: [], networks: [], ...(o.scratch || {}) },
  };
}
