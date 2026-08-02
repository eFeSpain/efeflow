/* The firewalls you look after, as a list.
 *
 * Nobody administers one box. There is the edge firewall and the database
 * firewall and the one in the branch office, and the tool remembered exactly
 * one of them — so moving between them meant retyping a hostname you had
 * typed a hundred times.
 *
 * This is deliberately not part of a project. An inventory describes your
 * estate, not the ruleset you happen to have open, and a `.efeflow.json` is a
 * file people attach to a bug report. The same reasoning as the service
 * catalogue: knowledge about the world lives on the machine, and what lives in
 * the project is the work.
 *
 * Pure and storage-free, like the rest of core/. The caller decides where the
 * list comes from and where it goes.
 */

/** Nothing about a host is required except somewhere to reach it. */
export const HOST = (o = {}) => ({
  id: o.id || `h${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`,
  name: (o.name || "").trim(),
  kind: o.kind === "local" ? "local" : "ssh",
  host: (o.host || "").trim(),
  user: (o.user || "").trim(),
  port: String(o.port || "").trim(),
  sudo: o.sudo !== false,
});

/** What to call it when it has not been named: how you would reach it. */
export const label = (h) =>
  h.name ||
  (h.kind === "local"
    ? "local"
    : (h.user ? `${h.user}@` : "") + (h.host || "?") + (h.port ? `:${h.port}` : ""));

/* Two entries for the same login on the same box are not two firewalls. The
   name is not part of it: renaming one must not make it a different host. */
const same = (a, b) =>
  a.kind === b.kind &&
  (a.kind === "local" ||
    (a.host.toLowerCase() === b.host.toLowerCase() &&
      a.user === b.user &&
      (a.port || "22") === (b.port || "22")));

/** Read a stored list, keeping only what is shaped like a host. */
export function readHosts(text) {
  let raw;
  try {
    raw = JSON.parse(text || "[]");
  } catch {
    return [];                       /* a corrupt entry is not worth a crash */
  }
  if (!Array.isArray(raw)) return [];
  const out = [];
  for (const item of raw) {
    if (!item || typeof item !== "object") continue;
    const h = HOST(item);
    if (h.kind === "ssh" && !h.host) continue;      /* nowhere to go */
    if (out.some((x) => same(x, h))) continue;
    out.push(h);
  }
  return out;
}

/**
 * Add one, or fold it into the entry that already reaches the same machine.
 *
 * Returns the list and the host as stored, which is not always the one passed:
 * pointing at a box you already have should select that one rather than grow a
 * second copy of it with a different name.
 */
export function addHost(list, o) {
  const h = HOST(o);
  if (h.kind === "ssh" && !h.host) return { list, host: null };
  const at = list.findIndex((x) => same(x, h));
  if (at >= 0) {
    const merged = { ...list[at], name: h.name || list[at].name, sudo: h.sudo };
    const next = list.slice();
    next[at] = merged;
    return { list: next, host: merged };
  }
  return { list: [...list, h], host: h };
}

export const updateHost = (list, id, patch) =>
  list.map((h) => (h.id === id ? HOST({ ...h, ...patch, id: h.id }) : h));

export const removeHost = (list, id) => list.filter((h) => h.id !== id);

export const findHost = (list, id) => list.find((h) => h.id === id) || null;

/** The shape src/target.js works in, which is a host without its identity. */
export const asTarget = (h) =>
  h ? { kind: h.kind, host: h.host, user: h.user, port: h.port, sudo: h.sudo }
    : { kind: "local", host: "", user: "", port: "", sudo: true };

/** And back, for the entry that matches a target already in use. */
export const matching = (list, tg) =>
  list.find((h) => same(h, HOST(tg))) || null;

export const writeHosts = (list) => JSON.stringify(list, null, 2);
