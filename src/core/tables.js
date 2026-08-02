/* The table itself, which was the one level of nftables nothing here could edit.
 *
 * Tables were discovered from the chains and never had properties of their own:
 * an imported `flags dormant` survived a round trip and was invisible while it
 * did, and a table comment the same. Dormant is not a cosmetic flag — it is how
 * you park a firewall. Its base chains are never registered, so nothing in the
 * table sees a packet, and a ruleset that carries one looks, on every screen
 * that reads it, exactly like a ruleset that is running.
 *
 * Everything here takes the model explicitly and returns plain data. The only
 * lines it will rewrite are the two it understands; anything else a table
 * carries stays where it sat, in the order it arrived. */

export const FAMILIES = ["ip", "ip6", "inet", "arp", "bridge", "netdev"];

/* `inet fw` → inet + fw. A bare `table filter {` is the ip family by nft's own
   default, and the parser records it expanded, so this agrees with it. */
export function splitTable(full) {
  const parts = String(full || "").trim().split(/\s+/).filter(Boolean);
  if (parts.length > 1 && FAMILIES.includes(parts[0]))
    return { family: parts[0], name: parts.slice(1).join(" ") };
  return { family: "ip", name: parts.join(" ") };
}

export const joinTable = (family, name) =>
  `${String(family || "ip").trim()} ${String(name || "").trim()}`.trim();

/* The same order generate.js emits them in, so a list of tables anywhere in the
   interface reads down the file. */
export function tableNames(model) {
  return [...new Set([
    ...(model?.chains || []).map((c) => c.table),
    ...(model?.sets || []).map((s) => s.table),
    ...(model?.objects || []).map((o) => o.table),
    ...(model?.tables || []).map((t) => t.name),
  ])].filter(Boolean);
}

const FLAGS = /^flags\s+(.+)$/;
const COMMENT = /^comment\s+"((?:[^"\\]|\\.)*)"/;

/* A table takes more than one flag — `flags dormant,owner` — so the toggle owns
   the word, not the line. */
export function flagsOf(extra = []) {
  const line = (extra || []).find((l) => FLAGS.test(l));
  return line
    ? line.match(FLAGS)[1].split(",").map((s) => s.trim()).filter(Boolean)
    : [];
}

const infoFor = (model, full) => (model?.tables || []).find((x) => x.name === full);

/** Everything the editor shows about one table, and what it would take with it. */
export function readTable(model, full) {
  const info = infoFor(model, full);
  const extra = info?.extra || [];
  const flags = flagsOf(extra);
  const cm = extra.map((l) => l.match(COMMENT)).find(Boolean);
  const chains = (model?.chains || []).filter((c) => c.table === full);
  /* a set with no table of its own belongs to the first one, which is where
     generate.js writes it */
  const first = tableNames(model)[0];
  return {
    ...splitTable(full),
    full,
    flags,
    dormant: flags.includes("dormant"),
    comment: cm ? cm[1] : "",
    extra,
    chains: chains.length,
    rules: chains.reduce((a, c) => a + c.rules.length, 0),
    sets: (model?.sets || []).filter((s) => (s.table || first) === full).length,
    objects: (model?.objects || []).filter((o) => o.table === full).length,
  };
}

/**
 * Write back the two properties this understands, in place.
 *
 * Replacing the lines where they sit rather than rebuilding the block is what
 * keeps a table that also carries something we have never heard of coming back
 * out in the order it went in.
 */
export function writeTable(model, full, patch = {}) {
  model.tables ||= [];
  let info = infoFor(model, full);
  if (!info) { info = { name: full, extra: [] }; model.tables.push(info); }

  const flags = flagsOf(info.extra).filter((f) => f !== "dormant");
  if (patch.dormant) flags.push("dormant");
  const flagLine = flags.length ? `flags ${flags.join(",")}` : null;
  const cmtLine = patch.comment
    ? `comment "${String(patch.comment).replace(/"/g, "")}"`
    : null;

  let sawFlags = false, sawComment = false;
  const out = [];
  for (const l of info.extra || []) {
    if (FLAGS.test(l)) { sawFlags = true; if (flagLine) out.push(flagLine); continue; }
    if (COMMENT.test(l)) { sawComment = true; if (cmtLine) out.push(cmtLine); continue; }
    out.push(l);
  }
  if (!sawComment && cmtLine) out.unshift(cmtLine);
  if (!sawFlags && flagLine) out.unshift(flagLine);
  info.extra = out;
  return info;
}

/** Is this table parked? The question the simulator and the analyser both ask. */
export const isDormant = (model, full) => flagsOf(infoFor(model, full)?.extra).includes("dormant");

/** Every table that is loaded and not running. */
export const dormantTables = (model) => tableNames(model).filter((n) => isDormant(model, n));

/**
 * Move a table and everything filed under it.
 *
 * Refuses to merge into a name that already exists: two tables' flags and
 * comments cannot both survive one block, and quietly picking a winner is the
 * kind of thing this whole file exists to stop.
 */
export function renameTable(model, from, to) {
  if (!from || !to || from === to) return 0;
  if (tableNames(model).includes(to)) return 0;
  let n = 0;
  const move = (list) => (list || []).forEach((x) => { if (x.table === from) { x.table = to; n++; } });
  move(model.chains);
  move(model.sets);
  move(model.objects);
  const info = infoFor(model, from);
  if (info) { info.name = to; n++; }
  return n;
}

/** Delete a table, and say what went with it. */
export function removeTable(model, full) {
  const gone = { chains: 0, rules: 0, sets: 0, objects: 0 };
  const cut = (list, key) => {
    for (let i = (list || []).length - 1; i >= 0; i--) {
      if (list[i].table !== full) continue;
      if (key === "chains") gone.rules += list[i].rules.length;
      gone[key]++;
      list.splice(i, 1);
    }
  };
  cut(model.chains, "chains");
  cut(model.sets, "sets");
  cut(model.objects, "objects");
  const at = (model.tables || []).findIndex((x) => x.name === full);
  if (at >= 0) model.tables.splice(at, 1);
  return gone;
}
