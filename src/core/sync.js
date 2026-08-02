/* Which rule of the model is which rule of the host.
 *
 * Three things wanted this and none of them could have it. Live counters need
 * to know where to put the numbers. Drift detection needs to know what the
 * host has that you have not. And addressing one rule by its handle — the only
 * way to change a single rule of a running kernel — needs to know that the
 * handle you are holding still points where you think.
 *
 * The three are the same question asked with rising stakes: get it wrong for
 * counters and a number is stale, get it wrong for a handle and you delete
 * somebody else's rule. So the pairing is done once, here, and each caller is
 * told how it was arrived at.
 *
 * A handle is nftables' own identity for a rule and is trusted first. Rules
 * without one — anything typed here rather than read from a host — are lined
 * up by text within their chain, in order, which is the same alignment the
 * round-trip check uses and is right exactly as often. */
import { ruleLine, UID } from "./model.js";
import { diffLines } from "./diff.js";

const key = (ch) => `${ch.table}/${ch.id}`;
const text = (r) => ruleLine(r) + (r.cmt ? ` comment "${r.cmt}"` : "");

/**
 * Pair one chain's rules with the host's.
 * @returns {{pairs, onlyModel, onlyHost}} pairs carry `by`, which is the whole
 *          point: only "handle" is strong enough to act on.
 */
export function pairChain(mine, theirs) {
  const pairs = [], onlyModel = [], onlyHost = [];
  const hostLeft = (theirs?.rules || []).map((r, i) => ({ r, i }));

  /* handles first, and across the whole chain — a rule that moved still is
     the rule it was */
  const byHandle = new Map();
  for (const h of hostLeft) if (h.r.handle) byHandle.set(h.r.handle, h);

  const takenHost = new Set();
  const mineLeft = [];
  (mine?.rules || []).forEach((r, i) => {
    const hit = r.handle && byHandle.get(r.handle);
    if (hit && !takenHost.has(hit.i)) {
      takenHost.add(hit.i);
      pairs.push({ i, r, hostRule: hit.r, hostIndex: hit.i, by: "handle",
                   same: text(r) === text(hit.r) });
    } else mineLeft.push({ r, i });
  });

  /* whatever is left over, lined up by what it says */
  const a = mineLeft.map((x) => text(x.r));
  const b = hostLeft.filter((h) => !takenHost.has(h.i)).map((h) => text(h.r));
  const rest = hostLeft.filter((h) => !takenHost.has(h.i));
  let ai = 0, bi = 0;
  for (const [sign] of diffLines(a, b)) {
    if (sign === " ") {
      pairs.push({ i: mineLeft[ai].i, r: mineLeft[ai].r, hostRule: rest[bi].r,
                   hostIndex: rest[bi].i, by: "text", same: true });
      ai++; bi++;
    } else if (sign === "-") onlyModel.push(mineLeft[ai++]);
    else onlyHost.push(rest[bi++]);
  }
  return { pairs, onlyModel, onlyHost };
}

/** The same, for every chain the two have in common — and the ones they do not. */
export function syncReport(model, host) {
  const mine = model.chains || [], theirs = host?.chains || [];
  const chains = new Map();
  let added = 0, missing = 0, changed = 0;

  for (const ch of mine) {
    const other = theirs.find((c) => key(c) === key(ch));
    if (!other) { missing += ch.rules.filter((r) => r.on).length; continue; }
    const r = pairChain(ch, other);
    chains.set(key(ch), r);
    added += r.onlyHost.length;
    missing += r.onlyModel.length;
    changed += r.pairs.filter((p) => !p.same).length;
  }
  /* a whole chain that exists there and not here is drift too */
  for (const ch of theirs)
    if (!mine.some((c) => key(c) === key(ch))) added += ch.rules.length;

  return { chains, added, missing, changed, inSync: !added && !missing && !changed };
}

/**
 * Copy the host's packet and byte figures onto the rules they belong to.
 * Counters are not part of what a ruleset means — nothing in the generated
 * source changes — so this is a read, not an edit.
 * @returns how many rules were given fresh numbers
 */
export function applyCounters(model, host) {
  let n = 0;
  for (const ch of model.chains || []) {
    const other = (host?.chains || []).find((c) => key(c) === key(ch));
    if (!other) continue;
    for (const p of pairChain(ch, other).pairs) {
      if (p.r.pkts === p.hostRule.pkts && p.r.bytes === p.hostRule.bytes) continue;
      p.r.pkts = p.hostRule.pkts;
      p.r.bytes = p.hostRule.bytes;
      n++;
    }
  }
  return n;
}

/**
 * The handle this rule can be addressed by on the host, or null.
 *
 * Null unless the pairing was made by handle, the text still agrees, and the
 * chain holds nothing else that has drifted. That last condition is the one
 * that matters: a handle is a position in somebody else's kernel, and acting
 * on one while the chain around it has moved is how you delete a rule you
 * never looked at.
 */
export function addressable(model, host, ch, i) {
  const other = (host?.chains || []).find((c) => key(c) === key(ch));
  if (!other) return null;
  const r = pairChain(ch, other);
  if (r.onlyHost.length || r.onlyModel.length) return null;
  const p = r.pairs.find((x) => x.i === i);
  return p && p.by === "handle" && p.same ? p.hostRule.handle : null;
}

export { key as chainKey, UID };
