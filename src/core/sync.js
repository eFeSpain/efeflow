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

/**
 * The same, for every chain the two have in common — and the ones they do not.
 *
 * `tables` narrows it to what an apply would actually replace. Without it,
 * every table on the host counts, which is right for `flush ruleset` and wrong
 * for everything else: a scoped apply emits `delete table` for the project's
 * own tables and leaves the rest standing, so Docker's three chains are not
 * drift, they are somebody else's firewall. Unnarrowed, a developer laptop
 * running Docker reported "3 it has that you have not" before every apply,
 * for ever — and a warning that is always on is a warning nobody reads, in
 * front of the one button that can lock you out of a machine.
 */
export function syncReport(model, host, { tables } = {}) {
  const inScope = tables ? (ch) => tables.includes(ch.table) : () => true;
  const mine = (model.chains || []).filter(inScope);
  const theirs = (host?.chains || []).filter(inScope);
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

/* ── what applying would do ──────────────────────────────────────────────
 *
 * syncReport answers "how do these two differ". That is a question about two
 * documents, and it is not the question somebody has in front of the Apply
 * button. Theirs is "what happens to my firewall if I press this", and the two
 * have different answers, because an apply is not a merge.
 *
 * Measured against nft 1.1.6 on a live kernel rather than reasoned about. A
 * scoped apply emits `delete table X` and recreates it, so:
 *
 *   before  tcp dport 22 ... handle 2      tcp dport 80  packets 5  handle 3
 *   after   tcp dport 25 ... handle 2      tcp dport 80  packets 0  handle 4
 *
 * inserting one rule at the top moved every handle below it and zeroed every
 * counter in the table — including the rules whose text nobody touched. So a
 * red/green diff of the two texts would be true about the text and wrong about
 * the machine: it would show two lines changing when fourteen rules are being
 * destroyed and rebuilt.
 *
 * And the case that nearly hid it: appending at the end left the handles
 * reading 2 and 3, exactly as before. Not preserved — reassigned from scratch
 * and coincidentally equal, because numbering restarts. The counter still went
 * from 7 to 0. A screen that inferred "handles unchanged, so nothing was
 * disturbed" would be lying in the most common case there is.
 */

/**
 * What pressing Apply does to the host, chain by chain, in the host's terms.
 *
 * @param tables the tables the apply replaces — the scoped apply's own list.
 *        Omit for `flush ruleset`, which replaces everything there is.
 * @returns chains in the order they are shown, plus the whole-machine truths
 *          that no line-by-line diff can carry.
 */
export function applyPlan(model, host, { tables } = {}) {
  const inScope = tables ? (ch) => tables.includes(ch.table) : () => true;
  const mine = (model?.chains || []).filter(inScope);
  const theirs = (host?.chains || []).filter(inScope);
  const seen = new Set();
  const chains = [];

  /* Direction is the whole point. `onlyHost` is not "something you are
     missing", it is a rule that exists on that firewall right now and will not
     exist after this — most likely put there by fail2ban or by a colleague. */
  for (const ch of mine) {
    const other = theirs.find((c) => key(c) === key(ch));
    seen.add(key(ch));
    if (!other) {
      chains.push({ key: key(ch), table: ch.table, chain: ch.id, isNew: true,
                    create: ch.rules.filter((r) => r.on), destroy: [], change: [], keep: 0 });
      continue;
    }
    const r = pairChain(ch, other);
    chains.push({
      key: key(ch), table: ch.table, chain: ch.id, isNew: false,
      create: r.onlyModel.map((x) => x.r),
      destroy: r.onlyHost.map((x) => x.r),
      change: r.pairs.filter((p) => !p.same).map((p) => ({ from: p.hostRule, to: p.r })),
      keep: r.pairs.filter((p) => p.same).length,
    });
  }
  /* a chain the host has inside a table we are replacing goes with the table */
  for (const ch of theirs)
    if (!seen.has(key(ch)))
      chains.push({ key: key(ch), table: ch.table, chain: ch.id, isGone: true,
                    create: [], destroy: ch.rules, change: [], keep: 0 });

  /* The part a diff cannot say. Every rule in a table that gets deleted and
     rebuilt is a new rule to the kernel, whatever its text says.

     Two different fates, and calling both "rebuilt" would flatter the worse
     one. A table this project has is deleted and put back: the rules survive
     as text and lose their handles and counters. A table only the host has —
     Docker's, under `flush ruleset` — is deleted and not put back at all. */
  const ours = new Set((model?.chains || []).map((c) => c.table));
  let recreated = 0, counting = 0, packets = 0, dropped = 0, droppedTables = [];
  for (const ch of theirs) {
    const kept = ours.has(ch.table);
    if (!kept && !droppedTables.includes(ch.table)) droppedTables.push(ch.table);
    for (const r of ch.rules) {
      if (kept) recreated++; else dropped++;
      if (r.pkts == null) continue;
      counting++;
      packets += r.pkts;
    }
  }

  const touched = chains.filter((c) => c.create.length || c.destroy.length || c.change.length);
  return {
    chains,
    touched,
    /* what the tables lose regardless of whether anything differs */
    recreated,
    counting,
    packets,
    dropped,
    droppedTables,
    tables: [...new Set(theirs.filter((c) => ours.has(c.table)).map((c) => c.table))],
    identical: !touched.length,
  };
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
