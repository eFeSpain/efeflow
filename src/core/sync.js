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
import { ruleLine, UID, ruleText } from "./model.js";
import { diffLines } from "./diff.js";

const key = (ch) => `${ch.table}/${ch.id}`;
const text = ruleText;

/**
 * Pair one chain's rules with the host's.
 * @returns {{pairs, onlyModel, onlyHost}} pairs carry `by`, which is the whole
 *          point: only "handle" is strong enough to act on.
 */
export function pairChain(mine, theirs, { active = false } = {}) {
  const pairs = [], onlyModel = [], onlyHost = [];
  const hostLeft = (theirs?.rules || []).map((r, i) => ({ r, i }));

  /* `active` is the difference between two questions that are not the same
     one: how do these documents differ, and what will this apply do.
     generate.js emits only the rules that are switched on, so a rule you
     unticked is a rule that will not be there afterwards — and pairing it with
     the host's copy made it read as unchanged. Measured: switch one rule off
     and the apply screen said `identical: true, keep: 2, destroy: 0` while
     applying would have deleted it from the firewall.

     The index stays the model's own, because addressable() addresses by it. */
  const mineAll = (mine?.rules || [])
    .map((r, i) => ({ r, i }))
    .filter((x) => !active || x.r.on);

  /* handles first, and across the whole chain — a rule that moved still is
     the rule it was */
  const byHandle = new Map();
  for (const h of hostLeft) if (h.r.handle) byHandle.set(h.r.handle, h);

  const takenHost = new Set();
  const mineLeft = [];
  for (const { r, i } of mineAll) {
    const hit = r.handle && byHandle.get(r.handle);
    if (hit && !takenHost.has(hit.i)) {
      takenHost.add(hit.i);
      pairs.push({ i, r, hostRule: hit.r, hostIndex: hit.i, by: "handle",
                   same: text(r) === text(hit.r) });
    } else mineLeft.push({ r, i });
  }

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
    const r = pairChain(ch, other, { active: true });
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
                    create: ch.rules.filter((r) => r.on), destroy: [], drift: [], change: [], keep: 0 });
      continue;
    }
    const r = pairChain(ch, other, { active: true });
    const destroy = r.onlyHost.map((x) => x.r);
    /* A host rule with no partner is a deletion — but not always drift. A rule
       you switched off is still in your model, filtered out of the pairing by
       `active`, so its host copy lands here looking exactly like a rule that
       appeared behind your back. It is not: it is one you chose to remove, and
       warning about it the way you warn about a fail2ban ban somebody is about
       to wipe is the boy crying wolf on the one screen that must not.
       `drift` is the honest subset — destroyed rules that match nothing you
       hold, disabled ones included — which is what a drift warning is for. */
    const knownText = new Set(ch.rules.map((x) => text(x)));
    chains.push({
      key: key(ch), table: ch.table, chain: ch.id, isNew: false,
      create: r.onlyModel.map((x) => x.r),
      destroy,
      drift: destroy.filter((hr) => !knownText.has(text(hr))),
      change: r.pairs.filter((p) => !p.same).map((p) => ({ from: p.hostRule, to: p.r })),
      keep: r.pairs.filter((p) => p.same).length,
    });
  }
  /* a chain the host has inside a table we are replacing goes with the table */
  for (const ch of theirs)
    if (!seen.has(key(ch)))
      /* A whole chain the host has and the model does not: every rule of it is
         gone after this, and none is one you hold — so all of it is drift. */
      chains.push({ key: key(ch), table: ch.table, chain: ch.id, isGone: true,
                    create: [], destroy: ch.rules, drift: ch.rules, change: [], keep: 0 });

  /* The part a diff cannot say. Every rule in a table that gets deleted and
     rebuilt is a new rule to the kernel, whatever its text says.

     Two different fates, and calling both "rebuilt" would flatter the worse
     one. A table this project has is deleted and put back: the rules survive
     as text and lose their handles and counters. A table only the host has —
     Docker's, under `flush ruleset` — is deleted and not put back at all.

     `tables` first and `model.chains` only as the fallback: a table of ours
     holding nothing but a set — or nothing but a comment and a flag — has no
     chain to be found by, and was reported as "not yours and not rebuilt" on
     the same screen that had just promised to replace it. The scope list is
     what the apply names, so it is what decides. */
  const ours = new Set(tables || (model?.chains || []).map((c) => c.table));
  let recreated = 0, counting = 0, packets = 0, dropped = 0;
  const droppedTables = [];
  for (const ch of theirs) {
    const kept = ours.has(ch.table);
    if (!kept && !droppedTables.includes(ch.table)) droppedTables.push(ch.table);
    for (const r of ch.rules) {
      if (kept) recreated++; else dropped++;
      /* `ctr` is whether the rule counts at all; `pkts` is what it has counted
         so far, and parseRule gives every rule a zero rather than a null. So
         `pkts == null` was never true and this counted every rule in the
         table — the screen quoted twice the counters it was about to reset. */
      if (!(r.ctr || r.pkts)) continue;
      counting++;
      packets += r.pkts || 0;
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
 * Null unless the pairing was made by handle and the chain holds nothing else
 * that has drifted. That second condition is the one that matters: a handle is
 * a position in somebody else's kernel, and acting on one while the chain
 * around it has moved is how you delete a rule you never looked at.
 *
 * `op` because the two operations do not want the same guarantee, and
 * demanding one of them for both made the other impossible. Deleting a rule is
 * a claim that the thing you are looking at is the thing on the host, so its
 * text has to still agree. Replacing one is a claim that it should stop
 * agreeing — the caller edited it, which is the entire point — so requiring
 * the texts to match meant `replace` returned null after every edit and
 * succeeded only when there was nothing to send. The button that changes one
 * rule of a running firewall could not change one rule of a running firewall.
 *
 * What that costs, said out loud: if somebody else replaced this exact rule in
 * place since it was read, its handle is unchanged and nothing here can tell
 * their edit from yours, so yours wins. Nothing in the model records what the
 * host said at the time — line numbers live beside the model rather than on
 * the rules for the same reason, and a per-rule snapshot would ride into every
 * saved project and undo step. The apply screen's diff is where that kind of
 * drift is meant to be seen.
 */
export function addressable(model, host, ch, i, op = "delete") {
  const other = (host?.chains || []).find((c) => key(c) === key(ch));
  if (!other) return null;
  const r = pairChain(ch, other);
  if (r.onlyHost.length || r.onlyModel.length) return null;
  const p = r.pairs.find((x) => x.i === i);
  if (!p || p.by !== "handle") return null;
  return op === "replace" || p.same ? p.hostRule.handle : null;
}

export { key as chainKey, UID };
