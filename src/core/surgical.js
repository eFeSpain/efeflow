/* Sending the changes instead of sending the ruleset.
 *
 * The apply this application has always done is `delete table X` and put it
 * back. It is atomic and it is correct, and it costs the whole table: every
 * rule in it is a new rule to the kernel, so every handle is assigned afresh
 * and every counter goes to zero — including the rules nobody edited. Change
 * one line of a firewall that has been up for a month and you lose a month of
 * numbers from all of it.
 *
 * nftables can do better, and the reason this was deferred rather than
 * refused is that doing it wrong is worse than not doing it: a half-applied
 * chain is a firewall in a state nobody designed. Four things were measured on
 * a live kernel (nft 1.1.3, Debian 13) before any of this was written, because
 * each of them decides whether the idea is safe at all:
 *
 *   1. A file of `replace`/`delete`/`insert`/`add` commands is ONE transaction.
 *      One bad line among three good ones left the ruleset byte for byte as it
 *      was. So there is no intermediate state to be caught in.
 *
 *   2. `nft -c -f -` validates such a file against the live ruleset, and a
 *      handle that no longer exists is refused there — before anything is
 *      written. The check already in nft_apply covers this for free.
 *
 *   3. A rule nobody touched keeps its handle AND its counter. A replaced rule
 *      keeps its handle and loses its counter, even when replaced with
 *      identical text. That is the whole prize: only what changed is reset.
 *
 *   4. `insert ... position H` places a rule immediately before the rule with
 *      handle H, and several inserts against the same anchor come out in the
 *      order they were issued. So emitting in model order is enough.
 *
 * What this deliberately does not do is anything except rules. A chain that
 * appeared or went, a set whose elements moved, a changed policy — each of
 * those has its own nft grammar and its own failure modes, and guessing at
 * them here would trade a known-good apply for an interesting one. When
 * anything but rules differs, this says so and the caller falls back to the
 * apply that always works.
 */
import { pairChain, chainKey } from "./sync.js";
import { ruleLine } from "./model.js";

const text = (r) => ruleLine(r) + (r.cmt ? ` comment "${r.cmt}"` : "");

/** Why the whole-table apply is still the one to use. */
const no = (why, detail) => ({ ok: false, why, detail });

/**
 * The changes, as nft commands, or a reason this cannot be expressed as some.
 *
 * @param tables the tables the apply covers. Anything outside them is not
 *        being replaced and so is not being compared.
 * @returns {{ok:true, commands, replaced, deleted, inserted, kept, keptCounters}}
 *        | {{ok:false, why, detail}}
 */
export function surgicalPlan(model, host, { tables } = {}) {
  const inScope = tables ? (c) => tables.includes(c.table) : () => true;
  const mine = (model?.chains || []).filter(inScope);
  const theirs = (host?.chains || []).filter(inScope);

  /* A table we are about to create has nothing to be surgical about. */
  const hostTables = new Set(theirs.map((c) => c.table));
  for (const t of new Set(mine.map((c) => c.table)))
    if (!hostTables.has(t)) return no("table-new", t);

  const byKey = new Map(theirs.map((c) => [chainKey(c), c]));
  for (const ch of mine)
    if (!byKey.has(chainKey(ch))) return no("chain-new", chainKey(ch));
  const mineKeys = new Set(mine.map(chainKey));
  for (const ch of theirs)
    if (!mineKeys.has(chainKey(ch))) return no("chain-gone", chainKey(ch));

  /* What a chain *is* — its hook, its priority, its policy — is not a rule and
     is not changed by any command below. A base chain whose policy went from
     accept to drop needs the chain replaced, and that is the other apply. */
  for (const ch of mine) {
    const other = byKey.get(chainKey(ch));
    for (const [k, what] of [["type", "type"], ["hook", "hook"], ["prio", "priority"],
                             ["policy", "policy"], ["dev", "device"]])
      if ((ch[k] ?? null) !== (other[k] ?? null))
        return no("chain-changed", `${chainKey(ch)} · ${what}`);
  }

  /* Sets, maps and named objects are addressed by name and edited by their own
     grammar. Comparing them properly is a feature of its own; noticing that
     they differ is enough to hand this back.

     By what they hold, not by `body`, which is a list of which lines a set
     declares and says nothing about what is in them: comparing that missed an
     elements list changing entirely — the exact silence this guard exists to
     prevent, and it took a test failing on its own fixture to find it. `seq`
     is left out because where a set sits among its siblings changes what the
     file looks like and not what the firewall does. */
  const shape = (xs, f) => (xs || []).map(f).sort().join("\n");
  const setsOf = (m) => shape((m?.sets || []).filter((s) => !tables || tables.includes(s.table)),
    (s) => JSON.stringify([s.table, s.kind, s.n, s.t, s.f,
                           [...(s.el || [])].sort(), s.attr || null]));
  const objsOf = (m) => shape((m?.objects || []).filter((o) => !tables || tables.includes(o.table)),
    (o) => JSON.stringify([o.table, o.kind, o.name, o.body]));
  if (setsOf(model) !== setsOf(host)) return no("sets-differ");
  if (objsOf(model) !== objsOf(host)) return no("objects-differ");

  const commands = [];
  let replaced = 0, deleted = 0, inserted = 0, kept = 0, keptCounters = 0;

  for (const ch of mine) {
    const other = byKey.get(chainKey(ch));
    const where = `${ch.table} ${ch.id}`;
    const r = pairChain(ch, other, { active: true });

    /* Pairing is by handle and so says nothing about order: the same rules
       moved around read as every one of them unchanged. Sending nothing while
       the order differs would be the worst answer available, so the relative
       order of the pairs has to still hold. */
    const seq = [...r.pairs].sort((a, b) => a.i - b.i).map((p) => p.hostIndex);
    for (let i = 1; i < seq.length; i++)
      if (seq[i] < seq[i - 1]) return no("reordered", chainKey(ch));

    /* An anchor for a new rule is the host handle of the next rule of ours
       that the host already has. Positions are all read from the ruleset as it
       is now, which is safe because inserting never renumbers what is there. */
    const anchorAfter = (i) => {
      const next = r.pairs.filter((p) => p.i > i).sort((a, b) => a.i - b.i)[0];
      return next?.hostRule?.handle ?? null;
    };

    for (const p of r.pairs) {
      if (p.same) { kept++; keptCounters += (p.hostRule.pkts || 0) > 0 ? 1 : 0; continue; }
      /* A pair made by text has no handle to address, and one that differs
         cannot have been made by text — but it is not this file's business to
         rely on that. */
      if (p.by !== "handle" || !p.hostRule.handle) return no("unaddressable", chainKey(ch));
      commands.push(`replace rule ${where} handle ${p.hostRule.handle} ${text(p.r)}`);
      replaced++;
    }

    for (const x of r.onlyHost) {
      if (!x.r.handle) return no("unaddressable", chainKey(ch));
      commands.push(`delete rule ${where} handle ${x.r.handle}`);
      deleted++;
    }

    for (const x of [...r.onlyModel].sort((a, b) => a.i - b.i)) {
      const at = anchorAfter(x.i);
      commands.push(at === null
        ? `add rule ${where} ${text(x.r)}`
        : `insert rule ${where} position ${at} ${text(x.r)}`);
      inserted++;
    }
  }

  if (!commands.length) return no("nothing-to-do");
  return { ok: true, commands, replaced, deleted, inserted, kept, keptCounters };
}
