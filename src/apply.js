/* Putting a ruleset on a machine, and being able to change your mind.
 *
 * This is the one operation in eFeFlow that can lock somebody out of a host,
 * and the shape of that failure is particular: the rule that cuts you off is
 * the rule that stops you undoing it. A rollback button in this window is no
 * use, because the window is on the wrong side of the firewall it just broke.
 *
 * So the net is armed on the host before anything is applied — a copy of the
 * running ruleset and a detached timer that puts it back unless it is told not
 * to. Losing the connection, the window, or the laptop restores. Keeping the
 * new ruleset is a deliberate act, which is the right way round for this.
 *
 * The ordering is the whole of the safety, so it lives here rather than in a
 * click handler where it cannot be tested: arm, then apply, and take the net
 * down again if the apply never happened — an armed rollback with nothing to
 * roll back would restore the ruleset over whatever the user did next. */

import * as nativeApi from "./native.js";
import { parseNft } from "./core/parse.js";
import { surgicalPlan } from "./core/surgical.js";

/**
 * The changes, if they can be sent as changes, or a reason they cannot.
 *
 * The whole-table apply rebuilds every rule in the tables it names, so every
 * counter in them goes to zero — including the rules nobody edited. When the
 * difference is only rules, nftables can be told about exactly those, and
 * everything else keeps its handle and its numbers. Measured on nft 1.1.3:
 * changing one rule of a five-rule chain this way left 34 packets of history
 * standing where the whole-table apply left none.
 *
 * Read fresh, and here rather than in the caller, because the commands address
 * rules by handle: a handle is a position in somebody else's kernel, and one
 * read a minute ago is a guess. If the reading is stale anyway, `nft -c`
 * refuses the file before a byte of it is written — checked on a live kernel.
 *
 * @returns {{ok:true, commands, ...counts}} | {{ok:false, why, detail}}
 */
export async function surgicalChanges({ model, target, tables, api = nativeApi }) {
  const r = await api.nftList(target);
  if (!r.ok) return { ok: false, why: "unreadable", detail: (r.stderr || r.stdout || "").trim() };
  return surgicalPlan(model, parseNft(r.stdout), { tables });
}

/**
 * @param seconds  how long the host waits before restoring. 0 arms nothing,
 *                 which is a choice the caller has to make explicitly.
 * @param api      injectable so the ordering can be tested without a host
 * @returns {ok, stage, error, armed, backup, seconds}
 */
export async function applyWithNet({ ruleset, target, seconds = 60, api = nativeApi }) {
  const net = seconds > 0;
  let backup = null;

  /* Whether this host already had a restore counting down before we touched
     it. `nft_arm` deliberately keeps an existing copy and only replaces the
     token, which retires whatever timer was watching — so if our apply then
     fails and we disarm, both timers are gone and the machine is left with no
     net at all, by an operation that changed nothing. Somebody else's
     countdown is not ours to cancel. */
  const wasArmed = net && (await api.nftArmed(target)).stdout?.trim() === "armed";

  if (net) {
    const armed = await api.nftArm(seconds, target);
    if (!armed.ok)
      return { ok: false, stage: "arm", error: text(armed) };
    backup = armed.stdout;
  }

  /* nft_apply validates before it writes and refuses without confirmation;
     both of those are the far side's job, not something to re-implement here */
  const applied = await api.nftApply(ruleset, target, true);
  if (!applied.ok) {
    /* Nothing was written, so our own arming has nothing to undo — but the
       sentinel is the only thing keeping an *earlier* countdown alive, and
       removing it strands a host that was already waiting to be restored.

       So it is left alone, and the honest cost of that is that our timer
       fires instead of theirs: sooner, perhaps, and it reloads a copy the
       kernel is already running, which resets that ruleset's counters. Both
       of those are worth paying to not leave a firewall with no net on it. */
    if (net && !wasArmed) await api.nftDisarm(target);
    return { ok: false, stage: "apply", error: text(applied), armed: false, wasArmed };
  }
  return { ok: true, armed: net, backup, seconds };
}

/** Keep what is running: the scheduled restore finds no sentinel and expires. */
export async function keep({ target, api = nativeApi }) {
  const r = await api.nftDisarm(target);
  return { ok: r.ok, error: text(r) };
}

/** Put the previous ruleset back now, rather than waiting for the timer. */
export async function rollBackNow({ target, api = nativeApi }) {
  const r = await api.nftRollback(target);
  return { ok: r.ok, error: text(r) };
}

/** Did a previous session leave a rollback pending on this host? */
export async function pendingRollback({ target, api = nativeApi }) {
  const r = await api.nftArmed(target);
  return r.ok && r.stdout.trim() === "armed";
}

const text = (o) => (o.stderr || o.stdout || "").trim();
