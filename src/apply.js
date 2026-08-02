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

/**
 * @param seconds  how long the host waits before restoring. 0 arms nothing,
 *                 which is a choice the caller has to make explicitly.
 * @param api      injectable so the ordering can be tested without a host
 * @returns {ok, stage, error, armed, backup, seconds}
 */
export async function applyWithNet({ ruleset, target, seconds = 60, api = nativeApi }) {
  const net = seconds > 0;
  let backup = null;

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
    if (net) await api.nftDisarm(target);
    return { ok: false, stage: "apply", error: text(applied), armed: false };
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
