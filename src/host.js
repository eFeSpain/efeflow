/* Talking to the host about a ruleset that is already running on it.
 *
 * Everything else in this application reasons about a ruleset as a document.
 * These three ask the machine, and they are the same question with rising
 * stakes: where do these counters go, has this drifted under me, and may I
 * change exactly this one rule.
 *
 * core/sync.js answers the question. This decides what to do about the answer,
 * and — as with src/apply.js — it lives apart from the click handlers so the
 * order and the refusals can be tested without a host. */

import * as nativeApi from "./native.js";
import { parseNft } from "./core/parse.js";
import { applyCounters, syncReport, applyPlan, addressable } from "./core/sync.js";
import { ruleLine } from "./core/model.js";

const read = async (target, api) => {
  const r = await api.nftList(target);
  if (!r.ok) return { ok: false, error: (r.stderr || r.stdout || "").trim() };
  return { ok: true, host: parseNft(r.stdout) };
};

/**
 * Bring the packet and byte figures up to date.
 *
 * The counters shown on every rule came from the text of the import and have
 * been frozen there ever since — the guide said so, which made it honest and
 * not useful. Nothing in the generated source changes, so this is a read: no
 * history entry, no unsaved-changes dot.
 */
export async function refreshCounters({ model, target, api = nativeApi }) {
  const r = await read(target, api);
  if (!r.ok) return r;
  const updated = applyCounters(model, r.host);
  /* A zero means two entirely different things, and the difference is the
     whole value of reading them. Before a host has been asked, every rule
     reads zero because nothing has ever counted. Afterwards, a rule that
     counts and still reads zero has matched nothing since the ruleset was
     loaded — which is a fact about your firewall, not about this window.
     Recorded on the model and not in it: `snapshot()` and `serialise()` both
     name the keys they take, so this rides in neither undo nor a project
     file, which is right for something observed rather than authored. */
  model.counters = { at: Date.now(), updated };
  return { ok: true, updated, host: r.host };
}

/**
 * Has the host changed under us?
 *
 * The scoped apply only replaces the tables this project owns, which keeps
 * Docker's out of it — but inside your own table, twenty rules added by
 * fail2ban while you were editing are invisible, and the apply takes them with
 * it. This is the look before that.
 */
export async function checkDrift({ model, target, tables, api = nativeApi }) {
  const r = await read(target, api);
  if (!r.ok) return r;
  /* `at` because a diff of a firewall is a photograph, and one taken before
     the last thing somebody did to that machine is worse than none. */
  return {
    ok: true,
    ...syncReport(model, r.host, { tables }),
    plan: applyPlan(model, r.host, { tables }),
    host: r.host,
    at: Date.now(),
  };
}

/**
 * Change one rule on the host, addressed by its handle.
 *
 * Refused unless the host still agrees about the chain the rule is in: a
 * handle is a position in somebody else's kernel, and acting on one after the
 * chain has moved is how you delete a rule you never looked at. The check is
 * made against a reading taken now, not against whatever was read at import.
 */
export async function pushRule({ model, chain, index, op, target, api = nativeApi }) {
  const r = await read(target, api);
  if (!r.ok) return r;

  const handle = addressable(model, r.host, chain, index, op);
  if (handle === null)
    return { ok: false, error: "unaddressable",
             why: "the host no longer agrees about this chain" };

  const rule = chain.rules[index];
  const out = await api.nftRuleOp({
    op,
    table: chain.table,
    chain: chain.id,
    handle,
    rule: op === "replace" ? ruleLine(rule) + (rule.cmt ? ` comment "${rule.cmt}"` : "") : "",
  }, target);

  return out.ok
    ? { ok: true, handle }
    : { ok: false, error: (out.stderr || out.stdout || "").trim() };
}
