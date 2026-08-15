/* The simulator, read backwards.
 *
 * The forward run answers "what happens to this packet". This answers "what
 * would have to change for it to be accepted, and where" — and it does it the
 * only honest way there is, by deriving from the forward run's own trace rather
 * than guessing. evaluate() already knows the exact path the packet takes and
 * the exact thing that stops it; the prescription is that thing, named, plus
 * the one rule that would sit in front of it.
 *
 * Two properties carry the ethos of the rest of core/:
 *
 *   It cannot lie about certainty. The forward run says `sure`/`unsure` — a
 *   trace that assumed a `meta mark` or an `fib` lookup rather than reading it.
 *   The prescription inherits that word untouched: a rule derived off an
 *   assumed trace is itself an assumption, and says so.
 *
 *   It does not have to be perfect, because it is checkable. The caller inserts
 *   the rule and runs the forward simulation again; if the derivation was
 *   wrong, the re-run shows the packet still dropped, in the same panel, rather
 *   than this file claiming a success nobody verified. That is the same
 *   discipline the shadowed-rule fix uses — propose, then prove.
 *
 * And it does that proof itself, ahead of the caller: `sideEffects` inserts the
 * rule transiently and re-simulates witness packets, so the prescription can
 * say not only "this makes your packet pass" but "and here are the other
 * sources it lets in", or that it found none. Pass {probe:false} to skip it.
 *
 * Pure: it reads MODEL through evaluate() and returns a description. It leaves
 * MODEL exactly as it found it. Applying the prescription is the UI's job,
 * through edit().
 */
import { family } from "./addr.js";
import { evaluate } from "./simulate.js";

/* ── proving the prescription, not just proposing it ─────────────────────────
 *
 * A rule that makes the target packet pass can, sitting where it sits, change
 * the fate of packets nobody asked about — the classic over-broad accept that
 * lets in a whole subnet on a port. The forward run cannot see that on its own.
 * This does, the only honest way it can: it inserts the rule for real — but
 * transiently, restoring the ruleset before it returns — and re-simulates a
 * spread of witness packets built from the target.
 *
 * The witnesses vary one thing: the address the rule is about (the source on
 * the way in, the destination on the way out). That is deliberate. Admitting
 * the *same* host and service in another state or source port is what the user
 * asked for — it is one flow — so probing those would be noise. Admitting a
 * source nobody named is the side effect that matters, and it is the one a
 * source-broad rule produces. A witness whose verdict moves from blocked to
 * accepted is a source the rule newly lets in.
 *
 * It can only falsify safety, never prove it: the witnesses are a sample of the
 * address space, not the whole of it, so an empty result is "no other source
 * newly admitted among N probes", never "safe". That is the same refusal to
 * overclaim that sure/unsure makes in the forward run. */
const SAMPLE4 = ["10.0.0.9", "172.16.0.9", "192.168.0.9", "100.64.0.9",
                 "203.0.113.9", "198.51.100.9", "192.0.2.9", "8.8.8.9"];
const SAMPLE6 = ["2001:db8::9", "2001:db8:1::9", "fe80::9"];

/* Witness packets: the target first, then the same packet with the address the
   rule is about swapped for one that is not the target's, across a spread of
   ranges a blocking rule might single out. */
function witnesses(p, key) {
  const cur = p[key];
  const fam = cur ? family(cur) : null;
  const pool = [
    ...(fam === 6 || fam === null ? SAMPLE6 : []),
    ...(fam === 4 || fam === null ? SAMPLE4 : []),
  ].filter(a => a !== cur).slice(0, 8);

  const clone = () => ({ ...p, flags: [...(p.flags || [])] });
  const side = key === "saddr" ? "source" : "destination";
  return [
    { ...clone(), _probe: "target" },
    ...pool.map(a => ({ ...clone(), [key]: a, _probe: `${side} ${a}`, _addr: a })),
  ];
}

const verdictOf = res => res.final?.v || "accept";

/* Insert the rule where prescribe would, re-simulate every witness, and return
   the ones whose verdict the insertion moved — restoring the chain either way.
   Pure to the caller: the array is the same length it was on entry. */
function sideEffects(input, chain, at, ruleObj, key) {
  if (!chain || !Array.isArray(chain.rules)) return null;
  const ws = witnesses(input, key);
  const before = ws.map(w => verdictOf(evaluate(w)));

  chain.rules.splice(at, 0, ruleObj);
  let after;
  try { after = ws.map(w => verdictOf(evaluate(w))); }
  finally { chain.rules.splice(at, 1); }

  const admits = [];
  for (let k = 1; k < ws.length; k++)
    if (before[k] !== after[k] && after[k] === "accept")
      admits.push({ addr: ws[k]._addr, what: ws[k]._probe, was: before[k] });

  return { probed: ws.length - 1, targetAccepted: after[0] === "accept", admits };
}

/* The clauses that pin this packet down, in the order and shape a person would
   write them, built from the packet as it flows when it reaches the deciding
   chain — post-NAT if NAT rewrote it, because that is what the rule there sees.
   Enough to be a real rule and not `accept` everything; the user widens or
   narrows it from there. */
function matchClauses(p, egress) {
  const out = [];
  const iface = egress ? p.oif : p.iif;
  if (iface) out.push(`${egress ? "oifname" : "iifname"} "${iface}"`);

  const addr = egress ? p.daddr : p.saddr;
  if (addr) out.push(`${family(addr) === 6 ? "ip6" : "ip"} ${egress ? "daddr" : "saddr"} ${addr}`);

  /* a transport with a port is the service; icmp has none */
  if (/^(tcp|udp|sctp)$/.test(p.proto) && p.dport) out.push(`${p.proto} dport ${p.dport}`);
  else if (p.proto) out.push(`meta l4proto ${p.proto}`);

  return out;
}

/**
 * @returns one of:
 *   { already: true }                       the packet is accepted as it is
 *   { chain, at, rule, blocker, verdict, sure, unsure }
 *       chain    the chain the rule goes in — the one that decides the packet
 *       at       the index to insert at: before the rule that stops it, or at
 *                the end (before the policy) when nothing matched
 *       rule     the nft expression to insert, ending in `accept`
 *       blocker  what decides it now: {policy} or {i, rule}
 *       verdict  what it does now (drop/reject)
 *       sure     false if the trace assumed anything on the way to the verdict
 *       sideEffects  {probed, targetAccepted, admits[]} from re-simulation, or
 *                    null when {probe:false}. `admits` is the sources the rule
 *                    newly lets in besides the target — empty when none found.
 */
export function prescribe(input, { probe = true } = {}) {
  const res = evaluate(input);
  /* Accepted covers the empty ruleset too: nothing stops the packet, so its
     verdict is accept and its deciding chain is null — either way, no rule is
     needed. A packet that is *not* accepted always has a chain that stopped
     it, which is why what follows can rely on one. */
  if (res.final.v === "accept") return { already: true };

  const chain = res.final.chain;
  const egress = chain.hook === "output" || chain.hook === "postrouting";
  const clauses = matchClauses(res.packet, egress);
  const rule = clauses.length ? `${clauses.join(" ")} accept` : "accept";
  const at = res.final.policy ? chain.rules.length : res.final.i;

  return {
    chain,
    at,
    rule,
    blocker: res.final.policy
      ? { policy: chain.policy }
      : { i: res.final.i, rule: res.final.r },
    verdict: res.final.v,
    sure: res.sure,
    unsure: res.unsure,
    sideEffects: probe
      ? sideEffects(input, chain, at,
          { expr: clauses.join(" "), verdict: "accept", on: true },
          egress ? "daddr" : "saddr")
      : null,
  };
}
