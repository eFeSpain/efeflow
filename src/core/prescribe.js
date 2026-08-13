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
 * Pure: it reads MODEL through evaluate() and returns a description. It changes
 * nothing. Applying the prescription is the UI's job, through edit().
 */
import { family } from "./addr.js";
import { evaluate } from "./simulate.js";

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
 */
export function prescribe(input) {
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

  return {
    chain,
    at: res.final.policy ? chain.rules.length : res.final.i,
    rule,
    blocker: res.final.policy
      ? { policy: chain.policy }
      : { i: res.final.i, rule: res.final.r },
    verdict: res.final.v,
    sure: res.sure,
    unsure: res.unsure,
  };
}
