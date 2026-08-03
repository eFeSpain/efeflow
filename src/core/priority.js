/* nft prints chain priorities by name; both directions are needed so an
   imported `priority filter` survives a round-trip as `priority filter`. */
export const PRIO_NAME = {
  raw: -300,
  mangle: -150,
  dstnat: -100,
  filter: 0,
  security: 50,
  srcnat: 100,
  out: 0,
};

export const NAME_PRIO = {
  "-300": "raw",
  "-150": "mangle",
  "-100": "dstnat",
  "0": "filter",
  "50": "security",
  "100": "srcnat",
};

export const prioLabel = (n) => NAME_PRIO[String(n)] || null;

/**
 * What a chain header writes after `priority`: a number, a name, or a name
 * with an offset — `filter + 10`, `srcnat + 5`, `raw - 10`. The last is how a
 * chain is ordered against a well-known one without hard-coding what that one
 * is worth, and Docker, libvirt and fail2ban all ship chains written that way.
 *
 * The header pattern used to require a bare word, so an offset did not match
 * it — and the line then fell through to the rule parser, which found `policy
 * drop;` at the end of it, recognised `drop` as a verdict and turned a chain
 * header into a rule. The chain lost its hook, so nothing ever walked it; it
 * gained a DROP nobody wrote; and the round-trip stayed at 100%, because the
 * invented rule re-emits as the line it was made from.
 *
 * @returns {{prio: number, name: string|null}} — `name` is the text as
 *   written, kept so the header goes back out the way it came in.
 */
export function readPriority(text) {
  const s = String(text ?? "").trim();
  if (/^-?\d+$/.test(s)) return { prio: +s, name: null };
  const m = s.match(/^(-?\w+)\s*([+-])\s*(\d+)$/);
  if (m && m[1] in PRIO_NAME)
    return { prio: PRIO_NAME[m[1]] + (m[2] === "-" ? -1 : 1) * +m[3], name: s };
  return { prio: PRIO_NAME[s] ?? 0, name: s };
}
