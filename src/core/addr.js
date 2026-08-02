/* Addresses, in both families.
 *
 * This used to be two lines inside the evaluator — a 32-bit shift and a mask —
 * which is a complete answer for IPv4 and no answer at all for IPv6. The
 * consequence was not that v6 rules were approximated: `ip6 saddr` was not
 * recognised as an address match at all, so a rule reading
 *
 *   ip6 saddr 2001:db8::/32 drop
 *
 * dropped a packet from 8.8.8.8. That is the same shape of failure as an
 * interface constraint that matches every interface — the filter silently does
 * something much larger than it says.
 *
 * BigInt rather than a pair of 64-bit halves: 128 bits of address arithmetic
 * happens once per rule per simulated packet, and clarity is worth more here
 * than the microseconds. */

export const BITS = { 4: 32n, 6: 128n };

/* A colon is the only thing that separates the two notations. */
export const family = (a) => (String(a ?? "").includes(":") ? 6 : 4);

export function v4(a) {
  const m = String(a ?? "").trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const o = m.slice(1).map(Number);
  if (o.some((x) => x > 255)) return null;
  return o.reduce((n, x) => (n << 8n) | BigInt(x), 0n);
}

export function v6(a) {
  const s = String(a ?? "").trim().replace(/^\[/, "").replace(/\]$/, "");
  if (!s.includes(":") || !/^[0-9a-fA-F:.]+$/.test(s)) return null;

  const halves = s.split("::");
  if (halves.length > 2) return null;

  /* each token is a hex group, or a dotted quad standing for the last two */
  const expand = (part) => {
    const out = [];
    for (const tok of part ? part.split(":") : []) {
      if (tok === "") continue;
      if (tok.includes(".")) {
        const n = v4(tok);
        if (n === null) return null;
        out.push(Number(n >> 16n) & 0xffff, Number(n & 0xffffn));
      } else {
        if (!/^[0-9a-fA-F]{1,4}$/.test(tok)) return null;
        out.push(parseInt(tok, 16));
      }
    }
    return out;
  };

  const head = expand(halves[0]);
  const tail = halves.length === 2 ? expand(halves[1]) : [];
  if (head === null || tail === null) return null;

  let groups;
  if (halves.length === 2) {
    const fill = 8 - head.length - tail.length;
    if (fill < 0) return null;
    groups = [...head, ...Array(fill).fill(0), ...tail];
  } else {
    if (head.length !== 8) return null;
    groups = head;
  }
  return groups.reduce((n, g) => (n << 16n) | BigInt(g), 0n);
}

/* Parsing the same address over and over is where the analyser's time went.
 *
 * Shadowing asks whether one criterion covers another, and a criterion is
 * often a set: `ip saddr @blocked` against a set of 200 prefixes re-parsed
 * every one of them, for every pair of rules, from the dotted string up. On a
 * thousand-rule ruleset that was almost the whole second an edit cost. A
 * profile said so — v4(), looksLikeAddr() and inCidr() were the top four
 * entries and the shadowing logic itself did not appear.
 *
 * These are pure functions of a string, so the answer never goes stale. The
 * cap is there because a long editing session invents new strings as you type,
 * and an unbounded cache in a program that stays open for a day is a leak with
 * good manners. */
const PARSED = new Map();
const CAP = 20000;

export function toBig(a) {
  const s = String(a ?? "").trim();
  const hit = PARSED.get(s);
  if (hit !== undefined) return hit;
  const val = family(s) === 6 ? v6(s) : v4(s);
  if (PARSED.size >= CAP) PARSED.clear();
  PARSED.set(s, val);
  return val;
}

/* Is `ip` inside `spec`? `spec` is an address or a prefix, in either family.
   An address of one family is never inside a prefix of the other — which is
   the whole reason an inet table spells out `ip saddr` and `ip6 saddr`. */
export function inCidr(ip, spec) {
  const s = String(spec ?? "").trim();
  if (!s.includes("/")) {
    const a = toBig(ip), b = toBig(s);
    return a !== null && b !== null && family(ip) === family(s) ? a === b : String(ip) === s;
  }

  const cut = s.lastIndexOf("/");
  const net = s.slice(0, cut), len = s.slice(cut + 1);
  const fam = family(net);
  if (family(ip) !== fam) return false;

  const a = toBig(ip), b = toBig(net);
  if (a === null || b === null || !/^\d+$/.test(len)) return false;

  const bits = BigInt(len);
  if (bits < 0n || bits > BITS[fam]) return false;
  const shift = BITS[fam] - bits;
  return a >> shift === b >> shift;
}

/* Does `a` cover the whole of `b`? Both may be an address or a prefix.
 *
 * The analyser's question, and a different one from inCidr's: `b` is a range
 * rather than a point, so it is not enough that b's network address falls
 * inside a — a has to be at least as broad. Comparing the network addresses
 * alone had 10.1.0.0/16 covering 10.1.0.0/8, which is backwards.
 *
 * Answers false for anything that is not an address, so a caller can hand it
 * ports and interface names without checking first. */
export function covers(a, b) {
  const A = prefix(a), B = prefix(b);
  if (!A || !B || A.fam !== B.fam || A.bits > B.bits) return false;
  return inCidr(B.net, a);
}

function prefix(spec) {
  const s = String(spec ?? "").trim();
  const cut = s.lastIndexOf("/");
  const net = cut < 0 ? s : s.slice(0, cut);
  if (toBig(net) === null) return null;
  const fam = family(net);
  if (cut >= 0 && !/^\d+$/.test(s.slice(cut + 1))) return null;
  const bits = cut < 0 ? BITS[fam] : BigInt(s.slice(cut + 1));
  return bits < 0n || bits > BITS[fam] ? null : { fam, net, bits };
}

/* Does this token look like an address or a prefix at all? Set elements are a
   mixture of addresses, ports and names, and only the first kind is worth
   handing to inCidr. */
export const looksLikeAddr = (t) => {
  const s = String(t ?? "").trim().split("/")[0];
  return toBig(s) !== null;
};
