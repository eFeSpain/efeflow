/* The things a table holds that are neither chains nor sets.
 *
 * flowtables, named counters and quotas, ct helpers and timeouts, synproxies.
 * The parser has carried them verbatim for a while, which meant a ruleset with
 * one survived a round trip and could not be touched: you could look at your
 * offload flowtable and not add a device to it.
 *
 * Same shape of answer as the rule editor. Typed fields for the four kinds
 * people reach for, the body kept as the source of truth underneath, and every
 * other kind — including ones nftables has not shipped yet — editable as the
 * text it already was. Nothing here rebuilds a body: a field finds its own
 * fragment and rewrites that, so a line nothing models is a line nothing
 * touches. */

const tidy = (s) => s.replace(/[ \t]{2,}/g, " ").trim();

/* Replace a fragment, remove it, or add it as a new line if it was not there. */
function splice(body, re, text) {
  const joined = body.join("\n");
  const m = joined.match(re);
  if (!m) return text ? [...body, text] : body;
  const out = joined.slice(0, m.index) + text + joined.slice(m.index + m[0].length);
  return out.split("\n").map(tidy).filter(Boolean);
}

/* What each kind is asked for by name. Everything not listed is text only. */
export const OBJECT_FIELDS = {
  flowtable: ["hook", "priority", "devices"],
  counter: ["packets", "bytes"],
  quota: ["mode", "amount", "unit"],
  "ct helper": ["type", "protocol"],
};

/* A skeleton nft will take, naming nothing that is not the user's — a
   flowtable arrives with no device for the same reason a dnat arrives with no
   address. The editor refuses to save it until you say which. */
export const OBJECT_TEMPLATE = {
  flowtable: ["hook ingress priority filter", "devices = { }"],
  counter: ["packets 0 bytes 0"],
  quota: ["over 1 mbytes"],
  "ct helper": ['type "ftp" protocol tcp'],
  "ct timeout": ["protocol tcp", "policy = { established: 3600 }"],
  synproxy: ["mss 1460", "wscale 7"],
};

export const OBJECT_KINDS = Object.keys(OBJECT_TEMPLATE);

const RE = {
  hook: /\bhook\s+(\w+)/,
  priority: /\bpriority\s+(-?\w+)/,
  devices: /\bdevices\s*=\s*\{([^}]*)\}/,
  packets: /\bpackets\s+(\d+)/,
  bytes: /\bbytes\s+(\d+)/,
  quota: /\b(over|until)\s+(\d+)\s*(\w+)?/,
  type: /\btype\s+"([^"]*)"/,
  protocol: /\bprotocol\s+(\w+)/,
};

/** What the editor shows. Absent fields come back as "". */
export function readObject(o) {
  const body = (o?.body || []).join("\n");
  const g = (re, i = 1) => { const m = body.match(re); return m ? (m[i] ?? "").trim() : ""; };
  const q = body.match(RE.quota);
  return {
    hook: g(RE.hook),
    priority: g(RE.priority),
    devices: g(RE.devices).split(",").map((s) => s.trim()).filter(Boolean).join(", "),
    packets: g(RE.packets),
    bytes: g(RE.bytes),
    mode: q ? q[1] : "",
    amount: q ? q[2] : "",
    unit: q ? (q[3] || "") : "",
    type: g(RE.type),
    protocol: g(RE.protocol),
  };
}

/** Apply what the editor changed, and only that. Returns the new body. */
export function editObject(o, patch = {}) {
  let body = [...(o?.body || [])];
  const has = (k) => patch[k] !== undefined && patch[k] !== null;

  if (has("hook"))
    body = patch.hook ? splice(body, RE.hook, `hook ${patch.hook}`) : splice(body, RE.hook, "");
  if (has("priority"))
    body = patch.priority
      ? splice(body, RE.priority, `priority ${patch.priority}`)
      : splice(body, RE.priority, "");
  if (has("devices")) {
    const list = String(patch.devices).split(",").map((s) => s.trim()).filter(Boolean);
    body = splice(body, RE.devices, `devices = { ${list.join(", ")} }`);
  }
  if (has("packets")) body = splice(body, RE.packets, `packets ${patch.packets || 0}`);
  if (has("bytes")) body = splice(body, RE.bytes, `bytes ${patch.bytes || 0}`);
  if (has("mode") || has("amount") || has("unit")) {
    const now = readObject(o);
    const mode = has("mode") ? patch.mode : now.mode || "over";
    const amount = has("amount") ? patch.amount : now.amount || "1";
    const unit = has("unit") ? patch.unit : now.unit || "mbytes";
    body = splice(body, RE.quota, `${mode} ${amount} ${unit}`.trim());
  }
  if (has("type")) body = splice(body, RE.type, `type "${patch.type}"`);
  if (has("protocol")) body = splice(body, RE.protocol, `protocol ${patch.protocol}`);
  return body;
}

/* ── who is using it ─────────────────────────────────────────────────────
   A flowtable is reached with `flow add @name`, the rest by name in a
   statement of their own. The delete guard needs this for the same reason the
   set one does: nft refuses a rule naming an object that is not there. */
const REF_RE = {
  flowtable: (n) => new RegExp(`\\bflow\\s+(?:add|offload)\\s+@${n}\\b`),
  counter: (n) => new RegExp(`\\bcounter\\s+name\\s+"${n}"`),
  quota: (n) => new RegExp(`\\bquota\\s+name\\s+"${n}"`),
  "ct helper": (n) => new RegExp(`\\bct\\s+helper\\s+set\\s+"${n}"`),
  "ct timeout": (n) => new RegExp(`\\bct\\s+timeout\\s+set\\s+"${n}"`),
  synproxy: (n) => new RegExp(`\\bsynproxy\\s+name\\s+"${n}"`),
};

const escapeRe = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Every rule in `chains` that names this object. */
export function refsToObject(o, chains = []) {
  const make = REF_RE[o?.kind];
  if (!make || !o.name) return [];
  const re = make(escapeRe(o.name));
  const out = [];
  for (const ch of chains) {
    if (ch.table !== o.table) continue;
    ch.rules.forEach((r, i) => { if (re.test(r.expr || "")) out.push({ ch, r, i }); });
  }
  return out;
}
