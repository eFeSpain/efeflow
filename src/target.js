/* Where nft runs.
 *
 * The analyser is eFeFlow's own reading of a ruleset; `nft -c` is the
 * authority. nft only exists on Linux, so on any other desktop the only way to
 * reach the authority is the firewall itself — which is also the normal case
 * on Linux, since the box you edit on is rarely the box you filter on. */

import * as native from "./native.js";
import { t } from "./i18n.js";

import { readHosts, writeHosts, addHost, updateHost, removeHost, matching, asTarget }
  from "./core/hosts.js";

const KEY = "efeflow.target";
const HKEY = "efeflow.hosts";

export const target = { kind: "local", host: "", user: "", port: "", sudo: true };

/* The estate, not the project. Nobody administers one box, and a hostname you
   have typed a hundred times should be a thing you pick. Kept beside the
   service catalogue — on this machine, in every project — because it describes
   your world rather than the ruleset you happen to have open, and because a
   `.efeflow.json` is a file people attach to a bug report. */
export let hosts = [];

/* Passwords live here and nowhere else: in memory, for this session only, never
   in localStorage and never in the hosts file that gets shared or attached to a
   bug report. Keyed by how you reach the box, so moving between saved hosts
   mid-session does not lose them. A saved host records that it *uses* a
   password (so the form can ask for it), never the password itself. */
const passwords = new Map();
const passKey = (tg) =>
  `${(tg.user || "").toLowerCase()}@${(tg.host || "").toLowerCase()}:${tg.port || "22"}`;

export function setPassword(pass, tg = target) {
  if (tg.kind !== "ssh" || !tg.host) return;
  if (pass) passwords.set(passKey(tg), pass);
  else passwords.delete(passKey(tg));
}
export const passwordFor = (tg = target) =>
  (tg.kind === "ssh" && passwords.get(passKey(tg))) || "";
export const hasPassword = (tg = target) => !!passwordFor(tg);

export function loadTarget() {
  try {
    Object.assign(target, JSON.parse(localStorage.getItem(KEY) || "{}"));
  } catch {
    /* a corrupt entry is not worth a crash */
  }
  try {
    hosts = readHosts(localStorage.getItem(HKEY));
  } catch {
    hosts = [];
  }
  /* Whatever was in use before there was a list belongs in it. */
  if (target.kind === "ssh" && target.host && !matching(hosts, target))
    hosts = addHost(hosts, target).list;
  return target;
}

/* The desktop keeps it in the config directory as well, so it survives the
   browser store being cleared — same path the catalogue uses. */
function persistHosts() {
  const text = writeHosts(hosts);
  try { localStorage.setItem(HKEY, text); } catch { /* private mode */ }
  native.writeSetting("hosts", text).catch(() => { /* read-only profile */ });
}

/** Merge a file written on another machine into this one's list. */
export function mergeHosts(text) {
  const before = hosts.length;
  for (const h of readHosts(text)) hosts = addHost(hosts, h).list;
  if (hosts.length !== before) persistHosts();
  return hosts.length - before;
}

export function rememberHost(o) {
  const r = addHost(hosts, o);
  hosts = r.list;
  persistHosts();
  return r.host;
}

export function forgetHost(id) {
  hosts = removeHost(hosts, id);
  persistHosts();
}

export function renameHost(id, name) {
  hosts = updateHost(hosts, id, { name });
  persistHosts();
}

/** Point at one of them, by id. */
export function useHost(id) {
  const h = hosts.find((x) => x.id === id);
  return saveTarget(asTarget(h));
}

/** The entry the current target came from, if it is one of them. */
export const currentHost = () => matching(hosts, target);

export function saveTarget(patch) {
  Object.assign(target, patch);
  /* A password is session-only and lives in `passwords`, never on disk. The
     draft that comes in here carries one, so strip it before anything is
     written — belt and braces, so no future caller can leak it through this
     door either. */
  delete target.pass;
  delete target.password;
  localStorage.setItem(KEY, JSON.stringify(target));
  /* pointing somewhere new is how a host gets into the list — and pointing
     at a known one teaches the list what changed. The entry used to keep the
     sudo it was created with forever, so picking the host back out of the
     list silently restored a setting the user had already turned off. */
  if (target.kind === "ssh" && target.host) {
    const known = matching(hosts, target);
    if (!known) hosts = addHost(hosts, target).list;
    else if (known.sudo !== target.sudo) hosts = updateHost(hosts, known.id, { sudo: target.sudo });
    else return target;
    persistHosts();
  }
  return target;
}

/* The shape the Rust side expects. */
export const asTauriTarget = (tg = target) =>
  tg.kind === "ssh"
    ? native.ssh(tg.host, {
        user: tg.user || undefined,
        port: tg.port ? Number(tg.port) : undefined,
        sudo: !!tg.sudo,
        pass: passwordFor(tg) || undefined,
      })
    : native.LOCAL;

export const describe = (tg = target) =>
  tg.kind === "ssh"
    ? (tg.user ? `${tg.user}@` : "") + (tg.host || "?") + (tg.port ? `:${tg.port}` : "")
    : t("this machine", "esta máquina");

/* Is this target usable at all? Answers without throwing so callers can show
   the reason rather than a dead button. */
export async function probe(tg = target) {
  if (!native.isDesktop())
    return { ok: false, why: t("needs the desktop app", "necesita la app de escritorio") };
  if (tg.kind === "ssh" && !tg.host)
    return { ok: false, why: t("no host given", "falta el host") };
  if (tg.kind === "local" && !native.platform.local_nft_possible)
    return { ok: false, why: t("no nft on this platform", "no hay nft en esta plataforma") };

  const r = await native.hostProbe(asTauriTarget(tg));
  if (!r.ok)
    return { ok: false, why: (r.stderr || "").trim().split("\n")[0] || t("no answer", "sin respuesta") };

  return { ok: true, ...readProbe(r.stdout) };
}

/* `nftables v1.0.9 (Old Doc Yak)` and `Linux 6.8.0-45-generic` into the two
   numbers the status bar shows, plus the lines they came from — a version we
   could not make sense of is still worth showing verbatim. */
export function readProbe(stdout) {
  const field = (k) =>
    (String(stdout || "")
      .split("\n")
      .find((l) => l.startsWith(k + "\t")) || "")
      .slice(k.length + 1)
      .trim();

  const nft = field("nft");
  const uname = field("kernel");
  return {
    version: /\bv?(\d[\w.]*)/.exec(nft)?.[1] || nft,
    banner: nft,
    kernel: uname.split(/\s+/).pop() || "",
    uname,
  };
}
