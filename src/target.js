/* Where nft runs.
 *
 * The analyser is eFeFlow's own reading of a ruleset; `nft -c` is the
 * authority. nft only exists on Linux, so on any other desktop the only way to
 * reach the authority is the firewall itself — which is also the normal case
 * on Linux, since the box you edit on is rarely the box you filter on. */

import * as native from "./native.js";
import { t } from "./i18n.js";

const KEY = "efeflow.target";

export const target = { kind: "local", host: "", user: "", port: "", sudo: true };

export function loadTarget() {
  try {
    Object.assign(target, JSON.parse(localStorage.getItem(KEY) || "{}"));
  } catch {
    /* a corrupt entry is not worth a crash */
  }
  return target;
}

export function saveTarget(patch) {
  Object.assign(target, patch);
  localStorage.setItem(KEY, JSON.stringify(target));
  return target;
}

/* The shape the Rust side expects. */
export const asTauriTarget = (tg = target) =>
  tg.kind === "ssh"
    ? native.ssh(tg.host, {
        user: tg.user || undefined,
        port: tg.port ? Number(tg.port) : undefined,
        sudo: !!tg.sudo,
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

  const r = await native.nftVersion(asTauriTarget(tg));
  return r.ok
    ? { ok: true, version: r.stdout.trim().split("\n")[0] }
    : { ok: false, why: (r.stderr || "").trim().split("\n")[0] || t("no answer", "sin respuesta") };
}
