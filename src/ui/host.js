/* Where nft runs, and what happens when a ruleset is sent there.
 *
 * Everything in this file talks to a machine, or decides whether to: the
 * target chip and its dialog, the apply screen with its diff and its rollback
 * countdown, and the live watch. It was the last nine hundred lines of a
 * five-thousand-line app.js, which is where the ordering bug in openApply hid
 * — warnOnDrift fired alongside a probe nobody had waited for, so the drift
 * check only ever ran on the second open of the dialog, and nothing in a file
 * that size made that visible.
 *
 * It needs nothing from app.js. What the rest of the interface used to hand it
 * comes from the model bus instead — the analyser's findings, and a signal
 * when a ruleset lands on a host — so this can be read, tested and changed on
 * its own. REACH is exported as a live binding: two other screens ask whether
 * a host answered, and only this file may decide.
 */
import { MODEL, ruleLine } from "../core/model.js";
import { generate } from "../core/generate.js";
import { project } from "../core/project.js";
import { tableNames } from "../core/tables.js";
import { findings, applied, rerender, onRender } from "../core/bus.js";
import { applyPlan } from "../core/sync.js";
import { surgicalPlan } from "../core/surgical.js";
import { asTarget, matching, label as hostLabel } from "../core/hosts.js";
import { t } from "../i18n.js";
import { target, loadTarget, saveTarget, asTauriTarget, describe, probe,
         hosts, forgetHost } from "../target.js";
import { applyWithNet, surgicalChanges, keep, rollBackNow, pendingRollback } from "../apply.js";
import { refreshCounters, checkDrift } from "../host.js";
import * as native from "../native.js";
import { $, $$, esc, el, toast, go } from "./shell.js";
/* Owned here, and only assignable here. APPLY is the dialog's two choices,
   PLAN the last reading of the host, SURGICAL what the button will try, WATCH
   the live monitor. REACH is the one the rest of the interface reads. */
export let REACH = null;
let APPLY, PLAN, SURGICAL, WATCH;
const FIND = findings.list;

/* ══ TARGET ═════════════════════════════════════════════════════════════
   The chip in the titlebar said "no local nft" and its tooltip suggested
   adding an SSH target, with nothing behind it. This is the something. */
let tgDraft = {...loadTarget()};

/* The chip shows where nft is configured to run — a setting, which exists
   whether or not it is reachable right now. Reachability is the colour and
   the tooltip, not a replacement for the answer. */
/* `null` is not a failure, it is a question nobody has asked. Painting the two
   the same way is how a tool that has never contacted anything ends up
   reporting that nothing answered. */
export function paintTargetChip(state){
  const chip = $("#tb-target"), label = $("#tb-target-t");
  if(!chip) return;
  chip.classList.remove("live","remote");

  /* A hostname up there reads as a connection to it. Until one has answered,
     the chip says it has not connected and keeps the destination in the
     tooltip — the saved host is remembered, it is simply not being claimed. */
  label.textContent = state === null
    ? t("not connected", "sin conectar")
    : !state.ok
      /* and a host that was asked and did not answer may not be named either:
         the only thing separating "efe@192.0.2.1" reachable from the same
         eight seconds of timeout was the colour of a six-pixel dot */
      ? target.kind === "ssh" ? t("no answer","sin respuesta") : t("no local nft","sin nft local")
      : target.kind === "ssh" ? describe() : state.version;

  if(state?.ok){
    chip.classList.add(target.kind === "ssh" ? "remote" : "live");
    chip.title = t(`nft reachable — ${state.version}`, `nft accesible — ${state.version}`);
  } else if(state === null){
    chip.title = t(`Will use ${describe()} when something needs it. Click to connect or change it.`,
                   `Usará ${describe()} cuando algo lo necesite. Pulsa para conectar o cambiarlo.`);
  } else {
    chip.title = `${describe()} — ` + (state?.why ? state.why + " · " : "")
      + t("click to choose where nft runs", "pulsa para elegir dónde se ejecuta nft");
  }
}

/* The last answer from probe(), so the apply dialog can say why it cannot
   reach a host instead of offering a button that fails on the far side. */
REACH = null;
/* The status bar reports the host, not a build-time guess about it. Unknown is
   a real answer and gets said as one: an em dash with the reason behind it,
   and a click that goes where the reason can be fixed. */
function paintHostStatus(state){
  const el = $("#st-host");
  if(!el) return;
  if(state?.ok){
    el.innerHTML = `nft <span class="num">${esc(state.version)}</span>`
      + (state.kernel ? ` · ${t("kernel","kernel")} <span class="num">${esc(state.kernel)}</span>` : "");
    el.title = [state.banner, state.uname].filter(Boolean).join(" · ");
  } else {
    el.innerHTML = `<span class="dimmer">nft — · ${t("kernel","kernel")} —</span>`;
    el.title = (state?.why ? state.why + " · " : "")
      + t("click to choose where nft runs", "pulsa para elegir dónde se ejecuta nft");
  }

  /* the same answer, wherever it is asked for — and "nobody has asked" is not
     the same answer as "nothing replied" */
  const said = state?.ok
    ? t(`${describe()} · nft ${state.version}${state.kernel ? ` · kernel ${state.kernel}` : ""}`,
        `${describe()} · nft ${state.version}${state.kernel ? ` · kernel ${state.kernel}` : ""}`)
    : state === null
      ? t(`${describe()} · not contacted`, `${describe()} · sin contactar`)
      : t(`No host answering — ${state?.why || "not reached"}`,
          `Ninguna máquina responde — ${state?.why || "sin contactar"}`);
  const ex = $("#ex-target");
  if(ex) ex.textContent = said;
  const ab = $("#about-target");
  if(ab) ab.textContent = said;
}

/* ── saying that a machine is being contacted ────────────────────────────
 *
 * Nothing here was ever quick. ssh sits out its eight-second ConnectTimeout on
 * a host that is away, and `nft list ruleset` over a link that is merely slow
 * takes as long as it takes. Until now all of that happened in silence, and
 * eight seconds of an interface that says nothing is indistinguishable from
 * one that has stopped: "connecting over ssh shows nothing and blocks
 * everything".
 *
 * The blocking half was real and was in the backend — the commands were
 * declared `fn` rather than `async fn`, which serialises them, so a probe of an
 * unreachable host held every other call behind it (measured: 7743ms for one
 * that answers instantly). That is fixed in nft.rs. This is the other half:
 * the chip is where the target lives, so the chip is where it says it is being
 * contacted, and it stays saying so until the last call in flight comes back.
 *
 * Counted rather than a flag, because refreshTarget is two calls and the
 * first finishing does not mean the interface is idle. */
let REACHING = 0;
export async function reaching(said, run){
  const chip = $("#tb-target"), label = $("#tb-target-t");
  if(REACHING++ === 0 && chip){
    chip.classList.add("busy");
    if(label) label.textContent = said;
  }
  try { return await run(); }
  finally {
    if(--REACHING === 0 && chip){
      chip.classList.remove("busy");
      paintTargetChip(REACH);   // whatever the answer turned out to be
    }
  }
}

/** Keep a button from being pressed again while its own call is still out. */
async function whilePressed(btn, said, run){
  if(!btn) return run();
  const was = btn.textContent, off = btn.disabled;
  btn.disabled = true;
  if(said) btn.textContent = said;
  try { return await run(); }
  finally { btn.disabled = off; btn.textContent = was; }
}

async function refreshTarget(){
  REACH = await reaching(
    t(`contacting ${describe()}…`, `contactando con ${describe()}…`),
    () => probe());
  paintTargetChip(REACH);
  paintHostStatus(REACH);
  if($("#scrim-apply")?.classList.contains("on")) paintApplyForm();

  /* A window closed mid-countdown leaves a host counting down alone. Nothing
     is broken by that — it restores, which is the point — but arriving to a
     firewall that is about to change under you deserves to be said out loud. */
  if(REACH.ok && !APPLY.timer && await reaching(
      t(`asking ${describe()}…`, `preguntando a ${describe()}…`),
      () => pendingRollback({target: asTauriTarget()})))
    toast(t(`${describe()} has a rollback pending — it will restore its previous ruleset`,
            `${describe()} tiene un rollback pendiente — restaurará su ruleset anterior`));
}

function syncTargetForm(){
  $$("#scrim-target .choice").forEach(c=>
    c.classList.toggle("on", c.dataset.target === tgDraft.kind));
  $("#tg-fields").style.display = tgDraft.kind === "ssh" ? "flex" : "none";
  $("#tg-host").value = tgDraft.host || "";
  $("#tg-user").value = tgDraft.user || "";
  $("#tg-port").value = tgDraft.port || "";
  $("#tg-sudo").classList.toggle("on", !!tgDraft.sudo);
  $("#tg-preview").textContent = describe(tgDraft);
  $("#tg-local-note").textContent = !native.isDesktop()
    ? t("Unavailable in a browser.","No disponible en navegador.")
    : native.platform.local_nft_possible
      ? t("Linux — nft can run here.","Linux — nft puede ejecutarse aquí.")
      : t(`No nft on ${native.platform.os}. Use SSH.`, `No hay nft en ${native.platform.os}. Usa SSH.`);
}

/* The estate, listed. A hostname you have typed a hundred times should be a
   thing you pick, and the one you are pointing at should be obvious. */
function renderHosts(){
  const box = $("#tg-saved"), fld = $("#tg-saved-fld");
  if(!box) return;
  fld.style.display = hosts.length ? "" : "none";
  /* against the draft, not the saved target: the highlight has to follow what
     you are choosing, or picking one in this dialog lights up nothing */
  const here = matching(hosts, tgDraft);
  box.innerHTML = hosts.map(h=>`
    <div class="hostrow${here && here.id===h.id ? " on" : ""}" data-host="${esc(h.id)}">
      <span class="nm">${esc(hostLabel(h))}</span>
      <span class="rf mono">${esc(h.name ? describe(asTarget(h)) : "")}</span>
      <button class="tb icon" data-forget="${esc(h.id)}" title="${esc(
        t("Forget this one","Olvidar este"))}">
        <svg class="ico sm" viewBox="0 0 24 24"><path d="M6 6l12 12M18 6 6 18"/></svg></button>
    </div>`).join("");
}

function openTarget(){
  tgDraft = {...target};
  $("#tg-result").style.display = "none";
  renderHosts();
  syncTargetForm();
  $("#scrim-target").classList.add("on");
  /* Opening the dialog that asks where nft runs is asking whether it does.
     Not awaited: the dialog is usable while the answer is on its way. */
  if(REACH === null && native.isDesktop()) refreshTarget();
}

$("#tb-target").addEventListener("click", openTarget);
/* both say the same thing about the same host, so both lead to the same place */
$("#st-host")?.addEventListener("click", openTarget);
$("#scrim-target").addEventListener("click", e=>{
  /* forgetting sits inside the row that selects, so it has to be asked first */
  const gone = e.target.closest("[data-forget]");
  if(gone){
    e.stopPropagation();
    forgetHost(gone.dataset.forget);
    renderHosts();
    return;
  }
  const pick = e.target.closest("[data-host]");
  if(pick){
    const h = hosts.find(x=>x.id === pick.dataset.host);
    if(h){ tgDraft = {...asTarget(h)}; renderHosts(); syncTargetForm(); }
    return;
  }
  const c = e.target.closest("[data-target]");
  if(c){ tgDraft.kind = c.dataset.target; syncTargetForm(); }
  /* Flip the state and let the global .sw-toggle handler paint the class —
     the same contract every other switch keeps (see app.js, "a global handler
     already flips every .sw-toggle"). This one painted as well, so the two
     flips cancelled: after every click the switch showed the opposite of the
     draft, and "off" went to the host as sudo. */
  if(e.target.closest("#tg-sudo")){ tgDraft.sudo = !tgDraft.sudo; }
});
$$("#tg-host, #tg-user, #tg-port").forEach(n=>n.addEventListener("input", ()=>{
  tgDraft.host = $("#tg-host").value.trim();
  tgDraft.user = $("#tg-user").value.trim();
  tgDraft.port = $("#tg-port").value.trim();
  $("#tg-preview").textContent = describe(tgDraft);
}));

$("#tg-test").addEventListener("click", async ()=>{
  const box = $("#tg-result");
  box.style.display = "";
  box.className = "tg-result busy";
  /* named, because the wait is the host's and eight seconds of "Asking nft…"
     against a host that is away reads as the button having done nothing */
  box.textContent = t(`Contacting ${describe(tgDraft)}…`,
                      `Contactando con ${describe(tgDraft)}…`);
  const r = await whilePressed($("#tg-test"), null, ()=> probe(tgDraft));
  box.className = "tg-result " + (r.ok ? "ok" : "bad");
  box.textContent = r.ok
    ? t(`Reachable · ${r.version}`, `Accesible · ${r.version}`)
    : r.why;
});

$("#tg-save").addEventListener("click", async ()=>{
  saveTarget(tgDraft);
  $("#scrim-target").classList.remove("on");
  await refreshTarget();
  toast(t(`nft will run on ${describe()}`, `nft se ejecutará en ${describe()}`));
});

/* Why a local read could not even ask for the privilege it needs.
 *
 * The native side answers with a word rather than a sentence, because the
 * sentence has to be said in the user's language and this file is where the
 * two languages live. Reported from the running app: "un mensaje que dice que
 * necesita root, pero no me pide root" — which was true, and the message did
 * not say why not. There are two reasons and they have different fixes, so
 * they get different text.
 */
/* Why, and only why. What was being attempted belongs to the caller — the
   same missing pkexec stops a read and a check, and each has its own way
   round it. */
const ROOT_WHY = {
  "needs-root-uninstalled": () => ({
    title: t("Nothing here can ask you for root",
             "Aquí no hay nada que pueda pedirte root"),
    body: t("nftables has no read-only permission: the kernel wants CAP_NET_ADMIN even to list the rules. eFeFlow can ask for it with a desktop password prompt rather than running as root — but what does the asking is installed by the .deb or the .rpm, and this build is running without it. That is why it says root and never prompts.",
            "nftables no tiene un permiso de solo lectura: el kernel exige CAP_NET_ADMIN incluso para listar las reglas. eFeFlow puede pedírtelo con un diálogo de contraseña del escritorio, en vez de ejecutarse como root — pero quien lo pide lo instala el .deb o el .rpm, y esta compilación se está ejecutando sin él. Por eso dice root y nunca te pregunta."),
  }),
  "needs-root-no-pkexec": () => ({
    title: t("pkexec is missing, and pkexec is what asks",
             "Falta pkexec, que es quien pregunta"),
    body: t("The eFeFlow helper is installed, but pkexec is not — it is the program that raises the password dialog. On Debian and Ubuntu it is a package of its own: sudo apt install pkexec. A polkit authentication agent has to be running too, which every desktop environment provides.",
            "El helper de eFeFlow está instalado, pero pkexec no — es el programa que levanta el diálogo de contraseña. En Debian y Ubuntu es un paquete aparte: sudo apt install pkexec. También hace falta un agente de autenticación de polkit en marcha, que todos los escritorios traen."),
  }),
  "needs-root": () => ({
    title: t("This needs root, and it cannot be asked for here",
             "Esto necesita root y aquí no se puede pedir"),
    body: t("The kernel wants CAP_NET_ADMIN for this, and the desktop authorisation is not available on this machine.",
            "El kernel exige CAP_NET_ADMIN para esto, y la autorización del escritorio no está disponible en esta máquina."),
  }),
  declined: () => ({
    title: t("The authorisation was declined","Se rechazó la autorización"),
    body: t("Nothing was read, and nothing on this machine was touched. Press the button again to be asked once more.",
            "No se ha leído nada y no se ha tocado nada de esta máquina. Vuelve a pulsar el botón para que te lo pregunte otra vez."),
  }),
  /* Measured on a Debian 13 desktop with the released .deb installed: the
     helper was root-owned, mode 755, shebang present, and execve ran it — and
     pkexec still exited 127, because the application had been started from an
     ssh session and polkit had no agent for it. The message told the user to
     reinstall a package that was installed perfectly, which is worse than
     saying nothing. pkexec names the reason in its stderr; the native side
     reads it now rather than inferring from the exit code alone. */
  "no-polkit-agent": () => ({
    title: t("Nothing asked you for a password",
             "Nada te ha pedido la contraseña"),
    body: t("The permission exists and the helper is fine — but there is nobody to raise the dialog. eFeFlow is running outside a desktop session that polkit can prompt in, which is what happens when it is launched from a terminal over ssh. Start it from your applications menu on that machine, or point eFeFlow at the firewall over SSH instead.",
            "El permiso existe y el helper está bien — pero no hay quien levante el diálogo. eFeFlow se está ejecutando fuera de una sesión de escritorio en la que polkit pueda preguntar, que es lo que pasa al lanzarlo desde un terminal por ssh. Ábrelo desde el menú de aplicaciones de esa máquina, o apunta eFeFlow al cortafuegos por SSH."),
  }),
  "helper-broken": () => ({
    title: t("polkit could not start the helper","polkit no pudo arrancar el helper"),
    body: t("The authorisation exists but the program behind it would not run. pkexec refuses a helper that is not owned by root or that others can write to, and reinstalling the package restores both.",
            "La autorización existe pero el programa que hay detrás no arrancó. pkexec rechaza un helper que no sea de root o en el que otros puedan escribir; reinstalar el paquete arregla las dos cosas."),
  }),
};

/* The explanation goes where the button that failed is, and it stays there.
   A toast cannot hold four sentences and a command you are meant to copy. */
export function showRootHelp(code){
  const why = ROOT_WHY[code]?.(); if(!why) return false;
  /* Only the cases that are about not being able to ask have a way round;
     a declined prompt is answered by pressing the button again. */
  const workaround = code.startsWith("needs-root");
  $("#imp-side").innerHTML = `
    <div class="imp-sec">
      <div style="display:flex;gap:9px;align-items:flex-start;margin-bottom:10px">
        <span style="color:var(--warn);font-size:13px;line-height:1.2">⚠</span>
        <span style="font:600 12.5px var(--sans);color:var(--t1)">${esc(why.title)}</span>
      </div>
      <div style="font-size:11.5px;color:var(--t3);line-height:1.65">${esc(why.body)}</div>
      ${workaround ? `<div style="font-size:11.5px;color:var(--t3);line-height:1.65;margin-top:10px">${esc(t(
        "Meanwhile: read the ruleset yourself, then open the file it writes.",
        "Mientras tanto: lee el ruleset tú y abre el fichero que genera."))}</div>
      <div class="mono" style="margin-top:7px;padding:8px 10px;border-radius:var(--r-sm);
           background:var(--raised-2);border:1px solid var(--line-2);color:var(--t2);
           font-size:11px;user-select:all;word-break:break-all">sudo nft -a list ruleset &gt; ruleset.nft</div>` : ""}
    </div>`;
  return true;
}

/* ── the two things a target is for ── */
$("#imp-host")?.addEventListener("click", async ()=>{
  const r = await whilePressed($("#imp-host"), t("Reading…","Leyendo…"),
    ()=> reaching(t(`reading ${describe()}…`, `leyendo ${describe()}…`),
                  ()=> native.nftList(asTauriTarget())));
  if(!r.ok){
    /* A privilege the application cannot obtain is not a one-line failure,
       and it is not English either. The native side names the case; the text
       and the language are decided here. */
    if(showRootHelp(r.hint)){
      toast(t("Could not read this machine — see the panel","No se pudo leer esta máquina — mira el panel"));
      return;
    }
    toast(r.stderr.trim().split("\n")[0] || t("could not read","no se pudo leer"));
    return;
  }
  /* A machine with no firewall loaded answers with nothing, and nothing is a
     perfectly good answer — but "Read from fw01" over an empty textarea reads
     as a success with the result hidden somewhere, and the Import button then
     stays disabled for a reason nobody has been told. Say which of the two it
     was. */
  const lines = r.stdout.split("\n").filter(l=>l.trim()).length;
  if(!lines){
    toast(t(`${describe()} has no ruleset loaded — there is nothing to read`,
            `${describe()} no tiene ningún ruleset cargado — no hay nada que leer`));
    return;
  }
  $("#imp-text").value = r.stdout;
  $("#imp-text").dispatchEvent(new Event("input", {bubbles:true}));
  toast(t(`Read ${lines} lines from ${describe()}`, `Leídas ${lines} líneas de ${describe()}`));
});

$("#val-nft")?.addEventListener("click", async ()=>{
  const r = await whilePressed($("#val-nft"), t("Checking…","Comprobando…"),
    ()=> reaching(t(`checking on ${describe()}…`, `comprobando en ${describe()}…`),
                  ()=> native.nftCheck(generate().join("\n"), asTauriTarget())));
  const box = $("#val-nft-out");
  box.style.display = "";
  box.className = "nft-out " + (r.ok ? "ok" : "bad");
  /* A ruleset nft rejected must be reported in nft's own words — that output
     is the answer. A privilege it never got to spend is not about the ruleset
     at all, so it is said here, in the user's language, like the read path. */
  const why = r.ok ? null : ROOT_WHY[r.hint]?.();
  box.textContent = r.ok
    ? t(`nft -c accepted the ruleset on ${describe()}.`,
        `nft -c aceptó el ruleset en ${describe()}.`)
    : why
      ? `${why.title}\n\n${why.body}\n\n` + t(
          "Without it, nft -c only gets as far as the syntax. Check on an SSH target for the kernel's answer.",
          "Sin eso, nft -c solo llega hasta la sintaxis. Compruébalo en un target SSH para tener la respuesta del kernel.")
      : (r.stderr || r.stdout).trim();
});

/* ══ APPLY ══════════════════════════════════════════════════════════════
   The only thing eFeFlow does that changes a machine, and the only thing it
   does that can lock you out of one. src/apply.js owns the ordering; this
   owns the dialog, and the countdown you have to answer to keep what you
   applied. Doing nothing rolls the host back — which is the right way round,
   because the failure this protects against is the one where you cannot
   reach the host to press anything at all. */
APPLY = { scope:"tables", secs:60, timer:null, left:0 };

/* Every table the export writes, which is not the same as every table holding
   a chain: one carrying only a set — or nothing but a comment and a flag — is
   still ours to replace, and naming it here is what the scoped apply promises. */
const applyTables = () => tableNames(MODEL);

function paintApplyForm(){
  const tables = applyTables();
  $("#ap-target").textContent = describe();
  $("#ap-go").textContent = t(`Apply to ${describe()}`, `Aplicar en ${describe()}`);
  $("#val-apply-t").textContent = t("Apply…","Aplicar…");

  $$("#ap-scope [data-scope]").forEach(b=>b.classList.toggle("on", b.dataset.scope===APPLY.scope));
  $$("#ap-window [data-secs]").forEach(b=>b.classList.toggle("on", +b.dataset.secs===APPLY.secs));

  $("#ap-scope-note").textContent = APPLY.scope==="tables"
    ? t(`Replaces ${tables.join(", ")} and leaves every other table on the host — Docker, libvirt, fail2ban — standing.`,
        `Reemplaza ${tables.join(", ")} y deja en pie cualquier otra tabla de la máquina — Docker, libvirt, fail2ban.`)
    : t("flush ruleset: empties the kernel first. Anything on the host that eFeFlow did not write is deleted with it.",
        "flush ruleset: vacía el kernel primero. Todo lo que haya en la máquina y no lo haya escrito eFeFlow se borra con ello.");

  $("#ap-window-note").textContent = APPLY.secs
    ? t(`The host copies its ruleset aside and puts it back after ${APPLY.secs}s unless you confirm. Lose the connection and it restores itself.`,
        `La máquina copia su ruleset y lo restaura a los ${APPLY.secs}s salvo que confirmes. Si pierdes la conexión, se restaura sola.`)
    : t("Nothing is armed. If this ruleset cuts off your access, you will need console access to the machine.",
        "No se arma nada. Si este ruleset te corta el acceso, necesitarás consola física en la máquina.");

  /* An unreachable target says so here rather than at the end of an apply that
     was never going to happen. */
  const warn = $("#ap-warn");
  const errs = FIND.filter(f=>f.sev==="error").length;
  const unreachable = REACH && !REACH.ok ? REACH.why : null;
  $("#ap-go").disabled = !!unreachable;

  warn.style.display = unreachable || errs ? "" : "none";
  warn.textContent = unreachable
    ? t(`Nothing to apply to: ${unreachable}. Point eFeFlow at a host with the chip in the title bar.`,
        `No hay dónde aplicar: ${unreachable}. Apunta eFeFlow a una máquina con el chip de la barra de título.`)
    : errs ? t(
      `The validation screen reports ${errs} error${errs===1?"":"s"}. nft -c runs on the host before anything is written, and will refuse.`,
      `La pantalla de validación reporta ${errs} error${errs===1?"":"es"}. nft -c se ejecuta en la máquina antes de escribir nada, y lo rechazará.`)
    : "";
}

function showApplyStage(after){
  $("#ap-before").style.display    = after ? "none" : "";
  $("#ap-ft-before").style.display = after ? "none" : "";
  $("#ap-after").style.display     = after ? "" : "none";
  $("#ap-ft-after").style.display  = after ? "" : "none";
}

function stopCountdown(){
  if(APPLY.timer) clearInterval(APPLY.timer);
  APPLY.timer = null;
}
function tickCountdown(){
  const m = Math.floor(APPLY.left/60), s = APPLY.left%60;
  $("#ap-clock").textContent = `${m}:${String(s).padStart(2,"0")}`;
  if(APPLY.left <= 0){
    stopCountdown();
    $("#ap-clock").style.color = "var(--t3)";
    $("#ap-count-t").textContent = t(
      `The window has passed, so ${describe()} has put its previous ruleset back.`,
      `La ventana ha pasado, así que ${describe()} ha restaurado su ruleset anterior.`);
    $("#ap-keep").disabled = true;
    refreshTarget();
    return;
  }
  APPLY.left--;
}

/* Has the host moved since you read it?
 *
 * The scoped apply keeps Docker's tables out of it, but inside your own table
 * twenty rules added by fail2ban while you were editing are invisible — and
 * the apply takes them with it. This is the look before that, and it runs when
 * the dialog opens rather than on a button, because the moment it matters is
 * the moment before you press Apply. */
/* ── what applying does, said before it is done ──────────────────────────
 *
 * Three things were wrong with the one-line summary this replaces, and only
 * the first was visible from here.
 *
 * It went silent when it could not read the host: `!r.ok` and `inSync` left by
 * the same door, so *I could not look* was drawn exactly like *nothing has
 * changed* — in front of the one button that can lock somebody out of a
 * machine. Same defect as the counters: a zero that means nothing, painted
 * like a zero that means something.
 *
 * It counted every table on the host, while the default apply replaces only
 * the project's own. Any machine running Docker reported drift before every
 * apply, for ever, about chains that were never going to be touched — and a
 * warning that is always on is a warning nobody reads.
 *
 * And "3 it has that you have not" reads like something missing from your
 * document. They are rules running on that firewall now — a ban, a
 * colleague's hotfix — and what Apply does to them is delete them.
 */
async function warnOnDrift(){
  const box = $("#ap-drift"), fld = $("#ap-plan-fld");
  box.style.display = "none";
  if(fld) fld.style.display = "none";
  PLAN = null;
  if(!REACH?.ok) return;

  /* Scoped to what this apply actually replaces. `ruleset` really does empty
     the kernel, so there the scope is everything and no list is passed. */
  const r = await reaching(
    t(`reading ${describe()}…`, `leyendo ${describe()}…`),
    ()=> checkDrift({
      model: MODEL,
      target: asTauriTarget(),
      tables: APPLY.scope === "tables" ? applyTables() : undefined,
    }));
  if(!$("#scrim-apply").classList.contains("on")) return;

  if(!r.ok){
    /* Said out loud, and never as an empty diff. Apply is left enabled: a
       screen that blocks the urgent operation because it could not draw a
       picture is a screen that teaches people to apply blind. */
    box.style.display = "";
    box.textContent = t(
      `Could not read ${describe()} — ${r.error || "no answer"}. This window cannot tell you what applying would replace. The rollback window below is the only safety net here.`,
      `No se ha podido leer ${describe()} — ${r.error || "sin respuesta"}. Esta ventana no puede decirte qué reemplazaría aplicar. La ventana de rollback de abajo es aquí la única red.`);
    return;
  }

  PLAN = r;
  paintApplyPlan();
}

/** The diff, and the two facts about the machine that no diff can carry. */
function paintApplyPlan(){
  const fld = $("#ap-plan-fld"), out = $("#ap-plan"), cost = $("#ap-plan-cost");
  const box = $("#ap-drift");
  if(!fld) return;
  if(!PLAN?.host){ fld.style.display = "none"; return; }

  /* Recomputed from the reading already taken, not from a second one. The
     scope buttons change what is replaced — "the whole ruleset" puts Docker's
     tables back in play — and switching between them is a question about a
     photograph we are already holding, not a reason to go back to the host. */
  const p = applyPlan(MODEL, PLAN.host, {
    tables: APPLY.scope === "tables" ? applyTables() : undefined,
  });
  fld.style.display = "";
  out.innerHTML = "";

  const line = (cls, mark, text)=>{
    const el = document.createElement("div");
    el.className = "ln " + cls;
    const i = document.createElement("i"); i.textContent = mark;
    const s = document.createElement("span"); s.textContent = text;
    el.append(i, s); out.appendChild(el);
  };

  for(const c of p.touched){
    const h = document.createElement("div");
    h.className = "ch";
    h.textContent = `${c.table} · ${c.chain}` + (
      c.isNew ? t(" — new here", " — nueva aquí")
      : c.isGone ? t(" — goes with the table", " — se va con la tabla") : "");
    out.appendChild(h);
    /* destroyed first: those are running right now and will not be */
    /* Three marks for three fates, because there were two.
       A rule you edited was drawn `−` old / `+` new — the same two marks a
       rule being deleted and a rule being created get — and only the colour
       told them apart. In a chain with a dozen entries that is a list of
       deletions to anybody scanning it, which is the alarming reading of a
       screen whose whole job is to be read quickly before a firewall changes.
       `~` on both halves says they are one rule, and leaves `−` meaning gone
       and `+` meaning new. */
    for(const r of c.destroy) line("gone", "−", ruleLine(r));
    for(const ch of c.change){ line("was", "~", ruleLine(ch.from)); line("now", "~", ruleLine(ch.to)); }
    for(const r of c.create) line("new", "+", ruleLine(r));
    if(c.keep) {
      const q = document.createElement("div");
      q.className = "quiet";
      q.textContent = t(`${c.keep} unchanged`, `${c.keep} sin cambios`);
      out.appendChild(q);
    }
  }

  if(p.identical){
    const q = document.createElement("div");
    q.className = "quiet";
    q.style.padding = "8px 10px";
    q.textContent = t("Nothing differs. The rules on the host already say this.",
                      "No difiere nada. Las reglas de la máquina ya dicen esto.");
    out.appendChild(q);
  }

  /* The part with no text. Measured on nft 1.1.6: a scoped apply deletes the
     table and rebuilds it, so every rule in it is a new rule to the kernel —
     handles reassigned, counters at zero — including the ones nobody edited.
     Where handles come out the same it is because numbering restarts and
     coincides, which is not the same as being preserved.

     …unless the difference is only rules, in which case nftables can be told
     about exactly those and the rest of the table is not touched at all. Which
     of the two it will be changes what this line has to say, so it is decided
     here — from the reading already in hand — rather than discovered
     afterwards. SURGICAL is what the button will try; a fresh read at apply
     time gets the last word, and if the host has moved since, the whole-table
     apply is still there. */
  SURGICAL = APPLY.scope === "tables"
    ? surgicalPlan(MODEL, PLAN.host, { tables: applyTables() })
    : { ok: false, why: "whole-ruleset" };

  const when = Math.max(0, Math.round((Date.now() - PLAN.at)/1000));
  const read = t(`read ${when}s ago`, `leído hace ${when}s`);
  const said = [];
  if(SURGICAL.ok){
    const n = SURGICAL.replaced + SURGICAL.deleted + SURGICAL.inserted;
    /* Only the parts that happened: "1 replaced, 0 deleted, 0 added" is three
       facts where one was wanted, and two of them are noise. */
    const bits = [
      SURGICAL.replaced && t(`${SURGICAL.replaced} replaced`,
        `${SURGICAL.replaced} reemplazada${SURGICAL.replaced===1?"":"s"}`),
      SURGICAL.deleted && t(`${SURGICAL.deleted} deleted`,
        `${SURGICAL.deleted} borrada${SURGICAL.deleted===1?"":"s"}`),
      SURGICAL.inserted && t(`${SURGICAL.inserted} added`,
        `${SURGICAL.inserted} añadida${SURGICAL.inserted===1?"":"s"}`),
    ].filter(Boolean);
    said.push(n === 1
      ? t(`One rule is touched — ${bits[0]}. The other ${SURGICAL.kept} keep their handles and their counters: nftables is told about the change rather than handed the table.`,
          `Se toca una sola regla — ${bits[0]}. Las otras ${SURGICAL.kept} conservan sus handles y sus contadores: a nftables se le dice el cambio en vez de darle la tabla entera.`)
      : t(`Only ${n} rules are touched — ${bits.join(", ")}. The other ${SURGICAL.kept} keep their handles and their counters: nftables is told about the changes rather than handed the table.`,
          `Solo se tocan ${n} reglas — ${bits.join(", ")}. Las otras ${SURGICAL.kept} conservan sus handles y sus contadores: a nftables se le dicen los cambios en vez de darle la tabla entera.`));
    cost.textContent = said.join(" ") + ` · ${read}`;
    paintDriftWarning(p);
    return;
  }
  /* "every handle is reassigned" was too strong, and the machine said so:
     applying a 27-rule ruleset on nft 1.1.3 left 7 of them reading the number
     they read before. They are new rules — numbering simply restarts and
     coincides — but somebody who checks a handle and finds it unchanged will
     conclude this screen lied to them. */
  if(p.recreated)
    said.push(t(
      `All ${p.recreated} rules in ${p.tables.join(", ")} are deleted and rebuilt, not edited: handles are assigned afresh — one that comes back the same did so by coincidence — and their counters go to zero.`,
      `Las ${p.recreated} reglas de ${p.tables.join(", ")} se borran y se reconstruyen, no se editan: los handles se asignan de nuevo —si alguno sale igual es casualidad— y sus contadores vuelven a cero.`));
  /* deleted and *not* put back — a different fate, and the worse one */
  if(p.dropped)
    said.push(t(
      `${p.droppedTables.join(", ")} is not yours and is not rebuilt: ${p.dropped} rule${p.dropped===1?"":"s"} on that host stop existing.`,
      `${p.droppedTables.join(", ")} no es tuya y no se reconstruye: ${p.dropped} regla${p.dropped===1?"":"s"} de esa máquina dejan de existir.`));
  if(p.packets)
    said.push(t(`${p.packets.toLocaleString()} packets counted so far go with them.`,
                `Con ello se pierden ${p.packets.toLocaleString()} paquetes contados hasta ahora.`));
  if(!said.length)
    said.push(t(`${describe()} has none of these tables yet — nothing is replaced.`,
                `${describe()} aún no tiene estas tablas — no se reemplaza nada.`));
  cost.textContent = said.join(" ") + ` · ${read}`;

  paintDriftWarning(p);
}

/* The old warning keeps its job: something moved under you since you read it.
   It is about rules this will destroy, which is what it always meant — and it
   means it whichever of the two applies is going to run, so it is said in one
   place that both of them reach. */
function paintDriftWarning(p){
  const box = $("#ap-drift");
  const gone = p.touched.reduce((a,c)=> a + c.destroy.length, 0);
  box.style.display = gone ? "" : "none";
  if(gone) box.textContent = gone === 1
    ? t(`${describe()} has 1 rule that this does not — added there since you read it. Applying deletes it.`,
        `${describe()} tiene 1 regla que esto no — añadida allí desde que lo leíste. Aplicar la borra.`)
    : t(`${describe()} has ${gone} rules that this does not — added there since you read it. Applying deletes them.`,
        `${describe()} tiene ${gone} reglas que esto no — añadidas allí desde que lo leíste. Aplicar las borra.`);
}

function openApply(){
  stopCountdown();
  /* Both choices go back to the safe one every time. A scope of "the whole
     ruleset" or a net of "none", remembered from an apply ten minutes ago and
     applied to a different host, is exactly the shape of thing that empties
     somebody's Docker tables at two in the morning. Two clicks is nothing
     against that; a sticky setting here is not a convenience. */
  APPLY.scope = "tables";
  APPLY.secs = 60;
  showApplyStage(false);
  paintApplyForm();
  $("#scrim-apply").classList.add("on");
  /* About to write to a firewall is the moment to know whether it answers and
     whether it already has a rollback counting down.

     Awaited, and this is why: warnOnDrift begins `if(!REACH?.ok) return`, so
     firing it alongside a probe that has not come back meant it returned
     instantly, every time, on the first open of this dialog. The drift check
     only ever ran the second time somebody opened it — which is not when they
     needed it. Found by driving the real dialog, not by reading this. */
  (async ()=>{
    if(REACH === null && native.isDesktop()) await refreshTarget();
    await warnOnDrift();
  })();
}

$("#val-apply")?.addEventListener("click", openApply);
$$("#ap-scope [data-scope]").forEach(b=>b.addEventListener("click", ()=>{
  APPLY.scope = b.dataset.scope;
  paintApplyForm();
  /* the scope is what "this replaces" means, so the picture of what it
     replaces changes with it — from the reading already in hand */
  paintApplyPlan();
}));
$$("#ap-window [data-secs]").forEach(b=>b.addEventListener("click", ()=>{
  APPLY.secs = +b.dataset.secs; paintApplyForm();
}));

$("#ap-go")?.addEventListener("click", async ()=>{
  /* three round trips on a bad day — arm, check, load — and the last of them
     is the one that can take the link out from under itself */
  let how = "whole";
  const r = await whilePressed($("#ap-go"), t("Applying…","Aplicando…"),
    ()=> reaching(t(`applying to ${describe()}…`, `aplicando en ${describe()}…`),
      async ()=>{
        /* The changes, if they can be sent as changes. Asked again here, and
           against a reading taken now: the panel's answer was worked out from
           a photograph, and these commands address rules by handle. If the
           host has moved since, this comes back refused and the apply that
           always works runs instead — the same ruleset either way. */
        let ruleset = null;
        if(APPLY.scope === "tables"){
          const s = await surgicalChanges({
            model: MODEL, target: asTauriTarget(), tables: applyTables(),
          });
          if(s.ok){ ruleset = s.commands.join("\n") + "\n"; how = "surgical"; }
        }
        if(ruleset === null) ruleset = generate(MODEL, {scope: APPLY.scope}).join("\n");
        return applyWithNet({ ruleset, target: asTauriTarget(), seconds: APPLY.secs });
      }));

  if(!r.ok){
    const warn = $("#ap-warn");
    warn.style.display = "";
    warn.textContent = (r.stage==="arm"
      ? t("Nothing was applied — the rollback could not be armed, so the host was left alone. ",
          "No se ha aplicado nada — no se pudo armar el rollback, así que la máquina se quedó como estaba. ")
      : t("Nothing was applied. ","No se ha aplicado nada. ")) + (r.error || "");
    return;
  }

  applied();
  showApplyStage(true);
  $("#ap-clock").style.color = "var(--v-reject)";
  $("#ap-keep").disabled = false;
  /* Which of the two ran, said afterwards as well as before. The panel had to
     guess from a reading a few seconds old; this is what happened. */
  toast(how === "surgical"
    ? t(`Sent as changes — every rule you did not touch kept its counters on ${describe()}`,
        `Enviado como cambios — cada regla que no tocaste conservó sus contadores en ${describe()}`)
    : t(`Applied whole to ${describe()} — counters in those tables start again`,
        `Aplicado entero en ${describe()} — los contadores de esas tablas empiezan de nuevo`));
  if(r.armed){
    APPLY.left = r.seconds;
    $("#ap-count-t").textContent = t(
      `Applied to ${describe()}. It rolls back to what it was running unless you keep it.`,
      `Aplicado en ${describe()}. Volverá a lo que tenía salvo que lo conserves.`);
    tickCountdown();
    APPLY.timer = setInterval(tickCountdown, 1000);
  } else {
    $("#ap-clock").textContent = "—";
    $("#ap-clock").style.color = "var(--v-accept)";
    $("#ap-count-t").textContent = t(
      `Applied to ${describe()}. Nothing was armed, so nothing will undo it.`,
      `Aplicado en ${describe()}. No se armó nada, así que nada lo deshará.`);
    $("#ap-rollback").style.display = "none";
  }
  refreshTarget();
});

$("#ap-keep")?.addEventListener("click", async ()=>{
  stopCountdown();
  const r = await whilePressed($("#ap-keep"), t("Keeping…","Conservando…"),
    ()=> reaching(t(`confirming on ${describe()}…`, `confirmando en ${describe()}…`),
                  ()=> keep({target: asTauriTarget()})));
  $("#scrim-apply").classList.remove("on");
  toast(r.ok ? t(`Kept on ${describe()}`, `Conservado en ${describe()}`)
             : t(`Could not confirm — ${r.error}`, `No se pudo confirmar — ${r.error}`));
});

$("#ap-rollback")?.addEventListener("click", async ()=>{
  stopCountdown();
  const r = await whilePressed($("#ap-rollback"), t("Rolling back…","Revirtiendo…"),
    ()=> reaching(t(`restoring ${describe()}…`, `restaurando ${describe()}…`),
                  ()=> rollBackNow({target: asTauriTarget()})));
  $("#scrim-apply").classList.remove("on");
  toast(r.ok ? t(`${describe()} is back on its previous ruleset`,
                 `${describe()} ha vuelto a su ruleset anterior`)
             : t(`Rollback failed — ${r.error}`, `El rollback falló — ${r.error}`));
  refreshTarget();
});

/* Closing the dialog is not confirming. The host keeps counting, and it will
   restore — which is what a net is for, but not something to be surprised by. */
$("#scrim-apply")?.addEventListener("click", e=>{
  if(e.target !== e.currentTarget && !e.target.closest("[data-close]")) return;
  if(APPLY.timer){
    stopCountdown();
    toast(t(`Still counting on ${describe()} — it will roll back unless you keep it`,
            `${describe()} sigue contando — revertirá salvo que lo conserves`));
  }
});

/* ══ THE HOST, WHILE YOU ARE EDITING ════════════════════════════════════
   Three things that ask a running machine rather than reason about a
   document. src/host.js owns what they do; this owns when and what they say. */

async function readCounters(){
  if(!REACH?.ok){ toast(t(`No host to read from — ${REACH?.why||""}`,
                          `Ninguna máquina que leer — ${REACH?.why||""}`)); return; }
  const r = await refreshCounters({model: MODEL, target: asTauriTarget()});
  if(!r.ok){ toast(t(`Could not read the counters — ${r.error}`,
                     `No se pudieron leer los contadores — ${r.error}`)); return; }
  /* Counters are not part of what a ruleset means: nothing in the generated
     source changes, so this is a read. No history entry, no unsaved dot. */
  rerender();
  toast(r.updated
    ? t(`Counters read from ${describe()} · ${r.updated} rules updated`,
        `Contadores leídos de ${describe()} · ${r.updated} reglas actualizadas`)
    : t(`Counters read from ${describe()} · nothing had moved`,
        `Contadores leídos de ${describe()} · nada se había movido`));
}
$("#cv-counters")?.addEventListener("click", readCounters);

/* `nft monitor` stays open and reports what the kernel does to the ruleset as
   it happens. Without it the only way to learn that fail2ban added twenty
   rules while you were editing is to apply over them. */
WATCH = null;
async function toggleWatch(){
  const btn = $("#cv-watch");
  if(WATCH){
    await native.nftUnwatch();
    WATCH.stop?.();
    WATCH = null;
    btn?.classList.remove("on");
    toast(t("Stopped watching","Se deja de vigilar"));
    return;
  }
  if(!REACH?.ok){ toast(t(`No host to watch — ${REACH?.why||""}`,
                          `Ninguna máquina que vigilar — ${REACH?.why||""}`)); return; }
  let seen = 0, told = false;
  const r = await native.nftWatch(asTauriTarget(), line=>{
    if(line === null){            /* the stream ended: nft stopped, or the link did */
      WATCH = null; btn?.classList.remove("on");
      toast(t(`Stopped watching ${describe()} — the stream ended`,
              `Se deja de vigilar ${describe()} — el flujo terminó`));
      return;
    }
    seen++;
    /* one word, not a running commentary: what matters is that it moved */
    if(!told){
      told = true;
      setTimeout(()=>{
        told = false;
        toast(t(`${describe()} changed under you — ${seen} events. Re-read it before applying.`,
                `${describe()} ha cambiado bajo tus pies — ${seen} eventos. Reléelo antes de aplicar.`));
      }, 1200);
    }
  });
  if(!r.ok){ toast(t(`Could not watch — ${r.stderr}`, `No se pudo vigilar — ${r.stderr}`)); return; }
  WATCH = r;
  btn?.classList.add("on");
  toast(t(`Watching ${describe()}`, `Vigilando ${describe()}`));
}
$("#cv-watch")?.addEventListener("click", toggleWatch);

loadTarget();
/* Read where nft is configured to run, and do not go and knock.
 *
 * This called refreshTarget() here, which is two ssh connections — is the host
 * reachable, and is a rollback pending — before the window had settled. On a
 * firewall that is slow or away that is sixteen seconds of timeout, and on any
 * firewall at all it is an application that reaches into production because
 * somebody opened an editor. The README's first promise is that nothing
 * reaches a live host unless you ask.
 *
 * So the chip shows the destination and says it has not been contacted. It
 * finds out when something needs the answer, which is a short list: opening
 * the target dialog, and opening the apply dialog. Everything else that talks
 * to a host — validate, import, counters, watch — asks on its own account and
 * reports for itself. */
REACH = null;
paintTargetChip(null);
paintHostStatus(null);
/* The chip carries its own tooltip rather than a data-tt, so nothing else
   redraws it when the language changes. */
onRender(() => { paintTargetChip(REACH); paintHostStatus(REACH); });
/* Except in a browser, where the answer costs nothing: probe() settles that
   from isDesktop() alone and never reaches for a socket. Leaving it unknown
   there would only mean the apply dialog offering a button it knows cannot
   work. Not knowing and not asking are different things; so are not knowing
   and knowing already. */
if(!native.isDesktop()) refreshTarget();

/* The first-run dialog used to open here, over a ruleset the user had not
   asked for. The empty state says the same three things without anything
   behind it to dismiss it onto. */

