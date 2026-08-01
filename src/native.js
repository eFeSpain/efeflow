/* The bridge to the Rust side. Everything here answers in the browser too,
   with `available:false`, so `npm run dev` in a plain tab stays usable and no
   caller needs to branch on the environment. */

const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

/* Lazily resolved so the module has no top-level await: WebView2 and WKWebView
   handle it, but keeping the bundle at plain es2021 avoids a whole class of
   "works on my machine" between the three webviews. */
let corePromise = null;
const core = () => (corePromise ||= import("@tauri-apps/api/core"));

async function invoke(cmd, args) {
  if (!inTauri) throw new Error("not running inside the desktop app");
  const { invoke: fn } = await core();
  return fn(cmd, args);
}

export const isDesktop = () => inTauri;

export const platform = {
  os: "web",
  arch: "",
  local_nft_possible: false,
};

/* Callers await this once at boot; everything after reads `platform` directly. */
export const ready = (async () => {
  if (!inTauri) return platform;
  try {
    Object.assign(platform, await invoke("platform"));
  } catch {
    /* keep the web defaults */
  }
  return platform;
})();

/* Linux ships WebKitGTK, whose backdrop-filter support has historically been
   poor. The stylesheet reads this to swap glass for a solid surface. */
export function applyPlatformClass() {
  const root = document.documentElement;
  root.dataset.os = platform.os;
  if (platform.os === "linux") root.classList.add("no-glass");
  if (inTauri) root.classList.add("desktop");
}

const unavailable = (what) => ({
  ok: false,
  stdout: "",
  stderr: `${what} needs the desktop app — you are running eFeFlow in a browser.`,
  code: null,
});

export const LOCAL = { kind: "local" };
export const ssh = (host, { user, port, sudo = true } = {}) => ({
  kind: "ssh",
  host,
  user: user || null,
  port: port || null,
  sudo,
});

export async function nftVersion(target = LOCAL) {
  if (!inTauri) return unavailable("Detecting nft");
  return invoke("nft_version", { target });
}

export async function nftList(target = LOCAL) {
  if (!inTauri) return unavailable("Reading the live ruleset");
  return invoke("nft_list", { target });
}

/* The authority on whether a ruleset is valid. Our analyser is an
   approximation; this is the real parser. */
export async function nftCheck(ruleset, target = LOCAL) {
  if (!inTauri) return unavailable("Validating with nft -c");
  return invoke("nft_check", { target, ruleset });
}

export async function nftApply(ruleset, target = LOCAL, confirmed = false) {
  if (!inTauri) return unavailable("Applying a ruleset");
  return invoke("nft_apply", { target, ruleset, confirmed });
}

/* ── files ─────────────────────────────────────────────────────────────
   Native dialogs when we have them, a download and an <input type=file>
   when we do not. */

export async function saveTextFile(name, text, filters) {
  if (inTauri) {
    const { save } = await import("@tauri-apps/plugin-dialog");
    const { writeTextFile } = await import("@tauri-apps/plugin-fs");
    const path = await save({ defaultPath: name, filters });
    if (!path) return null;
    await writeTextFile(path, text);
    return path;
  }
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
  return name;
}

export async function openTextFile(filters) {
  if (inTauri) {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const { readTextFile } = await import("@tauri-apps/plugin-fs");
    const path = await open({ multiple: false, filters });
    if (!path) return null;
    return { path, text: await readTextFile(path) };
  }
  return new Promise((resolve) => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".json,.nft,.conf,.txt";
    input.addEventListener("change", () => {
      const f = input.files?.[0];
      if (!f) return resolve(null);
      const rd = new FileReader();
      rd.onload = () => resolve({ path: f.name, text: String(rd.result) });
      rd.readAsText(f);
    });
    input.click();
  });
}

/* ── window controls, since the window is frameless ─────────────────── */
export async function windowAction(action) {
  if (!inTauri) return;
  const { getCurrentWindow } = await import("@tauri-apps/api/window");
  const w = getCurrentWindow();
  if (action === "minimize") return w.minimize();
  if (action === "maximize") return w.toggleMaximize();
  if (action === "close") return w.close();
  if (action === "startDrag") return w.startDragging();
}
