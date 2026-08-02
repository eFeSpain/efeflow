import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

/* Tauri gates every IPC call behind a capability. A missing grant is not a
   crash — the call just rejects, and the button looks dead. The window is
   frameless, so minimise/maximise/close are the app's own responsibility and
   a forgotten permission means the titlebar stops working. */

const caps = JSON.parse(
  readFileSync(new URL("../src-tauri/capabilities/default.json", import.meta.url), "utf8"),
);
const native = readFileSync(new URL("../src/native.js", import.meta.url), "utf8");
const granted = new Set(caps.permissions.filter((p) => typeof p === "string"));

/* window API method → the permission that unlocks it */
const NEEDS = {
  minimize: "core:window:allow-minimize",
  maximize: "core:window:allow-maximize",
  unmaximize: "core:window:allow-unmaximize",
  toggleMaximize: "core:window:allow-toggle-maximize",
  isMaximized: "core:window:allow-is-maximized",
  close: "core:window:allow-close",
  startDragging: "core:window:allow-start-dragging",
  setFocus: "core:window:allow-set-focus",
  setTitle: "core:window:allow-set-title",
};

test("every window call the frontend makes is granted", () => {
  const missing = [];
  for (const [method, permission] of Object.entries(NEEDS)) {
    const used = new RegExp(`\\bw\\.${method}\\s*\\(`).test(native);
    if (used && !granted.has(permission)) missing.push({ method, permission });
  }
  assert.deepEqual(
    missing,
    [],
    "window calls without a capability:\n" +
      missing.map((m) => `  w.${m.method}() needs ${m.permission}`).join("\n"),
  );
});

test("the plugins the bridge imports are granted", () => {
  if (/plugin-dialog/.test(native)) {
    assert.ok(granted.has("dialog:allow-open"), "dialog open is used but not granted");
    assert.ok(granted.has("dialog:allow-save"), "dialog save is used but not granted");
  }
  if (/plugin-fs/.test(native)) {
    assert.ok(granted.has("fs:allow-read-text-file"), "fs read is used but not granted");
    assert.ok(granted.has("fs:allow-write-text-file"), "fs write is used but not granted");
    assert.ok(
      caps.permissions.some((p) => p && p.identifier === "fs:scope"),
      "fs access without a scope resolves to nothing readable",
    );
  }
});

test("every command registered in Rust is reachable, and vice versa", () => {
  const main = readFileSync(new URL("../src-tauri/src/main.rs", import.meta.url), "utf8");
  const handler = main.match(/generate_handler!\[([\s\S]*?)\]/);
  assert.ok(handler, "invoke_handler should be discoverable");

  const registered = handler[1]
    .split(",")
    .map((s) => s.trim().replace(/^nft::/, ""))
    .filter(Boolean);

  const invoked = [...native.matchAll(/invoke\("(\w+)"/g)].map((m) => m[1]);
  for (const cmd of invoked) {
    assert.ok(registered.includes(cmd), `native.js calls "${cmd}", which Rust does not register`);
  }
  assert.ok(registered.length >= 5, "expected the nft commands to be registered");
});

/* The catalogue is a file in the app config directory. Every one of these is a
   silent rejection if it is missing: readSetting returns null and the entries
   you added yesterday are simply not there, with nothing said. */
test("the settings file the catalogue lives in is reachable", () => {
  for (const p of ["fs:allow-read-text-file", "fs:allow-write-text-file",
                   "fs:allow-mkdir", "fs:allow-exists"])
    assert.ok(granted.has(p), `native.js reads and writes settings; ${p} is not granted`);

  const scope = caps.permissions.find((p) => p && p.identifier === "fs:scope");
  assert.ok(scope, "fs:scope is what says which directories those permissions apply to");
  const paths = scope.allow.map((a) => a.path);
  assert.ok(paths.includes("$APPCONFIG"), "the directory itself, so it can be created");
  assert.ok(paths.includes("$APPCONFIG/**"), "and the file inside it");
});

/* $APPCONFIG is a Tauri variable; a typo in one is not an error, it is a scope
   that matches nothing.
   The list comes from the CLI package rather than src-tauri/gen/schemas, which
   Tauri writes during a build and .gitignore excludes — so it is on this
   machine and absent from every clean checkout, which is where CI runs. */
test("every path variable in the scope is one Tauri defines", () => {
  const schema = JSON.parse(readFileSync(
    new URL("../node_modules/@tauri-apps/cli/config.schema.json", import.meta.url), "utf8"));
  const known = new Set(
    [...schema.definitions.FsScope.description.matchAll(/\$[A-Z]+/g)].map((m) => m[0]));
  assert.ok(known.has("$APPCONFIG"), "the list itself should be readable");

  const scope = caps.permissions.find((p) => p && p.identifier === "fs:scope");
  for (const { path } of scope.allow) {
    const v = path.match(/^\$[A-Z]+/)?.[0];
    if (!v) continue;
    assert.ok(known.has(v), `${v} is not a path variable Tauri knows`);
  }
});
