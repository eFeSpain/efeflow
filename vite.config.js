import { defineConfig } from "vite";
import { readFileSync } from "node:fs";

/* The about panel used to read `1.0.0 · build 2026.08.01` out of the markup: a
   version that would go stale the next time package.json moved, beside a build
   date that was never a build of anything. Take the one that is true from the
   one place that holds it, and drop the one that is not. */
const { version } = JSON.parse(readFileSync(new URL("package.json", import.meta.url), "utf8"));

// Tauri serves the frontend from a dev server in development and from the
// bundled dist/ in release. The fixed port matters: tauri.conf.json points at
// it, and a shifting port breaks `tauri dev`.
export default defineConfig({
  clearScreen: false,
  define: { __APP_VERSION__: JSON.stringify(version) },
  server: {
    port: 5183,
    strictPort: true,
    watch: { ignored: ["**/src-tauri/**"] },
  },
  build: {
    // The system webview is the floor: WebView2 on Windows, WKWebView on
    // macOS, WebKitGTK on Linux. All three have shipped top-level await for
    // years, which the entry module uses to settle the platform before paint.
    target: "es2022",
    minify: "esbuild",
    sourcemap: true,
    outDir: "dist",
    emptyOutDir: true,
    rollupOptions: {
      /* A name imported from a module that does not export it is not a
         warning, it is `undefined()` at the moment that line runs. `nftVersion`
         was renamed and one call site was missed; rollup said so, the build
         went green, and it shipped in a release bundle — reachable only on the
         one platform that has a local nft, which is the platform nobody here
         builds on. Nothing about that should be survivable. */
      onwarn(warning, warn) {
        if (warning.code === "MISSING_EXPORT" || warning.code === "UNRESOLVED_IMPORT")
          throw new Error(`${warning.code}: ${warning.message}`);
        warn(warning);
      },
    },
  },
});
