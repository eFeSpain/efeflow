import { defineConfig } from "vite";

// Tauri serves the frontend from a dev server in development and from the
// bundled dist/ in release. The fixed port matters: tauri.conf.json points at
// it, and a shifting port breaks `tauri dev`.
export default defineConfig({
  clearScreen: false,
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
  },
});
