// The window is frameless: eFeFlow draws its own chrome so the titlebar can
// carry the project name, the language switch and the validation state.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod nft;

use tauri::Manager;

#[tauri::command]
fn platform() -> serde_json::Value {
    serde_json::json!({
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        // Only Linux can have a local nft. Everywhere else the SSH transport
        // is not a fallback, it is the design.
        "local_nft_possible": cfg!(target_os = "linux"),
    })
}

fn main() {
    tauri::Builder::default()
        // First, so a second launch never gets as far as a second window: it
        // hands its arguments to the instance already running and exits. This
        // one just brings that window forward. It matters more here than in most
        // apps — two eFeFlows could each arm a rollback on the same host, and
        // the second arm would photograph the first's half-applied ruleset as
        // the one to go back to.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.unminimize();
                let _ = win.show();
                let _ = win.set_focus();
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .invoke_handler(tauri::generate_handler![
            platform,
            nft::host_probe,
            nft::nft_list,
            nft::nft_check,
            nft::nft_apply,
            nft::nft_arm,
            nft::nft_disarm,
            nft::nft_armed,
            nft::nft_rollback,
            nft::nft_rule_op,
            nft::nft_watch,
            nft::nft_unwatch,
        ])
        .setup(|app| {
            let win = app.get_webview_window("main").expect("main window");
            // WebKitGTK is weak on backdrop-filter; the frontend degrades the
            // glass to a solid surface when it detects Linux.
            #[cfg(target_os = "macos")]
            {
                use tauri::TitleBarStyle;
                let _ = win.set_title_bar_style(TitleBarStyle::Overlay);
            }
            let _ = win.show();
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running eFeFlow");
}
