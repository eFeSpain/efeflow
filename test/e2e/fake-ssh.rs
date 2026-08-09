//! A firewall on the other end of an ssh, for the end-to-end run.
//!
//! The Tauri bridge cannot be stubbed from the page — `__TAURI_INTERNALS__` is
//! non-writable and non-configurable, and Tauri injects it after any init
//! script we could add. What *can* be replaced is the far end: the Rust side
//! runs `Command::new("ssh")`, resolved through PATH, so putting this first on
//! PATH makes every layer real except the machine. The real argv is built, a
//! real process is spawned, and the real parser reads what comes back.
//!
//! It has to be `ssh.exe`: Rust's `Command` tries the literal name and `.exe`
//! and does not honour PATHEXT, so a `.cmd` or a `.bat` is invisible to it.
//!
//! What it answers with is decided by two environment variables, so one binary
//! covers every scenario:
//!
//!   EFEFLOW_FAKE_RULESET  path to the file `nft -a list ruleset` returns
//!   EFEFLOW_FAKE_FAIL     `read` to refuse the read the way a non-root host
//!                         does, `probe` to refuse the connection entirely
use std::io::Read;

fn main() {
    let argv: String = std::env::args().skip(1).collect::<Vec<_>>().join(" ");
    let fail = std::env::var("EFEFLOW_FAKE_FAIL").unwrap_or_default();

    if fail == "probe" {
        eprintln!("ssh: connect to host fw.example port 22: Connection timed out");
        std::process::exit(255);
    }

    if argv.contains("list ruleset") {
        if fail == "read" {
            eprintln!("Error: Could not process rule: Operation not permitted (you must be root)");
            std::process::exit(1);
        }
        let path = std::env::var("EFEFLOW_FAKE_RULESET").unwrap_or_default();
        match std::fs::read_to_string(&path) {
            Ok(s) => print!("{s}"),
            Err(e) => {
                eprintln!("the stand-in could not read {path}: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    /* `shell()` sends its script on stdin as `sh -s`, so what is being asked
    for is in there rather than in the argv. */
    let mut stdin = String::new();
    let _ = std::io::stdin().read_to_string(&mut stdin);

    if stdin.contains("nft --version") {
        println!("nft\tnftables v1.1.3 (Commodore Bullmoose #4)");
        println!("kernel\tLinux 6.12.0-amd64");
    } else if stdin.contains("armed") || stdin.contains("efeflow") {
        /* no rollback pending, which is the state every scenario starts in */
        println!("clear");
    }
}
