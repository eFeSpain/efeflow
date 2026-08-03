//! The native half of eFeFlow: everything the browser cannot do.
//!
//! Two transports, one shape. Locally we run `nft` directly; remotely we run
//! it through `ssh`. The frontend does not care which — it asks for a ruleset
//! or a syntax check and gets the same struct back, so a firewall on the other
//! side of the world behaves like one under the desk.

use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use tauri::{AppHandle, Emitter};

/// Where a ruleset comes from, or where a check should run.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Target {
    /// The machine eFeFlow is running on.
    Local,
    /// A remote host reached over the system `ssh` binary, so the user's
    /// existing keys, agent, and ~/.ssh/config all apply. We deliberately do
    /// not reimplement SSH.
    Ssh {
        host: String,
        #[serde(default)]
        user: Option<String>,
        #[serde(default)]
        port: Option<u16>,
        /// Prefix commands with sudo — reading the ruleset usually needs root.
        #[serde(default)]
        sudo: bool,
    },
}

#[derive(Debug, Serialize)]
pub struct Outcome {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
    /// None when the process could not be spawned at all.
    pub code: Option<i32>,
}

impl Outcome {
    fn failed(msg: impl Into<String>) -> Self {
        Outcome {
            ok: false,
            stdout: String::new(),
            stderr: msg.into(),
            code: None,
        }
    }
}

impl Target {
    /// Is this somewhere we are willing to point `ssh` at?
    ///
    /// Nothing here reaches a shell — every command is argv — so the danger is
    /// not quoting, it is that `ssh` reads its own destination with getopt. A
    /// host of `-oProxyCommand=…` is not a host, it is an option, and the
    /// option it is happens to run a command. The `--` below closes that on
    /// its own; this refuses as well, because a destination beginning with a
    /// dash is a mistake or an attack in every case and neither deserves a
    /// connection attempt.
    fn check(&self) -> Result<(), String> {
        let Target::Ssh { host, user, .. } = self else {
            return Ok(());
        };
        if host.trim().is_empty() {
            return Err("no host to connect to".into());
        }
        for (what, v) in [
            ("host", host.as_str()),
            ("user", user.as_deref().unwrap_or("")),
        ] {
            if v.starts_with('-') {
                return Err(format!(
                    "refusing an ssh {what} that begins with a dash: {v}"
                ));
            }
            if v.contains(|c: char| c.is_whitespace() || c == '\0') {
                return Err(format!("refusing an ssh {what} with whitespace in it: {v}"));
            }
        }
        Ok(())
    }
}

/// Build the argv for a command against a target, without a shell in the way.
fn argv(target: &Target, cmd: &[&str]) -> (String, Vec<String>) {
    match target {
        Target::Local => (
            cmd[0].to_string(),
            cmd[1..].iter().map(|s| s.to_string()).collect(),
        ),
        Target::Ssh {
            host,
            user,
            port,
            sudo,
        } => {
            let mut args: Vec<String> = vec![
                "-o".into(),
                "BatchMode=yes".into(),
                "-o".into(),
                "ConnectTimeout=8".into(),
            ];
            if let Some(p) = port {
                args.push("-p".into());
                args.push(p.to_string());
            }
            /* everything after this is a destination and a command, never an
            option, whatever it begins with */
            args.push("--".into());
            args.push(match user {
                Some(u) => format!("{u}@{host}"),
                None => host.clone(),
            });
            if *sudo {
                args.push("sudo".into());
            }
            args.extend(cmd.iter().map(|s| s.to_string()));
            ("ssh".to_string(), args)
        }
    }
}

/// Run a shell script on the target, handed over on stdin.
///
/// Passing a script as an argument means quoting it for our shell and then
/// again for the login shell on the other end of ssh, and getting that wrong
/// on a command that edits a firewall is not a class of bug worth inviting.
/// `sh -s` reads the script from stdin, so there is no quoting at all.
fn shell(target: &Target, script: &str) -> Outcome {
    run(target, &["sh", "-s"], Some(script))
}

fn run(target: &Target, cmd: &[&str], stdin: Option<&str>) -> Outcome {
    if let Err(e) = target.check() {
        return Outcome::failed(e);
    }
    let (program, args) = argv(target, cmd);
    let mut child = match Command::new(&program)
        .args(&args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return Outcome::failed(format!(
                "could not run `{program}`: {e}. \
                 On Windows and macOS there is no local nft — use an SSH target."
            ))
        }
    };

    if let Some(text) = stdin {
        if let Some(mut pipe) = child.stdin.take() {
            let _ = pipe.write_all(text.as_bytes());
        }
    }

    match child.wait_with_output() {
        Ok(out) => Outcome {
            ok: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            code: out.status.code(),
        },
        Err(e) => Outcome::failed(e.to_string()),
    }
}

/// Is there an nft we can talk to, and what is it running on?
///
/// Both answers in one round trip, because both are wanted at the same moment
/// and one of them is over a network. Tagged rather than positional: newer
/// `nft --version` prints a block of build details under the version line, so
/// "the second line" is not the kernel on every host.
#[tauri::command]
pub fn host_probe(target: Target) -> Outcome {
    shell(
        &target,
        "set -e\n\
         printf 'nft\\t'; nft --version | head -n 1\n\
         printf 'kernel\\t'; uname -sr\n",
    )
}

/// Read the live ruleset. `-a` includes handles, which we strip on import but
/// which make the source recognisable to anyone who has run the command.
#[tauri::command]
pub fn nft_list(target: Target) -> Outcome {
    run(&target, &["nft", "-a", "list", "ruleset"], None)
}

/// Validate without applying. This is the check that matters: our own analyser
/// is an approximation, `nft -c` is the authority.
#[tauri::command]
pub fn nft_check(target: Target, ruleset: String) -> Outcome {
    run(&target, &["nft", "-c", "-f", "-"], Some(&ruleset))
}

/// Change one rule of a running ruleset, addressed by its handle.
///
/// The whole-ruleset apply is atomic and replaces tables entire, which resets
/// every counter in them to change one line. This is the smaller operation:
/// nftables' own way of naming a single rule.
///
/// The handle is a number and the op is one of two words, both checked here
/// rather than trusted — everything else on this side is argv, but this one
/// composes an nft command out of what a frontend sent.
#[tauri::command]
pub fn nft_rule_op(
    target: Target,
    op: String,
    table: String,
    chain: String,
    handle: u64,
    rule: String,
) -> Outcome {
    if op != "delete" && op != "replace" {
        return Outcome::failed(format!("refusing an unknown rule operation: {op}"));
    }
    if !is_ident(&table) || !is_ident(&chain) {
        return Outcome::failed("refusing a table or chain name that is not one".to_string());
    }
    if op == "replace" && rule.trim().is_empty() {
        return Outcome::failed("a replacement needs a rule".to_string());
    }
    /* Through the shell on stdin, like the rollback scripts, and for the same
    reason: over ssh the argv is joined and re-split by the login shell, so
    a rule carrying `log prefix "ssh "` would arrive with its quotes eaten
    and its spaces collapsed. Single-quoted here, the rule reaches nft as
    the one string it is. */
    let body = if op == "replace" {
        format!(" {}", sq(&rule))
    } else {
        String::new()
    };
    shell(
        &target,
        &format!("nft {op} rule {table} {chain} handle {handle}{body}\n"),
    )
}

/// Single-quote for a POSIX shell: the only character that matters inside is
/// the quote itself, and the way out of one is to close, escape, reopen.
fn sq(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// A table is `inet filter` and a chain is `input`: letters, digits, a few
/// punctuation marks people really use, and nothing that could become another
/// argument.
fn is_ident(s: &str) -> bool {
    !s.is_empty()
        && s.len() < 128
        && s.split(' ').all(|w| {
            !w.is_empty()
                && w.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
        })
}

/* ── the safety net ──────────────────────────────────────────────────────
Applying a firewall ruleset can cut off the connection you applied it over,
and a rollback driven from the editor cannot help with that: it would have
to reach the machine it has just locked itself out of. So the net is armed
on the host. Take a copy of the running ruleset, leave a sentinel file, and
start a detached process that restores the copy when the timer runs out
unless the sentinel has been removed first. Confirming removes it.

Routers have called this commit-confirm for thirty years, and this is why. */

/* These lived in /tmp, which is the wrong place for either of them.
`nft list ruleset > /tmp/efeflow-rollback.nft` is a redirect performed by
root at a path any local user can guess and, in a sticky directory, can
create ahead of it as a symlink pointing anywhere it likes. `umask 077`
fixes the mode of a file we create; it does nothing about a file that is
already there. And the far end of it is `nft -f` on that same path, as
root — so whoever wins the race chooses the firewall.

/run is root-owned, on tmpfs, and cleared on reboot. The last of those is
worth having on its own account: after a reboot the ruleset comes back from
/etc, and a rollback copy that outlived the kernel it was taken from would
restore something nobody asked for. */
const DIR: &str = "/run/efeflow";
const ROLLBACK: &str = "/run/efeflow/rollback.nft";
const SENTINEL: &str = "/run/efeflow/armed";

/// Every arm gets a token, and the timer it starts only fires while the
/// sentinel still holds that token.
///
/// Without one, arming twice was the way to lose the thing being kept safe.
/// Apply a ruleset that breaks something, do not confirm it, fix it and apply
/// again — and the second arm copied the *broken* ruleset aside as the one to
/// go back to. The net then restored the breakage, which is worse than having
/// had no net at all, because the whole point of it is to be the thing you did
/// not have to think about.
///
/// So the copy is taken once and kept until it is used or the arming ends, and
/// re-arming replaces the token instead — which retires the previous timer
/// rather than leaving it to fire early against a window somebody has since
/// extended.
fn token() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("{t:x}-{:x}", N.fetch_add(1, Ordering::Relaxed))
}

/// Copy the running ruleset aside and schedule its restoration in `seconds`.
///
/// Returns the copy it took, so the caller can show what it would go back to.
#[tauri::command]
pub fn nft_arm(target: Target, seconds: u32) -> Outcome {
    // clamped here rather than trusted: this number is spliced into a script
    let secs = seconds.clamp(10, 3600);
    let tok = token();
    let script = format!(
        "set -e\n\
         umask 077\n\
         mkdir -p -m 700 {DIR}\n\
         \
         # the copy is the ruleset as it was before eFeFlow touched anything,\n\
         # so an arm that finds one already armed keeps it rather than\n\
         # photographing whatever it has just been asked to replace\n\
         if [ ! -s {SENTINEL} ] || [ ! -s {ROLLBACK} ]; then\n\
           nft list ruleset > {ROLLBACK}\n\
         fi\n\
         printf '%s' '{tok}' > {SENTINEL}\n\
         \
         nohup sh -c 'sleep {secs}; \
           if [ \"$(cat {SENTINEL} 2>/dev/null)\" = \"{tok}\" ]; then \
             nft -f {ROLLBACK}; rm -f {SENTINEL}; \
           fi' </dev/null >/dev/null 2>&1 &\n\
         cat {ROLLBACK}\n"
    );
    shell(&target, &script)
}

/// Keep what is running. The scheduled restore finds no sentinel and does
/// nothing; the copy is left behind on purpose, as the last known-good.
#[tauri::command]
pub fn nft_disarm(target: Target) -> Outcome {
    shell(&target, &format!("rm -f {SENTINEL}\n"))
}

/// Is a rollback still pending on this host? Answers `armed` or `clear` so a
/// window that was closed, or an editor that was restarted, can find out.
#[tauri::command]
pub fn nft_armed(target: Target) -> Outcome {
    /* `-s` and not `-f`: the sentinel carries the token of the arming that owns
    it, and an empty one belongs to nobody */
    shell(
        &target,
        &format!("if [ -s {SENTINEL} ]; then echo armed; else echo clear; fi\n"),
    )
}

/// Put the copy back now, without waiting for the timer.
///
/// The sentinel goes first, so the pending timer finds its token gone and
/// stays out of the way of a restore already in progress.
#[tauri::command]
pub fn nft_rollback(target: Target) -> Outcome {
    shell(
        &target,
        &format!(
            "rm -f {SENTINEL}\n\
             if [ ! -s {ROLLBACK} ]; then\n\
               echo 'there is no rollback copy on this host to go back to' >&2\n\
               exit 1\n\
             fi\n\
             nft -f {ROLLBACK}\n"
        ),
    )
}

/// Apply atomically. Refuses unless the caller has confirmed, because this is
/// the one operation that can lock someone out of a machine.
#[tauri::command]
pub fn nft_apply(target: Target, ruleset: String, confirmed: bool) -> Outcome {
    if !confirmed {
        return Outcome::failed("refusing to apply without explicit confirmation");
    }
    let check = run(&target, &["nft", "-c", "-f", "-"], Some(&ruleset));
    if !check.ok {
        return Outcome {
            ok: false,
            stdout: String::new(),
            stderr: format!("validation failed, nothing was applied:\n{}", check.stderr),
            code: check.code,
        };
    }
    run(&target, &["nft", "-f", "-"], Some(&ruleset))
}

/* ── watching the host ───────────────────────────────────────────────────
`nft monitor` stays open and prints every change the kernel makes to the
ruleset as it happens: somebody else's `nft add rule`, fail2ban banning an
address, Docker restarting.

Every other command here is run-and-collect. This one is a child process
that outlives the call, so its lines go to the frontend as events and the
handle to it is kept so it can be stopped. One at a time: a second watch
would be a second stream nobody asked for. */

static WATCH: Mutex<Option<Child>> = Mutex::new(None);

#[tauri::command]
pub fn nft_watch(app: AppHandle, target: Target) -> Outcome {
    if let Err(e) = target.check() {
        return Outcome::failed(e);
    }
    nft_unwatch();

    let (program, args) = argv(&target, &["nft", "monitor", "ruleset"]);
    let child = Command::new(&program)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();

    let mut child = match child {
        Ok(c) => c,
        Err(e) => return Outcome::failed(format!("could not run `{program}`: {e}")),
    };

    if let Some(out) = child.stdout.take() {
        let app = app.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                if line.trim().is_empty() {
                    continue;
                }
                let _ = app.emit("nft-monitor", line);
            }
            /* the stream ending is news too: the connection dropped, or nft did */
            let _ = app.emit("nft-monitor-end", ());
        });
    }

    *WATCH.lock().unwrap() = Some(child);
    Outcome {
        ok: true,
        stdout: String::new(),
        stderr: String::new(),
        code: Some(0),
    }
}

#[tauri::command]
pub fn nft_unwatch() -> Outcome {
    if let Some(mut c) = WATCH.lock().unwrap().take() {
        let _ = c.kill();
        let _ = c.wait();
    }
    Outcome {
        ok: true,
        stdout: String::new(),
        stderr: String::new(),
        code: Some(0),
    }
}
