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

#[derive(Debug, Default, Serialize)]
pub struct Outcome {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
    /// None when the process could not be spawned at all.
    pub code: Option<i32>,
    /// Why a local call could not be made, as a word rather than a sentence.
    ///
    /// The sentence used to be here, in English, and the interface put it in a
    /// toast — which is bilingual everywhere else and gives you two seconds to
    /// read it. A code lets the interface say it in the user's language, in a
    /// place that stays on screen. `stderr` keeps the prose for the CLI and
    /// for whoever is reading a diagnostic.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<&'static str>,
}

impl Outcome {
    fn failed(msg: impl Into<String>) -> Self {
        Outcome {
            ok: false,
            stderr: msg.into(),
            ..Default::default()
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

/// Where nft actually lives, which is not where a login shell looks for it.
///
/// `nft` is in /usr/sbin. A non-interactive ssh command gets
/// `/usr/local/bin:/usr/bin:/bin:/usr/games` on Debian — no sbin at all — so
/// `ssh fw nft list ruleset` answers "nft: command not found", which reads as
/// *you have not installed nftables* on a machine where it is installed and
/// working. It only ever worked because sudo replaces the PATH with its own
/// `secure_path`, so turning the sudo toggle off broke the connection and
/// blamed the host. This is that same list, said out loud.
const SBIN_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/* ── the privileges the local transport needs ────────────────────────────
Reading a ruleset is not a read as far as the kernel is concerned. `nft list
ruleset` speaks netlink and wants CAP_NET_ADMIN, and nftables has no lesser
permission to ask for — which is why opening a *file* asks nothing and reading
the *machine* used to mean running the whole editor as root.

So the elevation is per call and it is not ours to grant: the packaged .deb and
.rpm install a helper that does three read-only things, and a polkit action
that authorises exactly that program. When both are present and we are not
already root, the local commands go through `pkexec`; one desktop prompt, kept
for the session, and the editor itself stays an ordinary user process.

None of this is required. Without the package — an AppImage, a `cargo run`, a
machine with no polkit agent — the commands run as before and fail as before,
and local_hint() is what turns that failure into something the user can act on
rather than "Operation not permitted". */

/// The three local operations that need root and change nothing.
#[derive(Clone, Copy)]
enum Verb {
    Read,
    Check,
    Monitor,
}

impl Verb {
    /// The word the helper takes. Also what the polkit action is scoped to.
    ///
    /// The one caller is inside `#[cfg(target_os = "linux")]`, because pkexec
    /// and polkit are, so on Windows and macOS this is dead code and
    /// `-D warnings` refuses to build. Not cfg'd away, because the test below
    /// checks these words against the helper's own case statement and that
    /// check is worth running wherever the suite runs. CI lints on ubuntu
    /// only, so nothing there would ever have said so.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn word(self) -> &'static str {
        match self {
            Verb::Read => "read",
            Verb::Check => "check",
            Verb::Monitor => "monitor",
        }
    }

    /// The command itself, for when we already have the privileges or have no
    /// way to ask for them. The helper runs these same three.
    fn nft(self) -> &'static [&'static str] {
        match self {
            Verb::Read => &["nft", "-a", "list", "ruleset"],
            Verb::Check => &["nft", "-c", "-f", "-"],
            Verb::Monitor => &["nft", "monitor", "ruleset"],
        }
    }

    /// What to tell somebody the command just failed on for want of root.
    fn hint(self) -> &'static str {
        match self {
            Verb::Read => "Reading this machine's ruleset needs root — install the eFeFlow .deb or .rpm to authorise it from the desktop, or run `sudo nft -a list ruleset > ruleset.nft` and open that file.",
            Verb::Check => "Checking against this machine's kernel needs root — install the eFeFlow .deb or .rpm to authorise it from the desktop, or check on an SSH target instead.",
            Verb::Monitor => "Watching this machine's ruleset needs root — install the eFeFlow .deb or .rpm to authorise it from the desktop, or watch an SSH target instead.",
        }
    }
}

#[cfg(target_os = "linux")]
fn am_root() -> bool {
    /* geteuid cannot fail and touches nothing — the unsafe is the FFI call
    itself, not anything this does with the answer. */
    unsafe { libc::geteuid() == 0 }
}

/// Where the packages put the helper. The env var is for running from a build
/// tree, where there is no installed copy to find.
#[cfg(target_os = "linux")]
fn helper() -> Option<String> {
    use std::path::Path;
    if let Ok(p) = std::env::var("EFEFLOW_NFT_HELPER") {
        return (!p.is_empty() && Path::new(&p).is_file()).then_some(p);
    }
    [
        "/usr/libexec/efeflow/efeflow-nft-helper",
        "/usr/lib/efeflow/efeflow-nft-helper",
        "/usr/local/libexec/efeflow/efeflow-nft-helper",
    ]
    .into_iter()
    .find(|p| Path::new(p).is_file())
    .map(str::to_string)
}

#[cfg(target_os = "linux")]
fn pkexec() -> Option<&'static str> {
    use std::path::Path;
    ["/usr/bin/pkexec", "/bin/pkexec"]
        .into_iter()
        .find(|p| Path::new(p).is_file())
}

/// Whether this call will go through pkexec, which decides how to read a
/// failure: 126 from pkexec is a refused authorisation, not a broken firewall.
#[cfg(target_os = "linux")]
fn elevating() -> bool {
    !am_root() && helper().is_some() && pkexec().is_some()
}
#[cfg(not(target_os = "linux"))]
fn elevating() -> bool {
    false
}

/// The program and argv for one verb against the local machine.
fn local_argv(v: Verb) -> (String, Vec<String>) {
    #[cfg(target_os = "linux")]
    if !am_root() {
        if let (Some(h), Some(px)) = (helper(), pkexec()) {
            return (px.to_string(), vec![h, v.word().to_string()]);
        }
    }
    let c = v.nft();
    (
        c[0].to_string(),
        c[1..].iter().map(|s| s.to_string()).collect(),
    )
}

/// Which of the two halves is missing, when a call that needed root did not
/// even get as far as asking for it.
///
/// "This needs root" and then no prompt is the worst of both: reported from
/// the running app as "me sale un mensaje que dice que necesita root, pero no
/// me pide root". There are two quite different reasons for it and the fix is
/// different for each, so they are not going to share a sentence.
#[cfg(target_os = "linux")]
fn why_not_elevated() -> &'static str {
    if helper().is_none() {
        "needs-root-uninstalled"
    } else if pkexec().is_none() {
        "needs-root-no-pkexec"
    } else {
        "needs-root"
    }
}
#[cfg(not(target_os = "linux"))]
fn why_not_elevated() -> &'static str {
    "needs-root"
}

/// Say what a local failure was actually about.
///
/// `Operation not permitted` on its own is a true statement that helps nobody:
/// it does not say which permission, that the application need not have it, or
/// what to do instead. Only the shapes that are really about privilege are
/// rewritten — an nft that rejects a ruleset must keep saying so in its own
/// words, because that message is the product.
fn local_hint(out: Outcome, v: Verb, elevated: bool) -> Outcome {
    if out.ok {
        return out;
    }
    let both = format!("{} {}", out.stderr, out.stdout);
    /* pkexec's own exit codes: 126 is "not authorised", which covers both a
    wrong password and a dismissed dialog, and 127 is a helper it could not
    run at all. Neither reaches nft, so neither says anything about nft. */
    let (code, prose) = match out.code {
        Some(126) if elevated => (
            "declined",
            "The authorisation was declined, so nothing was read.".to_string(),
        ),
        /* 127 has two quite different causes and this used to name only one of
        them, confidently. Measured on a Debian 13 desktop: the helper was
        root-owned, mode 755, with its shebang, and `execve` ran it — and
        pkexec still exited 127, because the application had been started
        outside the graphical session and polkit had no agent to ask with.
        Being told to reinstall a package that is installed correctly is worse
        than being told nothing.

        pkexec says which it was, so read it rather than guess. */
        Some(127) if elevated && both.contains("authentication agent") => (
            "no-polkit-agent",
            "Nothing asked for a password, so nothing was read. This is running outside a \
             desktop session that polkit can prompt in — launch eFeFlow from your applications \
             menu rather than from a terminal over ssh, or use an SSH target instead."
                .to_string(),
        ),
        Some(127) if elevated => (
            "helper-broken",
            "polkit could not start the eFeFlow helper — reinstall the package, or check that \
             /usr/libexec/efeflow/efeflow-nft-helper is owned by root and executable."
                .to_string(),
        ),
        _ if both.contains("Operation not permitted")
            || both.contains("must be root")
            || both.contains("Permission denied") =>
        {
            (why_not_elevated(), v.hint().to_string())
        }
        _ => return out,
    };
    Outcome {
        hint: Some(code),
        stderr: if out.stderr.trim().is_empty() {
            prose
        } else {
            format!("{prose}\n\n{}", out.stderr.trim())
        },
        ..out
    }
}

/// Spawn without giving the child a console of its own.
///
/// `windows_subsystem = "windows"` makes *this* process windowless and says
/// nothing about what it starts. `ssh.exe` is a console application, so
/// Windows obligingly builds it a console — and a conhost window appears
/// behind the app, for every call. Two of them at launch, because the boot
/// asks the host twice: once whether it is reachable and once whether a
/// rollback is pending. Nothing was wrong with the firewall; the flashing was
/// the tool talking to it.
#[cfg(windows)]
fn no_console(c: &mut Command) {
    use std::os::windows::process::CommandExt;
    /* CREATE_NO_WINDOW */
    c.creation_flags(0x0800_0000);
}
#[cfg(not(windows))]
fn no_console(_: &mut Command) {}

/// The inherited PATH with the sbin directories added, and nothing removed.
///
/// Adding rather than replacing: on Windows and macOS the inherited one is the
/// only thing that finds `ssh` at all, and on Linux somebody may keep nft
/// somewhere this list has never heard of.
fn local_path() -> String {
    match std::env::var("PATH") {
        Ok(p) if !p.is_empty() => {
            let sep = if cfg!(windows) { ';' } else { ':' };
            if cfg!(windows) {
                p
            } else {
                format!("{p}{sep}{SBIN_PATH}")
            }
        }
        _ => SBIN_PATH.to_string(),
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
            /* `env` and not a shell assignment: this is handed to the remote
            login shell as one string, and a bare `PATH=… nft …` would be a
            shell builtin's problem rather than ours the moment somebody's
            login shell is not POSIX. */
            args.push("env".into());
            args.push(format!("PATH={SBIN_PATH}"));
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
    spawn_collect(&program, &args, stdin)
}

/// One of the three read-only operations, wherever it is being run.
///
/// Locally this is the path that may go through pkexec, so it is also where a
/// failure gets read for what it is. Over ssh nothing changes: the remote
/// `sudo` toggle has always been the answer there.
fn run_verb(target: &Target, v: Verb, stdin: Option<&str>) -> Outcome {
    match target {
        Target::Local => {
            let (program, args) = local_argv(v);
            local_hint(spawn_collect(&program, &args, stdin), v, elevating())
        }
        Target::Ssh { .. } => run(target, v.nft(), stdin),
    }
}

fn spawn_collect(program: &str, args: &[String], stdin: Option<&str>) -> Outcome {
    let mut cmdline = Command::new(program);
    cmdline
        .args(args)
        /* The same gap on this side of the wire: a desktop launcher hands an
        application the session PATH, which on Linux is a normal user's and so
        has no sbin in it either. Harmless where the target is ssh — the
        program being run is ssh, and it is not in sbin. */
        .env("PATH", local_path())
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    no_console(&mut cmdline);
    let mut child = match cmdline.spawn() {
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
            hint: None,
        },
        Err(e) => Outcome::failed(e.to_string()),
    }
}

/// Is there an nft we can talk to, and what is it running on?
///
/// Both answers in one round trip, because both are wanted at the same moment
/// and one of them is over a network. Tagged rather than positional: newer
/// Run blocking work somewhere that is not the queue every command shares.
///
/// A `#[tauri::command]` declared `fn` rather than `async fn` is serialised
/// with all the others, and every one of these ends in `wait_with_output` on a
/// child that may be an ssh sitting out an eight-second ConnectTimeout.
/// Measured: a `platform` call issued 300ms after a probe of an unreachable
/// host came back in 7743ms — it had been queued behind it. The window kept
/// painting, so it did not look frozen; it simply answered nothing until the
/// timeout expired.
async fn detached<F>(f: F) -> Outcome
where
    F: FnOnce() -> Outcome + Send + 'static,
{
    match tauri::async_runtime::spawn_blocking(f).await {
        Ok(o) => o,
        Err(e) => Outcome::failed(format!("the command could not be run: {e}")),
    }
}

/// `nft --version` prints a block of build details under the version line, so
/// "the second line" is not the kernel on every host.
#[tauri::command]
pub async fn host_probe(target: Target) -> Outcome {
    detached(move || {
        shell(
            &target,
            "set -e\n\
             printf 'nft\\t'; nft --version | head -n 1\n\
             printf 'kernel\\t'; uname -sr\n",
        )
    })
    .await
}

/// Read the live ruleset. `-a` includes handles, which we strip on import but
/// which make the source recognisable to anyone who has run the command.
#[tauri::command]
pub async fn nft_list(target: Target) -> Outcome {
    detached(move || run_verb(&target, Verb::Read, None)).await
}

/// Validate without applying. This is the check that matters: our own analyser
/// is an approximation, `nft -c` is the authority.
#[tauri::command]
pub async fn nft_check(target: Target, ruleset: String) -> Outcome {
    detached(move || run_verb(&target, Verb::Check, Some(&ruleset))).await
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
pub async fn nft_rule_op(
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
    detached(move || {
        shell(
            &target,
            &format!("nft {op} rule {table} {chain} handle {handle}{body}\n"),
        )
    })
    .await
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
pub async fn nft_arm(target: Target, seconds: u32) -> Outcome {
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
         #\n\
         # It is a restore script and not a listing. `nft -f` on a listing\n\
         # adds to what is already loaded, so a table the apply created — the\n\
         # one that may be doing the cutting off — outlives the rollback. And\n\
         # `nft list ruleset` on a firewall with no rules yet is zero bytes,\n\
         # which every `-s` test below reads as no copy at all: the net would\n\
         # decline to fire on precisely the machine most likely to need it,\n\
         # the one being set up for the first time. `flush ruleset` on the\n\
         # front fixes both, and nft applies a file as one transaction, so\n\
         # there is no moment where the firewall is empty.\n\
         if [ ! -s {SENTINEL} ] || [ ! -s {ROLLBACK} ]; then\n\
           printf 'flush ruleset\\n' > {ROLLBACK}\n\
           nft list ruleset >> {ROLLBACK}\n\
         fi\n\
         printf '%s' '{tok}' > {SENTINEL}\n\
         \
         nohup sh -c 'sleep {secs}; \
           if [ \"$(cat {SENTINEL} 2>/dev/null)\" = \"{tok}\" ]; then \
             nft -f {ROLLBACK}; rm -f {SENTINEL}; \
           fi' </dev/null >/dev/null 2>&1 &\n\
         cat {ROLLBACK}\n"
    );
    detached(move || shell(&target, &script)).await
}

/// Keep what is running. The scheduled restore finds no sentinel and does
/// nothing; the copy is left behind on purpose, as the last known-good.
#[tauri::command]
pub async fn nft_disarm(target: Target) -> Outcome {
    detached(move || shell(&target, &format!("rm -f {SENTINEL}\n"))).await
}

/// Is a rollback still pending on this host? Answers `armed` or `clear` so a
/// window that was closed, or an editor that was restarted, can find out.
#[tauri::command]
pub async fn nft_armed(target: Target) -> Outcome {
    /* `-s` and not `-f`: the sentinel carries the token of the arming that owns
    it, and an empty one belongs to nobody */
    detached(move || {
        shell(
            &target,
            &format!("if [ -s {SENTINEL} ]; then echo armed; else echo clear; fi\n"),
        )
    })
    .await
}

/// Put the copy back now, without waiting for the timer.
///
/// The sentinel goes first, so the pending timer finds its token gone and
/// stays out of the way of a restore already in progress.
#[tauri::command]
pub async fn nft_rollback(target: Target) -> Outcome {
    detached(move || {
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
    })
    .await
}

/// Apply atomically. Refuses unless the caller has confirmed, because this is
/// the one operation that can lock someone out of a machine.
#[tauri::command]
pub async fn nft_apply(target: Target, ruleset: String, confirmed: bool) -> Outcome {
    if !confirmed {
        return Outcome::failed("refusing to apply without explicit confirmation");
    }
    /* Say this here rather than let it fail three commands later. The polkit
    helper covers reading and validating and deliberately not this, so on a
    local target without root the pre-flight `nft -c` is what breaks first —
    and "validation failed: Operation not permitted" reads as a problem with
    the ruleset, which is the one thing it is not. */
    #[cfg(target_os = "linux")]
    if matches!(target, Target::Local) && !am_root() {
        return Outcome::failed(
            "Applying a ruleset to this machine needs root. eFeFlow only asks permission to read \
             and validate — start it with root privileges to apply here, or apply to an SSH \
             target with sudo.",
        );
    }
    detached(move || {
        let check = run(&target, &["nft", "-c", "-f", "-"], Some(&ruleset));
        if !check.ok {
            return Outcome {
                ok: false,
                stderr: format!("validation failed, nothing was applied:\n{}", check.stderr),
                code: check.code,
                ..Default::default()
            };
        }
        run(&target, &["nft", "-f", "-"], Some(&ruleset))
    })
    .await
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

    let (program, args) = match &target {
        Target::Local => local_argv(Verb::Monitor),
        Target::Ssh { .. } => argv(&target, Verb::Monitor.nft()),
    };
    let mut cmdline = Command::new(&program);
    cmdline
        .args(&args)
        .env("PATH", local_path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        /* Not piped. Nothing has ever read this one, and a pipe nobody reads
        is a pipe that fills: the child blocks on write and the watch stops
        with no explanation. Neither `nft monitor` nor ssh says enough to reach
        a buffer's worth in practice — measured, not assumed — so this is not a
        bug being fixed, it is a hazard not being kept for no reason. The lines
        that matter arrive on stdout. */
        .stderr(Stdio::null());
    no_console(&mut cmdline);
    let child = cmdline.spawn();

    let mut child = match child {
        Ok(c) => c,
        Err(e) => return Outcome::failed(format!("could not run `{program}`: {e}")),
    };

    let out = child.stdout.take();
    /* Stored before the reader starts, so a stream that ends immediately still
    finds its own child here to reap. */
    let pid = child.id();
    *WATCH.lock().unwrap() = Some(child);

    if let Some(out) = out {
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

            /* And a child nobody waits for is a zombie for as long as the
            application runs. Only `nft_unwatch` ever reaped one, so a watch
            that ended by itself — the commonest way for one to end, since it
            is what a dropped connection looks like — left one behind every
            time. Confirmed on Debian 13: the process went to state Z the
            moment its stream closed, and a wait() cleared it.

            By pid, because a watch started in the meantime is somebody else's
            child and waiting on it would hang this thread on a process that is
            still running. */
            if let Ok(mut w) = WATCH.lock() {
                if w.as_ref().map(Child::id) == Some(pid) {
                    if let Some(mut c) = w.take() {
                        let _ = c.wait();
                    }
                }
            }
        });
    }
    Outcome {
        ok: true,
        code: Some(0),
        ..Default::default()
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
        code: Some(0),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failed(code: i32, stderr: &str) -> Outcome {
        Outcome {
            ok: false,
            stderr: stderr.into(),
            code: Some(code),
            ..Default::default()
        }
    }

    /// The message nft writes about a ruleset is the product. Explaining
    /// privileges over the top of a syntax error would bury the one line the
    /// user actually needs to read.
    #[test]
    fn a_rejected_ruleset_keeps_nfts_own_words() {
        let out = failed(1, "/dev/stdin:1:34-34: Error: syntax error, unexpected '}'");
        let seen = local_hint(out, Verb::Check, false);
        assert_eq!(
            seen.stderr,
            "/dev/stdin:1:34-34: Error: syntax error, unexpected '}'"
        );
    }

    #[test]
    fn a_permission_failure_says_what_to_do_instead() {
        let out = failed(1, "Operation not permitted (you must be root)");
        let seen = local_hint(out, Verb::Read, false);
        assert!(seen
            .stderr
            .starts_with("Reading this machine's ruleset needs root"));
        /* the original survives underneath: the first line is for the toast,
        the rest is for whoever is diagnosing */
        assert!(seen.stderr.contains("Operation not permitted"));
    }

    /// Declining the polkit dialog is not a firewall problem, and pkexec says
    /// so with an exit code rather than a message.
    #[test]
    fn a_declined_authorisation_is_not_reported_as_a_failure_to_read() {
        let seen = local_hint(failed(126, ""), Verb::Read, true);
        assert_eq!(
            seen.stderr,
            "The authorisation was declined, so nothing was read."
        );
    }

    /// Same code, no pkexec in the picture: 126 came from something else and
    /// must not be dressed up as an authorisation prompt nobody saw.
    #[test]
    fn the_same_code_means_nothing_when_nothing_was_elevated() {
        let seen = local_hint(
            failed(126, "bash: nft: command not found"),
            Verb::Read,
            false,
        );
        assert_eq!(seen.stderr, "bash: nft: command not found");
    }

    /// "It needs root" followed by no prompt was the actual complaint. The
    /// code has to distinguish the two reasons, because one is fixed by
    /// installing the package and the other by installing pkexec.
    #[test]
    fn a_permission_failure_names_why_it_could_not_ask() {
        let out = failed(1, "Operation not permitted (you must be root)");
        let seen = local_hint(out, Verb::Read, false);
        let code = seen.hint.expect("a permission failure carries a code");
        assert!(code.starts_with("needs-root"), "got {code}");
    }

    #[test]
    fn a_rejected_ruleset_carries_no_code_at_all() {
        let out = failed(1, "/dev/stdin:1:34-34: Error: syntax error");
        assert_eq!(local_hint(out, Verb::Check, false).hint, None);
    }

    /* Both of these are exit 127 and they are not the same problem.
    Measured on a Debian 13 desktop carrying the released .deb: the helper was
    root-owned, mode 755, shebang present, and execve ran it — and pkexec still
    exited 127, because the application had been started from an ssh session
    and polkit had no agent to raise a dialog with. The message sent somebody
    to reinstall a package that was installed perfectly. pkexec says which it
    was; this reads that instead of inferring from the number. */
    #[test]
    fn no_authentication_agent_is_not_a_broken_helper() {
        let no_agent = failed(
            127,
            "Error creating textual authentication agent: Error opening current \
             controlling terminal for the process (`/dev/tty'): No such device or address",
        );
        assert_eq!(
            local_hint(no_agent, Verb::Read, true).hint,
            Some("no-polkit-agent")
        );

        /* and a 127 that says nothing about an agent keeps the old reading */
        assert_eq!(
            local_hint(failed(127, "no such file"), Verb::Read, true).hint,
            Some("helper-broken")
        );
    }

    #[test]
    fn a_declined_prompt_is_its_own_code() {
        assert_eq!(
            local_hint(failed(126, ""), Verb::Read, true).hint,
            Some("declined")
        );
    }

    #[test]
    fn success_is_left_alone() {
        let out = Outcome {
            ok: true,
            stdout: "table inet filter {}".into(),
            code: Some(0),
            ..Default::default()
        };
        assert!(local_hint(out, Verb::Read, false).ok);
    }

    /// The words themselves, pinned. This is the Rust half of the agreement
    /// and it is deliberately literal: changing one has to show up in a diff
    /// as a changed string, not as a renamed identifier.
    #[test]
    fn the_verbs_are_the_words_the_helper_understands() {
        assert_eq!(Verb::Read.word(), "read");
        assert_eq!(Verb::Check.word(), "check");
        assert_eq!(Verb::Monitor.word(), "monitor");
    }

    /// And the other half, which nothing was checking.
    ///
    /// The word this sends and the word the helper answers to live in two
    /// languages in two directories, and they agree only by having been
    /// written on the same afternoon. Disagreeing costs an elevated call that
    /// exits 2 with `unknown verb` — after the user has authenticated, which
    /// is the worst moment to discover a typo. The test above pinned the Rust
    /// side to itself and proved nothing about the script; this reads the
    /// script.
    #[test]
    fn every_verb_is_an_arm_of_the_helper_case_statement() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../packaging/linux/efeflow-nft-helper"
        );
        let script = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("the packaged helper should be readable at {path}: {e}"));

        /* `read)`, `check)`, `monitor)` — and not the `*)` fallback, which is
        the arm that exists to refuse everything else. */
        let arms: Vec<&str> = script
            .lines()
            .map(str::trim)
            .filter_map(|l| l.strip_suffix(')'))
            .filter(|w| !w.is_empty() && w.chars().all(|c| c.is_ascii_lowercase()))
            .collect();

        for v in [Verb::Read, Verb::Check, Verb::Monitor] {
            assert!(
                arms.contains(&v.word()),
                "the helper has no `{}` arm — it answers to {arms:?}",
                v.word()
            );
        }
    }
}
