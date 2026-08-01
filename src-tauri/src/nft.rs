//! The native half of eFeFlow: everything the browser cannot do.
//!
//! Two transports, one shape. Locally we run `nft` directly; remotely we run
//! it through `ssh`. The frontend does not care which — it asks for a ruleset
//! or a syntax check and gets the same struct back, so a firewall on the other
//! side of the world behaves like one under the desk.

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::process::{Command, Stdio};

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
        Outcome { ok: false, stdout: String::new(), stderr: msg.into(), code: None }
    }
}

/// Build the argv for a command against a target, without a shell in the way.
fn argv(target: &Target, cmd: &[&str]) -> (String, Vec<String>) {
    match target {
        Target::Local => (cmd[0].to_string(), cmd[1..].iter().map(|s| s.to_string()).collect()),
        Target::Ssh { host, user, port, sudo } => {
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

fn run(target: &Target, cmd: &[&str], stdin: Option<&str>) -> Outcome {
    let (program, args) = argv(target, cmd);
    let mut child = match Command::new(&program)
        .args(&args)
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
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

/// Is there an nft we can talk to, and which version?
#[tauri::command]
pub fn nft_version(target: Target) -> Outcome {
    run(&target, &["nft", "--version"], None)
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
