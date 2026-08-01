<div align="center">

<img src="assets/app.png" width="128" alt="eFeFlow">

# eFeFlow

**Visual nftables firewall rule designer**

Design Linux nftables rulesets on a canvas laid out by netfilter hook and chain
priority. Import what is already running, see which rules can never match, and
watch a packet take its real path through the chains.

[English](README.md) · [Español](README.es.md)

[![ci](https://github.com/eFeSpain/efeflow/actions/workflows/ci.yml/badge.svg)](https://github.com/eFeSpain/efeflow/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/eFeSpain/efeflow?include_prereleases&sort=semver)](https://github.com/eFeSpain/efeflow/releases)
[![licence](https://img.shields.io/badge/licence-MIT-blue)](LICENSE)

[**Download**](https://github.com/eFeSpain/efeflow/releases/latest) — Linux `.deb` `.rpm` `.AppImage` · Windows `.msi` · macOS `.dmg`

</div>

---

## What it is

eFeFlow is a **designer**, not a firewall manager. It edits a ruleset and emits
`nft` source. Nothing touches a live host unless you explicitly ask it to.

### It opens on a blank ruleset

Three filter hooks, a default-deny policy on the two that face the network,
and the conntrack fast path — the shape almost every nftables ruleset starts
from, and every line of it yours from the first second. eFeFlow never opens on
a firewall you did not write.

`Ctrl+N` returns to it at any time. Click the project name, or press `F2`, to
rename it: the name goes in the header comment of the generated ruleset and
becomes the export filename.

### The canvas is a field, not a whiteboard

Horizontally, a chain sits at the netfilter hook it is attached to —
`prerouting`, `input`, `forward`, `output`, `postrouting` — in the order a
packet actually meets them. Vertically, it sits at its chain priority: `raw` at
−300, `dstnat` at −100, `filter` at 0, `srcnat` at +100.

Position is meaning. You read evaluation order off the screen instead of
reconstructing it in your head. Cards can be dragged when a different
arrangement suits how you think about the network, and the automatic layout is
one button away.

Every rule carries a coloured stripe for its verdict, so squinting at a chain
gives you a barcode of the policy.

### The analyser

Findings are derived from the ruleset each time it changes, never authored. The
core relation is **subsumption**: rule A subsumes rule B when every packet
matching B also matches A. If A comes first and terminates, B is dead code.

| Check | What it means |
|---|---|
| **Shadowed** | A rule an earlier one already decides. It costs an evaluation and changes nothing. |
| **Conflict** | Overlapping DNAT rules with different targets. nftables terminates on the first NAT verdict, so one silently wins. |
| **Merge** | Rules differing only by port, which a single set lookup replaces — one hash probe instead of *n* comparisons. |
| **Unused** | A set loaded into the kernel on every reload that no rule consumes. |
| **Hardening** | A chain that fast-paths `established` but never drops `invalid`. |
| **Resilience** | A log rule with no rate limit, which floods the kernel ring buffer under a scan. |

Rate-limited rules are never treated as shadowing anything. They are
non-deterministic, and flagging there would tell you to delete a rule that
works.

Most findings carry a one-click fix that mutates the model, re-emits the code
and re-runs the analysis. Everything is undoable.

### The packet simulator

Evaluates against the same model the code is emitted from, so a verdict here is
the verdict your exported ruleset produces. It arrives already run, and any
change to the packet re-runs it.

It models nftables semantics rather than an approximation of them:

- **`accept` ends the chain, not the packet.** The packet carries on to the
  next hook. Only `drop` and `reject` end it outright.
- **Direction chooses the path**, as the kernel's routing decision does —
  ingress walks prerouting then input; forward adds postrouting; egress starts
  at output.
- **Turning connection tracking off** marks the packet `untracked`, so
  `ct state` rules can no longer match it and `ct status` never does.
- **TCP flags** distinguish presence from exclusivity: `tcp flags syn` matches
  `syn|ack`, `tcp flags & (syn|ack) == syn` does not.

Step mode advances one rule at a time with <kbd>Space</kbd>.

### Import, and the round-trip check

Paste the output of `nft list ruleset`, or read it from a host. Before importing
anything, eFeFlow parses it, **re-emits every rule from the model**, and
compares the two line by line. The percentage it reports is the only honest
evidence that nothing was lost in translation — and if a rule cannot be
reproduced, it shows you which.

Chain priorities survive by name (`priority filter` comes back as
`priority filter`, not `0`), and counters, comments and the `# handle` suffixes
of `nft -a` are all understood.

### Where nft runs

The analyser is eFeFlow's own reading of your ruleset. **`nft -c` is the
authority**, and `nft` only exists on Linux — so point eFeFlow at the firewall.
The chip in the top right opens the target dialog: this machine, or a host over
SSH with user, port and sudo.

It shells out to the system `ssh`, so your keys, your agent and `~/.ssh/config`
already apply and eFeFlow stores no credentials. The dialog shows the exact
command before you commit to it, and **Test connection** reports the nft version
or the reason it failed.

Two actions give a target its purpose:

- **Read from host** pulls `nft -a list ruleset` straight into the import
  dialog, where the round-trip check verifies it as usual.
- **Check with `nft -c`** on the validation screen runs the real parser. If it
  disagrees with the analyser, nft is right.

Applying a ruleset validates first and refuses without explicit confirmation.
It is the one operation that can lock you out of a machine.

### Export

Four formats, each producing genuinely different output: an atomic ruleset
file, an incremental delta of `add rule` commands for a running box, a systemd
bundle with a pre-apply validation hook, and an Ansible playbook with your sets
extracted as variables.

---

## Platform reality

`nft` only exists on Linux, so the native integrations differ:

| | Linux | Windows | macOS |
|---|:---:|:---:|:---:|
| Design, analyse, simulate, import, export | ✅ | ✅ | ✅ |
| Validate with local `nft -c` | ✅ | — | — |
| Read local `nft list ruleset` | ✅ | — | — |
| Everything above **over SSH** | ✅ | ✅ | ✅ |

SSH is not the fallback, it is the design — the firewall is rarely the machine
with your editor open. eFeFlow shells out to the system `ssh`, so your keys,
agent and `~/.ssh/config` all apply. A local Linux target is just the case
where the remote host is `localhost`.

Applying a ruleset validates first and refuses without explicit confirmation.
It is the one operation that can lock you out of a machine.

---

## Running it

```bash
npm install
npm run app          # desktop app, with the native layer
npm run dev          # or just the frontend in a browser
npm test             # 73 assertions
```

Building needs the [Tauri prerequisites](https://tauri.app/start/prerequisites/)
for your platform. On Debian/Ubuntu:

```bash
sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev patchelf
```

```bash
npm run app:build    # installers in src-tauri/target/release/bundle/
```

Tagging `v*` runs the release workflow, which builds on four runners — Linux,
Windows, macOS arm64 and x86_64 — and collects the installers into a draft
release.

---

## Layout

```
src/core/        pure, DOM-free, covered by npm test
  model.js         the ruleset and the shared vocabulary
  parse.js         nft source → model
  generate.js      model → nft source, with line provenance
  analyse.js       findings, by criterion subsumption
  simulate.js      packet evaluation
  diff.js          LCS diff against the last import or export
src/app.js       the interface
src/native.js    bridge to Rust; degrades to browser equivalents
src-tauri/       nft and ssh transports, window commands
```

The split is the point. Anything that decides a verdict lives in `core/` and is
tested headlessly.

---

## Tests

Three layers, because a green core suite is not evidence that the product
works — the packet simulator once shipped broken while every core test passed,
killed by a parameter that shadowed a helper.

**Core** — the parser against a real `nft list ruleset` dump, import → generate
→ import as a fixed point across three tables, criterion subsumption, and
packet evaluation including conntrack, flag masks and chain terminality.

**Interface** — boots the real app in jsdom, walks every screen and dispatches
real events. Selecting rules, editing fields, undo, applying fixes, switching
language, running the simulator to a verdict.

**Contracts** — static guards for the bugs that got through: every id the code
looks up must exist in the markup; no parameter may be named after a shared
helper; every window command the frontend calls must have a Tauri capability;
layout may not derive card height from a rule count.

```bash
npm test                            # everything
node --test "test/ui-*.test.js"     # just the interface
```

---

## Licence

MIT
