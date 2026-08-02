<div align="center">

<img src="assets/app.png" width="112" alt="eFeFlow">

# eFeFlow

**Design Linux firewall rules visually. Get clean `nft` source out.**

[![ci](https://github.com/eFeSpain/efeflow/actions/workflows/ci.yml/badge.svg)](https://github.com/eFeSpain/efeflow/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/eFeSpain/efeflow?include_prereleases&sort=semver)](https://github.com/eFeSpain/efeflow/releases)
[![licence](https://img.shields.io/badge/licence-MIT-blue)](LICENSE)
[![status](https://img.shields.io/badge/status-beta-F0C13C)](#-beta)

[English](README.md) · [Español](README.es.md)

<img src="docs/editor.png" width="880" alt="The rule editor">

</div>

---

## ⚠ Beta

eFeFlow is **under active development**. The parser, analyser and packet
evaluator are covered by an automated suite, but the tool is young and you will
find rough edges.

Treat what it generates as a **draft you review**, not output to trust blindly.
Validate with `nft -c` before applying anything, and keep console access to any
machine you apply a ruleset to.

---

## What it does

An nftables ruleset is an ordered list of text where position is meaning, and a
single misplaced rule silently shadows the ten below it. eFeFlow makes that
visible.

**It is a designer, not a firewall manager.** It edits a ruleset and emits `nft`
source. Nothing reaches a live host unless you ask.

### The canvas is a field, not a whiteboard

A chain sits at the netfilter hook it is attached to — left to right in the
order a packet meets them — and at its priority, top to bottom. **Position is
meaning**: you read evaluation order off the screen instead of reconstructing it
in your head.

Add a chain by clicking its hook in the rail, or by dragging one out of the
library. Drag rules to reorder them, across chains if you like. Every rule
carries a coloured stripe for its verdict, so squinting at a chain gives you a
barcode of the policy.

### It tells you what is wrong with your ruleset

<img src="docs/validate.png" width="880" alt="The validation screen">

Findings are derived from the ruleset every time it changes, never authored.

| | |
|---|---|
| **Shadowed** | a rule an earlier one already decides |
| **Conflict** | overlapping DNAT rules with different targets |
| **Merge** | rules differing only by port, which one set lookup replaces |
| **Unused** | a set loaded into the kernel that no rule consumes |
| **Hardening** | a chain that trusts conntrack but never drops `invalid` |
| **Resilience** | a log rule with no rate limit |

Most carry a one-click fix. Everything is undoable.

### It runs your packet through your rules

<img src="docs/simulator.png" width="880" alt="The packet simulator">

Describe a packet and watch it walk the chains, rule by rule, to a verdict — and
it is the verdict your exported ruleset produces, because the simulator
evaluates the same model the code is emitted from.

It models nftables properly, in both families. `accept` ends the chain, not the
packet. `ip6 saddr` constrains IPv6 and nothing else. Turning conntrack off
marks the packet `untracked`, so `ct state` rules stop matching it. `tcp flags
syn` matches `syn|ack`; `tcp flags & (syn|ack) == syn` does not.

And where it cannot model something — nftables is a larger language than any
model of it — **it says so rather than guessing quietly**. A rule carrying a
`meta mark` or an `fib` lookup is taken as matching, marked in the trace, and
named under the verdict: this one is a guess, and this is the part of it that
was assumed rather than evaluated.

### It imports what you already run, and proves it

Paste `nft list ruleset`, or read it straight from a host. Before importing
anything, eFeFlow **re-emits the whole file from the model and compares it line
by line** — rules, chain headers, sets, table flags, and the flowtables, named
counters and ct helpers it carries through untouched rather than modelling. The
percentage it reports is honest evidence that nothing was lost in translation,
and if a line cannot be reproduced it shows you which one.

### And the rest

<table>
<tr>
<td width="50%"><img src="docs/sets.png" alt="Set manager"><br><b>Sets as real assets</b><br>Back-references computed from your rules. Rename one and every rule that uses it follows.</td>
<td width="50%"><img src="docs/topology.png" alt="Topology"><br><b>Topology from the rules</b><br>Interfaces and zones derived from what your rules actually name. Nothing declared.</td>
</tr>
<tr>
<td><img src="docs/code.png" alt="Generated code"><br><b>Live source</b><br>Edit a field and the nft re-emits. Click a line and it selects the rule. Five export formats.</td>
<td><img src="docs/dashboard.png" alt="Dashboard"><br><b>The ruleset at a glance</b><br>Packet path, health, worst-case evaluations per packet.</td>
</tr>
</table>

Bilingual throughout, English and Spanish. nftables vocabulary is never
translated — you write `accept`, not `aceptar`.

---

## Install

Grab an installer from [**Releases**](https://github.com/eFeSpain/efeflow/releases/latest):
Linux `.deb` `.rpm` `.AppImage` · Windows `.msi` · macOS `.dmg`

### Where `nft` runs

`nft` only exists on Linux, so the native integrations differ:

| | Linux | Windows | macOS |
|---|:---:|:---:|:---:|
| Design, analyse, simulate, import, export | ✅ | ✅ | ✅ |
| Validate with a local `nft -c` | ✅ | — | — |
| Read a local `nft list ruleset` | ✅ | — | — |
| Both of those **over SSH** | ✅ | ✅ | ✅ |

**SSH is not a fallback, it is the design** — the firewall is rarely the machine
with your editor open. Click the chip in the top right to point eFeFlow at a
host. It shells out to the system `ssh`, so your keys, your agent and
`~/.ssh/config` already apply, and eFeFlow stores no credentials.

### Applying, and being able to change your mind

Applying is the one operation that can lock you out of a machine, and the
failure has a nasty shape: the rule that cuts you off is the rule that stops
you undoing it. A rollback button in the editor is no use, because the editor
is on the wrong side of the firewall it just broke.

So the net is armed **on the host**. Before anything is written, eFeFlow copies
the running ruleset aside there and starts a detached timer that puts it back
unless it is told not to. Keeping what you applied is a deliberate act; losing
the connection, the window or the laptop restores. Routers have called this
commit-confirm for thirty years.

It also replaces **only the tables your project owns** by default. `flush
ruleset` empties the kernel, and on a machine that also runs Docker, libvirt,
kubernetes or fail2ban that deletes their tables too — none of which will
notice or put them back. Both choices reset to the safe one every time the
dialog opens.

`nft -c` runs on the host before a byte is written, and refuses for you.

### Once it is running

A ruleset that has been applied is no longer a document, and three things on
the canvas treat it as a machine:

**Read counters** pulls `nft list ruleset` back and puts the real packet and
byte counts on your rules. It is the only honest answer to *is this rule ever
hit* — the analyser can tell you a rule is unreachable, but only the kernel can
tell you a reachable one has matched nothing in six weeks.

**Watch** attaches `nft monitor` and reports every change the host makes while
you have it open, whoever made it.

**Handle** — the chip on a rule imported from a host — pushes that one rule,
by its handle, without touching the rest of the table. Handles are the only
stable name a rule has: they survive reordering, and text does not.

All three read the host first. The push refuses outright unless the rule it is
about to name is still, line for line, the rule the host has under that handle
— and unless the whole chain still agrees. Being approximately right about
which rule you are deleting is worse than not deleting one.

---

## Build from source

```bash
npm install
npm run app          # the desktop app
npm run dev          # or the frontend alone, in a browser
npm test             # 432 assertions
npm run app:build    # installers in src-tauri/target/release/bundle/
```

Needs the [Tauri prerequisites](https://tauri.app/start/prerequisites/) for your
platform. On Debian/Ubuntu:

```bash
sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev patchelf
```

---

## Contributing

Bug reports are welcome — especially a ruleset that does not survive the
round-trip check. That is the kind of bug worth knowing about: paste the ruleset
and what the check reported.

[**How it is built**](docs/architecture.md) covers the module layout, why the
core is kept free of the DOM, and how the three test layers came to exist.

## Licence

MIT
