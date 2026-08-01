<div align="center">

<img src="assets/app.png" width="120" alt="eFeFlow">

# eFeFlow

**Visual nftables firewall rule designer**

Design Linux nftables rulesets on a canvas laid out by netfilter hook and chain
priority. Import what is already running, see which rules can never match, and
watch a packet take its actual path through the chains.

</div>

---

## What it is

eFeFlow is a **designer**, not a firewall manager. It edits a ruleset and emits
`nft` source. Nothing touches a live host unless you explicitly ask it to.

- **Hook rail canvas** — x is the packet's real path through netfilter, y is the
  chain priority. Chains are anchored at their coordinates; nothing floats.
- **Round-trip import** — paste or read `nft list ruleset`, and eFeFlow parses
  it, re-emits every rule, and shows you where the two disagree *before*
  importing. If it cannot reproduce a rule, it says so.
- **Analyser** — shadowed rules, overlapping DNAT targets with divergent
  destinations, sets nobody references, rules that collapse into a set lookup,
  missing invalid-state drops, unrated log rules. Every finding derived from the
  model, most with a one-click fix.
- **Packet simulator** — evaluates against the same model the code is emitted
  from, with conntrack state, TCP flags, NAT hooks and step-by-step playback.
- **Bilingual** — Spanish and English throughout. nftables vocabulary is never
  translated: you write `accept`, not `aceptar`.

## Platform reality

`nft` only exists on Linux, so the native integrations differ:

| | Linux | Windows | macOS |
|---|---|---|---|
| Design, analyse, simulate, export | ✅ | ✅ | ✅ |
| Validate with local `nft -c` | ✅ | — | — |
| Read local `nft list ruleset` | ✅ | — | — |
| Everything above **over SSH** | ✅ | ✅ | ✅ |

SSH is not the fallback, it is the design — the firewall is rarely the machine
with your editor open. eFeFlow shells out to the system `ssh`, so your keys,
agent and `~/.ssh/config` all apply.

## Running it

```bash
npm install
npm run app          # desktop app with the native layer
npm run dev          # or just the frontend in a browser
npm test             # core suites: parser, analyser, simulator
```

Building requires the [Tauri prerequisites](https://tauri.app/start/prerequisites/)
for your platform. On Debian/Ubuntu:

```bash
sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev patchelf
```

```bash
npm run app:build    # produces installers in src-tauri/target/release/bundle/
```

## Layout

```
src/core/      pure, DOM-free, covered by npm test
  model.js       the ruleset and the shared vocabulary
  parse.js       nft source → model
  generate.js    model → nft source
  analyse.js     findings, by criterion subsumption
  simulate.js    packet evaluation
src/app.js     the interface
src/native.js  bridge to Rust, degrades to browser equivalents
src-tauri/     nft and ssh transports
```

The split is the point: anything that decides a verdict lives in `core/` and is
tested headlessly. `npm test` runs the parser against a real `nft list ruleset`
dump and asserts that import → generate → import is a fixed point.

## Licence

MIT
