# How eFeFlow is built

Notes for anyone changing the code. The [README](../README.md) covers what the
tool does; this covers why it is shaped the way it is.

## The split

```
src/core/        pure, DOM-free, covered by npm test
  model.js         the ruleset, the blank skeleton, shared vocabulary
  parse.js         nft source → model
  generate.js      model → nft source, with line provenance
  analyse.js       findings, by criterion subsumption
  simulate.js      packet evaluation
  diff.js          LCS diff against the last import or export
  project.js       name, origin, and the names you keep by hand
  bus.js           one registry every derived view subscribes to
src/app.js       the interface
src/native.js    bridge to Rust; degrades to browser equivalents
src/target.js    where nft runs: this machine, or a host over SSH
src-tauri/       nft and ssh transports, window commands
```

**Anything that decides a verdict lives in `core/` and never touches the DOM.**
That is what lets the parser be tested against a real `nft list ruleset` dump,
and the packet evaluator against a table of cases, without a browser.

## Two invariants worth keeping

**Nothing writes `MODEL` directly.** Every mutation goes through
`edit(label, fn)`, which snapshots the whole ruleset before and after. At this
size a full snapshot is cheap and it removes a class of bugs that per-field
diffing invites. The label is what the user would call the change, and it
surfaces in the undo tooltip.

**Findings describe the ruleset; applying one must act on the ruleset as it is
now.** Fixes resolve their target by identity when applied, not by holding an
object reference. Undo rebuilds every chain and rule from JSON, so a captured
reference becomes an orphan and the fix silently mutates nothing.

## Emission carries provenance

`generateWithMap()` returns the lines and a parallel array saying which rule
each came from. Without it the code pane has to match rules back to lines by
their text — and two chains can hold the same rule, so selecting one would light
up all of them.

## Tests, and why there are three layers

`npm test` — 104 assertions.

**Core** exercises the pure functions: the parser against
`test/fixtures/flawed.nft`, import → generate → import as a fixed point across
three tables, criterion subsumption, packet evaluation including conntrack, flag
masks and chain terminality.

**Interface** (`test/ui-*.test.js`) boots the real app in jsdom, walks every
screen and dispatches real events.

**Contracts** are static guards, each one grown from a bug that reached the
running app:

| Guard | The bug it prevents |
|---|---|
| `markup-contract` | an id the code looks up that the markup does not have |
| `shadowing` | a parameter named after a shared helper |
| `capabilities` | a window command with no Tauri capability |
| `ui-layout` | layout deriving a card's height from a rule count |

The interface layer exists because a green core suite is not evidence that the
product works. The packet simulator once shipped broken while all 18 core tests
passed: a parameter named `t` shadowed the translation helper and killed
`runSim` on its first line, inside a handler whose exception went nowhere.

## The fixture

`test/fixtures/flawed.nft` is planted with the six defects the analyser is built
to find. It lives in the tests and not in the product, because an application
must never open on a firewall its user did not write.

UI tests load it through the import dialog rather than assigning to `MODEL`, so
they exercise the path a real ruleset arrives by.

## Screenshots

`npm run shots` regenerates `docs/*.png` from the real frontend in headless
Chromium. Committed images go stale silently, so regenerate them when the
interface changes.

## Platform notes

- WebKitGTK has poor `backdrop-filter` support. The frontend detects Linux from
  the Rust side and swaps glass for a solid surface, keeping the layering.
- Timers belong to the window in a browser but not in the jsdom harness;
  aliasing `setTimeout` or `performance` to jsdom's makes them call themselves.
- Tauri gates every IPC call behind a capability. A missing grant rejects
  silently, which reads as a dead button — hence the capabilities test.
