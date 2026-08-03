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
  lint.js          what nft would reject, before nft is asked
  expr.js          surgical edits to one match of one rule
  tables.js        the table itself: family, comment, flags dormant
  objects.js       named counters, quotas, ct helpers, flowtables
  addr.js          addresses and prefixes, v4 and v6
  sync.js          which rule here is which rule there
  diff.js          LCS diff against the last import or export
  project.js       name, origin, and the names you keep by hand
  bus.js           one registry every derived view subscribes to
  samples.js       the worked scenarios the import dialog offers
src/app.js       the interface
src/apply.js     commit-confirm: arm, push, keep or roll back
src/host.js      counters, drift and per-handle pushes against a live host
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

## What the analyser deliberately does not answer

Subsumption is computed **within a chain**. Two rules are only ever weighed
against each other if they sit in the same one, so a rule made unreachable by a
terminal rule in the chain that jumped to it is not reported.

That is a choice, not an oversight. Reaching across a `jump` means reasoning
about every path into the target chain — several callers, each with its own
constraints, `goto` not returning where `jump` does — and the cost of getting
it wrong is not a missed finding. It is a Delete button under a rule that
fires. `subsumes()` already refuses on a rate limit, on a negation and on
anything it could not read whole, for the same reason; this is the same refusal
one level up.

Worth knowing before widening it: the finding is only as good as the offer
attached to it, and every finding here carries a fix.

## Emission carries provenance

`generateWithMap()` returns the lines and a parallel array saying which rule
each came from. Without it the code pane has to match rules back to lines by
their text — and two chains can hold the same rule, so selecting one would light
up all of them.

## Tests, and why there are three layers

`npm test` — 833 assertions.

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
| `ui-panels` | a grid child with no column, which moves when a sibling hides |
| `release` | three files carrying the version, disagreeing |
| `imports` (control chars) | a `\b` saved as the byte it escapes, in a pattern that then matches nothing |
| `ui-roundtrip-panel` | a panel that rewrites what it was opened to read |
| `ssh-target` | a way to reach a host that does not validate where it is going |
| `rollback-script` | the arm script losing the copy it exists to protect |

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

`test/fixtures/probe.nft` is the other kind: not a firewall anybody would run,
but one shape of the language per chain, written to be got wrong. It exists
because of what the `$WAN` bug implied rather than what it was. The evaluator
has two ways of not understanding something — where it does not recognise a
construct, `unmodelled()` reports it and the verdict is marked as a guess, and
that path works; where a matcher recognises the shape and then decides wrongly,
nothing is left over to report and the screen is confidently wrong. There is no
net under the second one, so the fixture goes looking for it.

`test/probe.test.js` asks three things of it, in the order in which getting
them wrong is dangerous: is the model the ruleset that was written, does each
construct decide what nftables would decide, and does what it cannot decide
still get said out loud. The third is not a formality — every fix narrows what
goes unread, and the temptation each time is to widen a matcher until it
swallows something it cannot actually evaluate.

## The samples, and why they are in `core/`

`core/samples.js` holds the worked scenarios the import dialog offers — a
filtering host, a NAT gateway, port forwarding with hairpin, a WireGuard
endpoint, a load balancer, rogue-DHCP filtering on a bridge, a hardened public
server. They exist so the import path can be tried without a host, and so the
shapes people actually need can be read as rules instead of described in a
manual. The first was a template literal inside `app.js`, where no test could
reach it.

They sit in `core/` because they make promises the tests have to be able to
check. `test/samples.test.js` holds **every** sample to four: it parses with no
unrecognised lines, every rule re-emits byte-identical, it is substantial enough
to read as a scenario, and every address in it is RFC 1918 or RFC 5737
documentation space.

Two of those are load-bearing. A sample that lost a rule on the way in would
make the honest round-trip percentage a liar on the very rulesets a new user
reaches for first. And **nothing that ships in a public repository may describe
a real network** — a shipped ruleset is exactly the kind of file where
somebody's internal subnets get committed by accident.

None is ever applied. One lands in the textarea and faces the round-trip
review, exactly like a paste. The description rides in as a `#` comment, which
the parser and the round-trip check both skip.

The rogue-DHCP sample is named for what it does. DHCP snooping is a switch
feature: it watches the exchange and builds a binding table. A bridge can only
refuse to carry server traffic from a port with no business answering, so that
is what the sample claims. In a firewall tool a mislabelled example gets copied
and deployed.

## Asking nftables instead of ourselves

`npm test` checks this project against its own reading of nftables. Every table
of cases in `test/` says what nft would do, and the saying is still ours —
which is exactly how a matcher can be confidently wrong for a year.

`npm run differ` asks nft. For each ruleset it loads the original, has eFeFlow
parse and re-emit it, loads that too, and compares what `nft list ruleset`
gives back for each. Those are nft's own canonical forms, so the question it
answers is whether the round trip changed what the ruleset *means* — a stronger
claim than verify() makes about the text, and the one worth having. A file that
comes back with different text and identical netlink lost nothing; a file whose
text matched while its netlink moved lost everything and told nobody.

Each load happens inside a network namespace of its own — an empty netfilter
instance that does not exist a moment later — so nothing it does can reach the
firewall of the machine running it. `unshare -rn` where unprivileged user
namespaces are allowed, a plain network namespace under sudo where they are
not; without either, or without `nft`, it says so and stops.

CI runs it with `--require`, which turns "could not run" into a failure. A skip
that reports success is the green tick that only means nobody checked.

`npm run oracle` asks the same of the evaluator. A real packet goes through a
real netfilter instance with one counter per expression under test, and the
counters say which of them matched it; the simulator is asked about the same
packet, described the same way. Four go through: a TCP SYN, a UDP datagram,
that SYN again over IPv6, and a byte on an established connection.

It earned its place immediately. `ip saddr . tcp dport @pairs` matched a UDP
packet, because a concatenation key was being read as a field rather than as
what it is — the destination port *of a TCP packet*. The standalone matcher had
always checked the protocol; the concatenation table, added later, did not. No
test here would have found it, because every one of them is this project
stating what nftables does.

`test/fixtures/flawed.nft` is reported as skipped there and always will be:
its element list is abbreviated to a comment, so nft refuses it. That is
recorded in its own commit and is not a regression.

## The Rust half

CI runs `cargo fmt --check` and `cargo clippy -D warnings` over `src-tauri`,
and neither has a counterpart in `npm test` — so a Rust change can pass
everything locally and fail on push. `npm run rust:check` is the same pair;
`npm run rust:fmt` fixes the formatting half.

Take rustfmt's output rather than configuring around it. It is the convention
CI enforces, and there are five hundred lines of Rust here to have an opinion
about.

One of them is not Rust. `nft_arm` is a shell script living inside a Rust
string, and neither `cargo fmt` nor `cargo clippy` has an opinion about shell —
which is how it came to lose the copy it exists to protect, and to keep it in
`/tmp`. `test/rollback-script.test.js` extracts that script from this file and
runs it against a fake `nft`, so the one part of the safety net that no
compiler checks is at least executed by something.

## Screenshots and GIFs

Both drive the real frontend in headless Chromium, and both import the flawed
fixture the way a user would — through the import dialog. Committed media goes
stale silently, so regenerate it when the interface changes.

`npm run shots` produces the one still the README uses: the canvas, whose
layout is the single idea here that prose struggles with. There were nine, and
eight of them showed a window rather than a finding.

`npm run gifs` records the three scenes that carry the argument — paste and see
it proved, a packet walking to a verdict, a shadowed rule next to the button
that deletes it. One browser context per scene, then ffmpeg trims the setup off
the front and encodes with a per-scene palette; a shared one turns the aqua on
near-black into mud. It needs **ffmpeg on PATH**, the only dependency in this
repo that is not npm.

Two things a recorder has to be told, because neither is automatic. A browser
records the page and not the pointer, so a cursor is drawn into the page from
real mouse events — it cannot claim a click that did not happen. And a demo is
not a test: acted at test speed it is unreadable, so the pauses are deliberate.

Everything is produced twice, `name.png` and `name.es.png`. An English page
illustrated with a Spanish interface reads as nobody having looked, and
`test/readme.test.js` holds each README to its own language.

## Platform notes

- WebKitGTK has poor `backdrop-filter` support. The frontend detects Linux from
  the Rust side and swaps glass for a solid surface, keeping the layering.
- Timers belong to the window in a browser but not in the jsdom harness;
  aliasing `setTimeout` or `performance` to jsdom's makes them call themselves.
- Tauri gates every IPC call behind a capability. A missing grant rejects
  silently, which reads as a dead button — hence the capabilities test.
