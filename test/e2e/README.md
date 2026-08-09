# The end-to-end run

```
npx tauri build --no-bundle     # this drives the built application, not the source
npm run e2e
```

## Why it exists

`npm test` evaluates every module in jsdom, dispatches real events and builds
every screen — and it cannot reach the Tauri bridge, because there is no Rust
on the other side of it. Four defects got past it in two days and every one was
found by driving the real application by hand:

- opening the **simulator on a project with no chains** threw, and a blank
  project is the state the application starts in, one click away;
- **`openApply` fired the drift check** alongside a probe nobody had waited
  for, so it only ever ran on the second open of the dialog;
- **editing a rule dropped its handle**, which `nft replace` keeps — so an
  edit read as somebody else's drift and cost two commands instead of one;
- **two content security policies** contradicted each other about the IPC
  bridge, so every call the application made logged a violation and fell back
  to a slower transport.

None of those are subtle. They were invisible because nothing ever started the
program and used it.

## How it works

The Tauri bridge cannot be stubbed from the page — `__TAURI_INTERNALS__` is
non-writable and non-configurable, and Tauri injects it after any init script
Playwright could add. So nothing here is stubbed. What is replaced is the
**far end**: the Rust side runs `Command::new("ssh")` resolved through `PATH`,
so `fake-ssh.rs` is compiled and put first on `PATH`. Real argv, a real child
process, the real parser — only the firewall is imaginary.

It has to be `ssh.exe`. Rust's `Command` tries the literal name and `.exe` and
does not honour `PATHEXT`, so a `.cmd` is invisible to it.

What the stand-in answers with is set per scenario:

| variable | effect |
|---|---|
| `EFEFLOW_FAKE_RULESET` | the file `nft -a list ruleset` returns |
| `EFEFLOW_FAKE_FAIL=read` | refuses the read the way a non-root host does |
| `EFEFLOW_FAKE_FAIL=probe` | refuses the connection entirely |

## What it will not do

**Windows only.** The debugging protocol is WebView2's and WebKitGTK does not
speak it, so this cannot run on the Linux build or in CI as it stands. A run
that cannot happen says so and exits 0 — it is a gate to pass before a release,
not a replacement for `npm test`.

It also **tests the binary that is there**. If `src/` is newer than the `.exe`
it refuses rather than quietly testing the last build.

## Adding to it

The entry requirement is that a scenario covers something jsdom cannot: the
bridge, the real webview, or the first draw of a screen. Anything that can be
asserted about the source or about a module belongs in `test/` with the other
986, which run in a second and on every platform.
