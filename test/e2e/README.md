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
not a replacement for `npm test`. What covers Linux instead is below.

It also **tests the binary that is there**. If `src/` is newer than the `.exe`
it refuses rather than quietly testing the last build.

## The Linux half

```
npm run e2e:linux -- efe@the-machine
npm run e2e:linux -- efe@the-machine --deb dist/efeflow_0.9.10_amd64.deb
```

The `.deb` is what people download, and the Linux path has code Windows does
not even compile — `am_root()`, `helper()`, `pkexec`, the polkit action. It has
already produced one real defect that way. There is no CDP over there, so
`linux-smoke.sh` covers the cheap and expensive part instead: whether the
package put its parts where the code looks for them, whether the helper's three
verbs behave (and whether `apply` is still refused), and whether the
application starts **with a webview**.

That last one is the point of the process checks. `WebKitWebProcess` only
appears once a page has been rendered, so a window that comes up empty — what a
broken frontend looks like on Linux — is caught rather than counted as a
successful launch.

It clicks nothing and claims nothing about the interface. It needs a desktop
session logged in on the machine, and says so rather than pretending when there
is none. It writes nothing to the firewall.

Checked the same way as the Windows run: the helper was chowned and stripped of
its shebang, and the binary replaced with one that exits immediately. Both
mutations went red on exactly the right lines — and the first attempt reported
"it closes when asked" as a pass about a process that had never opened, which
is the shape of dishonesty this project keeps finding in itself. The section
now refuses to report on a run that did not happen.

## Adding to it

The entry requirement is that a scenario covers something jsdom cannot: the
bridge, the real webview, or the first draw of a screen. Anything that can be
asserted about the source or about a module belongs in `test/` with the other
986, which run in a second and on every platform.
