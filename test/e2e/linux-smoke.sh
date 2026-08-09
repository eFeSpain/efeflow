#!/bin/sh
# Does the Linux build start, and is the package the code expects?
#
# The end-to-end run drives the application through WebView2's debugging
# protocol, and WebKitGTK — the webview Tauri uses on Linux — does not speak
# it. So nothing automated touches the .deb that people actually download,
# while the Linux path has code Windows does not even compile: am_root(),
# helper(), pkexec, the polkit action. It has already produced one real defect
# that way.
#
# This is the cheap half of the answer. It cannot click anything, so it makes
# no claim about the interface. What it does check is the failure that is both
# likeliest and most expensive — the application not starting, or starting
# without a webview — and that the package put its parts where the code looks
# for them.
#
# Run it on the machine itself, from inside its graphical session's reach:
#   sh linux-smoke.sh                 against whatever is installed
#   sh linux-smoke.sh ./efeflow.deb   install that first, then check
#
# It touches no firewall. It reads nftables' version and nothing else.
set -u
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

pass=0; fail=0
ok()   { pass=$((pass+1)); printf '  ok    %s\n' "$1"; }
no()   { fail=$((fail+1)); printf '  FAIL  %s\n' "$1"; }
note() { printf '        %s\n' "$1"; }
check() { if [ "$1" = 0 ]; then ok "$2"; else no "$2"; fi; }

DEB="${1-}"
HELPER=/usr/libexec/efeflow/efeflow-nft-helper
ACTION=/usr/share/polkit-1/actions/com.alegoriasoft.efeflow.policy
ACTION_ID=com.alegoriasoft.efeflow.nft-read

echo
echo "── the package ─────────────────────────────────────────────"

if [ -n "$DEB" ]; then
  if sudo -n apt-get install -y "$DEB" >/tmp/efeflow-install.log 2>&1; then
    ok "installed $DEB"
  else
    no "installing $DEB"; tail -3 /tmp/efeflow-install.log | sed 's/^/        /'
  fi
fi

command -v eFeFlow >/dev/null 2>&1; check $? "eFeFlow is on PATH"
note "$(dpkg-query -W -f='${Package} ${Version}' efeflow 2>/dev/null || echo 'not a dpkg install')"

[ -x "$HELPER" ]; check $? "the helper is installed and executable"
[ -f "$ACTION" ]; check $? "the polkit action is installed"

# pkexec refuses a helper that is not root's or that others can write to, and
# says so in a way that reads as a broken package. Check it here instead.
if [ -x "$HELPER" ]; then
  owner=$(stat -c '%U:%G %a' "$HELPER")
  case "$owner" in
    "root:root 755"|"root:root 750") ok "the helper is root:root and not group-writable ($owner)" ;;
    *) no "pkexec will refuse the helper: $owner" ;;
  esac
  head -c 2 "$HELPER" | grep -q '#!' ; check $? "it has a shebang, so execve can run it"
fi

if command -v pkaction >/dev/null 2>&1; then
  pkaction --action-id "$ACTION_ID" >/dev/null 2>&1
  check $? "polkit knows the action by the id the policy declares"
else
  note "pkaction is not installed; the action was not checked"
fi

echo
echo "── the three things the helper may do ──────────────────────"
if [ -x "$HELPER" ] && sudo -n true 2>/dev/null; then
  sudo -n "$HELPER" read >/dev/null 2>&1; check $? "read"
  printf 'table inet smoke_check {\n  chain c {\n    type filter hook input priority 0; policy accept;\n  }\n}\n' \
    | sudo -n "$HELPER" check >/dev/null 2>&1
  check $? "check, on a ruleset nft accepts"
  # and it must refuse anything else, apply above all
  sudo -n "$HELPER" apply >/dev/null 2>&1
  [ $? -eq 2 ]; check $? "apply is refused with exit 2, as the helper's own comment says it must be"
  # the check really was a check
  [ "$(sudo -n nft list ruleset 2>/dev/null | grep -c smoke_check)" = 0 ]
  check $? 'and the check loaded nothing'
else
  note "no passwordless sudo here, so the helper's verbs were not run"
fi

echo
echo "── does it start, and does the webview come up? ─────────────"
UID_=$(id -u)
XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-/run/user/$UID_}
export XDG_RUNTIME_DIR
[ -n "${WAYLAND_DISPLAY:-}" ] || [ -n "${DISPLAY:-}" ] || {
  if [ -e "$XDG_RUNTIME_DIR/wayland-0" ]; then WAYLAND_DISPLAY=wayland-0; export WAYLAND_DISPLAY; fi
}
[ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ] || {
  DBUS_SESSION_BUS_ADDRESS=unix:path=$XDG_RUNTIME_DIR/bus; export DBUS_SESSION_BUS_ADDRESS; }

if [ -z "${WAYLAND_DISPLAY:-}" ] && [ -z "${DISPLAY:-}" ]; then
  no "no graphical session to start it in — run this where one is logged in"
else
  LOG=/tmp/efeflow-smoke.log
  : > "$LOG"
  setsid eFeFlow >"$LOG" 2>&1 </dev/null &
  sleep 14

  # -x, and never -f with the binary's path: `pkill -f eFeFlow` matches the
  # command line of the shell running it, and kills itself.
  if pgrep -x eFeFlow >/dev/null; then
    ok "the process is still alive after 14s"

    # A webview that loaded a page spawns these two. Without them the window is
    # up and empty, which is the failure that would otherwise go unseen.
    ps -eo comm | grep -q WebKitWebProces; check $? "WebKitWebProcess is running — a page was rendered"
    ps -eo comm | grep -q WebKitNetworkPr; check $? "WebKitNetworkProcess is running"

    pkill -x eFeFlow 2>/dev/null
    sleep 1
    [ -z "$(pgrep -x eFeFlow)" ]; check $? "it closes when asked"
  else
    # Everything below this depends on there being a process. Saying `ok` to
    # "it closes when asked" about one that never opened is the shape of
    # dishonesty this whole project keeps finding in itself.
    no "the process is still alive after 14s"
    note "the rest of this section needs a running application and was not checked"
  fi

  # The log is worth reading either way: when it started, to catch a panic it
  # survived, and when it did not, because the reason is in there.
  if grep -q "panicked at" "$LOG"; then
    no "it panicked"; grep -m2 "panicked at" "$LOG" | sed 's/^/        /'
  else
    ok "no panic in its output"
  fi
  # VMware without 3D and the EGL fallbacks are noise on any virtual machine.
  other=$(grep -vE "VMware: No 3D|libEGL warning|DRI2|^$" "$LOG" | head -3)
  [ -z "$other" ] && ok "and nothing else on stderr" || { note "unexplained output:"; echo "$other" | sed 's/^/        /'; }
fi

echo
echo "── nftables, read and not touched ──────────────────────────"
nft --version >/dev/null 2>&1; check $? "nft is installed: $(nft --version 2>/dev/null)"
note "this script wrote nothing to the firewall"

echo
printf '  %d passed, %d failed\n\n' "$pass" "$fail"
[ "$fail" = 0 ]
