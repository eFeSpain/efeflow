#!/bin/sh
# The bundler copies the two extra files in; this is what makes them work.
#
# pkexec refuses to run a program that is not owned by root or that anybody
# else can write to, and it says so only on stderr — so a helper that arrived
# owned by the build user, or mode 0644, is a helper that silently never runs
# and an application that looks like it lost the ability to read the host.
set -e

helper=/usr/libexec/efeflow/efeflow-nft-helper
if [ -f "$helper" ]; then
  chown root:root "$helper"
  chmod 0755 "$helper"
fi

policy=/usr/share/polkit-1/actions/com.alegoriasoft.efeflow.policy
if [ -f "$policy" ]; then
  chown root:root "$policy"
  chmod 0644 "$policy"
fi

exit 0
