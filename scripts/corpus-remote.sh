#!/bin/sh
# The same two questions, asked of a different nft.
#
# Everything `npm run corpus` measures is measured against whatever nft is on
# the machine running it — here, WSL's 1.1.6. Debian stable ships 1.1.3, which
# is what most of the people this is aimed at are running, and a version is not
# a detail in a language this size: a construct one accepts the other may not.
#
# So this runs on a machine with the other nft. It is given a directory of
# original rulesets and a directory of our re-emissions, and answers for each:
#
#   does this nft accept the original?      (else it is not evidence)
#   does it accept what we wrote?
#   are the two listings the same ruleset?
#
#   sh corpus-remote.sh /path/to/originals /path/to/reemit
#
# Each load is in a network namespace of its own, so nothing here can reach the
# firewall of the machine it runs on.
set -u
PATH=/usr/local/sbin:/usr/sbin:/sbin:$PATH
export PATH

orig=${1:?usage: corpus-remote.sh <originals> <reemit>}
mine=${2:?usage: corpus-remote.sh <originals> <reemit>}

# Counters are runtime state: a file that came out of a ruleset listing carries
# real packet counts, and a bare counter is the right thing to emit. So is the
# clock: a set element with a timeout is listed with the time it has left, and
# two loads are never at the same instant.
norm() {
  sed -E -e 's/counter packets [0-9]+ bytes [0-9]+/counter/g' \
         -e 's/ expires [0-9a-z]+//g'
}
load() { unshare -rn sh -c 'nft -f "$1" >/dev/null 2>&1 && nft list ruleset' sh "$1" 2>/dev/null | norm; }

theirs=0; ours=0; same=0; moved=0; refused=0
for f in "$orig"/*; do
  [ -f "$f" ] || continue
  n=$(basename "$f")
  case "$n" in _*) continue ;; esac
  unshare -rn nft -c -f "$f" >/dev/null 2>&1 || continue   # not evidence here
  theirs=$((theirs+1))
  [ -f "$mine/$n" ] || continue
  if unshare -rn nft -c -f "$mine/$n" >/dev/null 2>&1; then
    ours=$((ours+1))
  else
    refused=$((refused+1)); printf 'REFUSED\t%s\n' "$n"; continue
  fi
  a=$(load "$f"); b=$(load "$mine/$n")
  if [ "$a" = "$b" ]; then same=$((same+1)); else moved=$((moved+1)); printf 'MOVED\t%s\n' "$n"; fi
done

printf '\n  nft            : %s\n' "$(nft --version)"
printf '  it accepts     : %s of the originals\n' "$theirs"
printf '  and accepts    : %s of ours\n' "$ours"
printf '  identical      : %s\n' "$same"
printf '  meaning moved  : %s\n' "$moved"
printf '  refused ours   : %s\n\n' "$refused"
[ "$moved" = 0 ] && [ "$refused" = 0 ]
