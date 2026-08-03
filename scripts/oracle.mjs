#!/usr/bin/env node
/* The evaluator against the kernel.
 *
 * `npm run differ` asks nft whether a round trip kept the meaning of a
 * ruleset. This asks the kernel whether the evaluator agrees with netfilter
 * about a packet.
 *
 * A real packet is sent through a real netfilter instance inside a throwaway
 * network namespace, with one counter per expression under test. The counters
 * say which expressions matched it; eFeFlow is asked the same question about
 * the same packet, described the same way. Four packets go through: a TCP SYN,
 * a UDP datagram, the same SYN over IPv6, and a byte on an established
 * connection.
 *
 * Every table of cases under test/ is still this project stating what nftables
 * does, and a matcher can be confidently wrong for as long as the statement
 * is. This one does not need anybody to be right about netfilter.
 *
 *   npm run oracle              run it
 *   npm run oracle -- --require refuse to be skipped
 *
 * Only our packet reaches the counters, and only inside a namespace that does
 * not exist a moment later: nothing here can touch the firewall of the machine
 * it runs on.
 */
import { argv, exit, stdout } from "node:process";
import { spawnSync } from "node:child_process";
import { writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const { MODEL } = await import("../src/core/model.js");
const { matches, unmodelled } = await import("../src/core/simulate.js");


const REQUIRE = argv.slice(2).includes("--require");

function sandbox() {
  const probe = (cmd, as) => {
    const r = spawnSync(cmd[0], [...cmd.slice(1), "sh", "-c", "true"], { encoding: "utf8" });
    return r.status === 0 ? { cmd, as } : null;
  };
  return probe(["unshare", "-rn"], "a user namespace")
      ?? probe(["sudo", "-n", "unshare", "-n"], "sudo")
      ?? null;
}
const nftv = spawnSync("nft", ["--version"], { encoding: "utf8" });
const BOX = nftv.status === 0 ? sandbox() : null;
if (nftv.status !== 0 || !BOX) {
  const why = nftv.status !== 0
    ? "there is no `nft` on this machine"
    : "no network namespace can be entered here";
  /* a skip that reports success is a green tick that only means nobody checked */
  stdout.write(`oracle: not run — ${why}.\n` + "\n");
  exit(REQUIRE ? 2 : 0);
}
stdout.write(`oracle: ${nftv.stdout.trim()}, in ${BOX.as}\n\n`);

const SETS_NFT = `
	set ports { type inet_service ; elements = { 18080, 22 } }
	set nets  { type ipv4_addr ; flags interval ; elements = { 127.0.0.0/8 } }
	set nets6 { type ipv6_addr ; flags interval ; elements = { ::1/128 } }
	set pairs { type ipv4_addr . inet_service ; elements = { 127.0.0.1 . 18080 } }
	set ifs   { type ifname ; flags interval ; elements = { "lo", "veth*" } }
`;
const SETS_MODEL = [
  { n: "ports", el: ["18080", "22"] },
  { n: "nets", el: ["127.0.0.0/8"] },
  { n: "nets6", el: ["::1/128"] },
  { n: "pairs", el: ["127.0.0.1 . 18080"] },
  { n: "ifs", el: ["lo", "veth*"] },
];

/* ── the packets, each said twice ────────────────────────────────────────── */
const WORK = mkdtempSync(join(tmpdir(), "efeflow-oracle-"));
const RULES = join(WORK, "probe.nft");

const SPORT = 15000, DPORT = 18080;

const SEND = {
  tcp: `
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", ${SPORT}))
s.settimeout(0.3)
try: s.connect(("127.0.0.1", ${DPORT}))
except Exception: pass`,
  udp: `
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", ${SPORT}))
s.sendto(b"x", ("127.0.0.1", ${DPORT}))`,
  tcp6: `
s = socket.socket(socket.AF_INET6)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("::1", ${SPORT}))
s.settimeout(0.3)
try: s.connect(("::1", ${DPORT}))
except Exception: pass`,
  icmp: `
import subprocess
subprocess.run(["ping","-c","1","-W","1","-s","64","127.0.0.1"],
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)`,
  /* the same TCP SYN, watched on its way out instead of on its way in */
  output: `
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", ${SPORT}))
s.settimeout(0.3)
try: s.connect(("127.0.0.1", ${DPORT}))
except Exception: pass`,
  /* a listener, a handshake, and then a byte: the byte is the established one */
  established: `
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", ${DPORT})); srv.listen(1)
c = socket.socket()
c.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
c.bind(("127.0.0.1", ${SPORT}))
c.connect(("127.0.0.1", ${DPORT}))
srv.accept()
import time; time.sleep(0.1)
c.send(b"hello")
time.sleep(0.2)`,
};

const PKT = {
  tcp:  { proto: "tcp", saddr: "127.0.0.1", daddr: "127.0.0.1", state: "new", flags: ["syn"] },
  udp:  { proto: "udp", saddr: "127.0.0.1", daddr: "127.0.0.1", state: "new", flags: [] },
  tcp6: { proto: "tcp", saddr: "::1", daddr: "::1", state: "new", flags: ["syn"] },
  established: { proto: "tcp", saddr: "127.0.0.1", daddr: "127.0.0.1", state: "established",
                 flags: ["ack", "psh"] },
  icmp: { proto: "icmp", saddr: "127.0.0.1", daddr: "127.0.0.1", state: "new", flags: [] },
  output: { proto: "tcp", saddr: "127.0.0.1", daddr: "127.0.0.1", state: "new", flags: ["syn"] },
};

/* which hook the probe chain hangs off, and which way round the interface is */
const HOOK = { icmp: "input", output: "output" };
const DIR  = { output: "out" };

/* which selector the jump uses to let only our packet through */
const GATE = {
  tcp: `tcp sport ${SPORT} tcp dport ${DPORT} tcp flags syn`,
  udp: `udp sport ${SPORT} udp dport ${DPORT}`,
  tcp6: `tcp sport ${SPORT} tcp dport ${DPORT} tcp flags syn`,
  established: `tcp sport ${SPORT} tcp dport ${DPORT} ct state established tcp flags & (psh) == psh`,
  icmp: `meta l4proto icmp icmp type echo-request`,
  output: `tcp sport ${SPORT} tcp dport ${DPORT} tcp flags syn`,
};

const COMMON = [
  "tcp dport 18080", "udp dport 18080", "tcp dport > 1024", "tcp dport < 1024",
  "tcp sport 15000", "udp sport 15000",
  "meta l4proto tcp", "meta l4proto udp", "meta l4proto 6", "meta l4proto 17",
  "meta nfproto ipv4", "meta nfproto ipv6",
  'iifname "lo"', 'iifname "lo*"', "iifname @ifs", 'iifname != "lo"',
  "ct state new", "ct state established", "ct state { new, established }",
  "ct state related", "ct state != new",
  "tcp flags syn", "tcp flags ack", "tcp flags & (syn|ack) == syn",
  "tcp flags syn / fin,syn,rst,ack", "tcp flags & (fin|syn|rst|psh|ack|urg) == 0",
  "ip saddr 127.0.0.1", "ip saddr 127.0.0.0/8", "ip saddr @nets",
  "ip saddr . tcp dport @pairs", "tcp dport @ports",
  "ip6 saddr ::1", "ip6 saddr ::1/128", "ip6 saddr @nets6",
  "ip6 nexthdr tcp", "ip protocol tcp",
  "ip frag-off & 0x1fff != 0",
  /* the outgoing side, which only the output probe can answer */
  'oifname "lo"', 'oifname "eth*"', 'oifname != "lo"', "oif lo",
  /* icmp: the protocol is knowable, which message it is never was */
  "meta l4proto icmp", "ip protocol icmp", "icmp type echo-request", "icmp type echo-reply",

  /* negation, in every place it can be written */
  "tcp dport != { 22, 80 }", "ip saddr != @nets", "ip saddr != 127.0.0.0/8",
  "meta l4proto != tcp", "ct state != { new, established }",
  /* anonymous sets, including a concatenated one */
  "ip saddr { 127.0.0.1 }", "ip saddr . tcp dport { 127.0.0.1 . 18080 }",
  "ip saddr . tcp dport { 10.0.0.1 . 22 }",
  /* the transport-agnostic spelling */
  "th dport 18080", "th sport 15000", "th dport 9999",
  /* several constraints of the same kind in one rule, which is one rule */
  "tcp sport 15000 tcp dport 18080", "tcp sport 15000 tcp dport 9999",
  "ip saddr 127.0.0.1 ip daddr 127.0.0.1", "ip saddr 127.0.0.1 ip daddr 10.0.0.1",
  /* a range written the other way, and the boundaries */
  "tcp dport 18080-18080", "tcp dport 18079-18080", "tcp dport 18081-18999",
  /* no verdict maps here: one is the verdict, so the counter behind it never
     runs and the probe would be measuring its own shape. test/vmap.test.js
     asks about those where they belong, at the verdict. */
  /* things nothing here models: the kernel will disagree and the trace has to
     say so rather than be quietly right by accident */
  "meta mark 0x1", "meta skuid 0", "ip ttl 64", "ip ttl < 5", "meta length > 10000",
  "ct mark 0x1", "ip dscp cs1",
];

/* Which of the expressions this nft will take.
 *
 * They go in one file, so one it refuses takes the other sixty-nine with it —
 * and versions differ about what they will parse: 1.0.2 will not have a
 * concatenated set lookup at all ("Byteorder mismatch"), which is fixed later.
 * nft names the line it objects to, so the line comes out and it is asked
 * again, and what it would not take is reported rather than passed over. */
function accepted(cases, kind) {
  let live = cases.map((e, i) => ({ e, i }));
  const refused = [];
  for (let attempt = 0; attempt < cases.length; attempt++) {
    writeFileSync(RULES, rulesetFor(live, kind));
    const r = spawnSync(BOX.cmd[0], [...BOX.cmd.slice(1), "sh", "-c", `nft -c -f ${RULES} 2>&1`],
      { encoding: "utf8" });
    const out = (r.stdout || "") + (r.stderr || "");
    if (!/Error:/.test(out)) return { live, refused };
    const m = out.match(/probe\.nft:(\d+):/);
    if (!m) return { live: [], refused };
    /* the rules start after the sets and the header; find the one on that line */
    const line = rulesetFor(live, kind).split("\n")[+m[1] - 1] ?? "";
    const c = line.match(/comment "c(\d+)"/);
    if (!c) return { live: [], refused };
    refused.push(+c[1]);
    live = live.filter((x) => x.i !== +c[1]);
  }
  return { live, refused };
}

function rulesetFor(live, kind) {
  const rules = live.map(({ e, i }) => `\t\t${e} counter comment "c${i}"`).join("\n");
  return `table inet probe {
${SETS_NFT}
	chain input {
		type filter hook ${HOOK[kind] ?? "input"} priority 0; policy accept;
		${GATE[kind]} jump probe
	}

	chain probe {
${rules}
	}
}
`;
}

function runOne(kind) {
  const cases = COMMON;
  const { live, refused } = accepted(cases, kind);
  if (!live.length) {
    stdout.write(`  ${kind}: this nft would not take the probe at all` + "\n");
    return { bad: 0, seen: 0 };
  }
  if (refused.length)
    stdout.write(`  ${kind.padEnd(12)} this nft refuses ${refused.length}: `
      + refused.map((i) => JSON.stringify(cases[i])).join(", ") + "\n");
  const rules = live.map(({ e, i }) => `\t\t${e} counter comment "c${i}"`).join("\n");
  const ruleset = `table inet probe {
${SETS_NFT}
	chain input {
		type filter hook ${HOOK[kind] ?? "input"} priority 0; policy accept;
		${GATE[kind]} jump probe
	}

	chain probe {
${rules}
	}
}
`;
  writeFileSync(RULES, ruleset);
  const script = `
set -e
ip link set lo up
nft -f ${RULES}
python3 - <<'PY'
import socket
${SEND[kind]}
PY
nft list chain inet probe probe
`;
  const r = spawnSync(BOX.cmd[0], [...BOX.cmd.slice(1), "sh", "-c", script], { encoding: "utf8" });
  const out = (r.stdout || "") + (r.stderr || "");
  if (/Error:/.test(out)) {
    stdout.write(`  ${kind}: the kernel refused the ruleset` + "\n");
    stdout.write("   " + out.split("\n").filter((l) => /Error/.test(l)).slice(0, 2).join("\n   "));
    return { bad: 0, seen: 0 };
  }
  const kernel = new Map();
  for (const line of out.split("\n")) {
    const m = line.match(/counter packets (\d+) bytes \d+ comment "c(\d+)"/);
    if (m) kernel.set(+m[2], +m[1] > 0);
  }
  if (![...kernel.values()].some(Boolean)) {
    stdout.write(`  ${kind}: no counter moved — the packet never reached the chain` + "\n");
    return { bad: 0, seen: 0 };
  }

  Object.assign(MODEL, { chains: [], objects: [], tables: [], prelude: [], sets: SETS_MODEL });
  const leaving = DIR[kind] === "out";
  const p = { dir: DIR[kind] ?? "in", iif: leaving ? "" : "lo", oif: leaving ? "lo" : "",
              sport: SPORT, dport: DPORT, tracked: true, nat: true, ...PKT[kind] };

  let bad = 0, seen = 0, yes = 0, assumed = 0;
  for (const [i, expr] of cases.entries()) {
    if (!kernel.has(i)) continue;
    seen++;
    const k = kernel.get(i);
    if (k) yes++;
    const e = matches({ expr }, p);
    if (k === e) continue;
    /* Disagreeing about something it said it had not read is the design
       working: the verdict carries the admission with it. Disagreeing with
       nothing to show for it is the failure this harness is for. */
    const un = unmodelled(expr);
    if (un.length) { assumed++; continue; }
    bad++;
    stdout.write(`  SILENT   ${kind.padEnd(12)} kernel=${String(k).padEnd(5)} eFeFlow=${String(e).padEnd(5)} ${expr}` + "\n");
  }
  stdout.write(`  ${kind.padEnd(12)} ${seen} compared, ${bad} silent, ${assumed} declared`
    + `  (kernel: ${yes} match / ${seen - yes} do not)` + "\n");
  return { bad, seen };
}

let bad = 0, seen = 0;
for (const kind of ["tcp", "udp", "tcp6", "established", "icmp", "output"]) {
  const r = runOne(kind);
  bad += r.bad; seen += r.seen;
}
rmSync(WORK, { recursive: true, force: true });
stdout.write(`\n  ${seen} compared against the kernel, ${bad} disagree\n` + "\n");
if (REQUIRE && seen === 0) {
  stdout.write("  nothing was compared, which is not the same as agreeing\n" + "\n");
  exit(2);
}
exit(bad ? 1 : 0);
