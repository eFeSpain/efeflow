/* Editing one field of a rule must not cost you the rest of it. */
import test from "node:test";
import assert from "node:assert/strict";

import { readExpr, editExpr, setProto, setLog, setLimit, readLog, editLogParts } from "../src/core/expr.js";

/* The exact rule that used to be destroyed by typing in the comment box. */
const RICH =
  'ip6 saddr @admins tcp dport 22 tcp flags syn / syn,ack ' +
  'log prefix "ssh " limit rate 3/minute burst 3 packets';

test("everything the panel does not model survives an edit to what it does", () => {
  const out = editExpr(RICH, { dport: "2222" });
  assert.equal(
    out,
    'ip6 saddr @admins tcp dport 2222 tcp flags syn / syn,ack ' +
      'log prefix "ssh " limit rate 3/minute burst 3 packets',
  );
});

test("an edit to one field leaves the eight around it alone", () => {
  const before = readExpr(RICH);
  const after = readExpr(editExpr(RICH, { saddr: "@ops" }));
  for (const k of ["proto", "daddr", "sport", "dport", "state", "iif", "oif", "limit", "burst"])
    assert.equal(after[k], before[k], `${k} changed and should not have`);
  assert.equal(after.saddr, "@ops");
});

/* `ip saddr` on an IPv6 address matches nothing at all, and nothing says so. */
test("the address family follows the address", () => {
  assert.match(editExpr("ip saddr 10.0.0.1 accept", { saddr: "2001:db8::1" }), /ip6 saddr 2001:db8::1/);
  assert.match(editExpr("ip6 saddr 2001:db8::1", { saddr: "10.0.0.1" }), /\bip saddr 10\.0\.0\.1/);
  assert.match(editExpr("ip6 saddr 2001:db8::1", { saddr: "2001:db8::2" }), /ip6 saddr 2001:db8::2/);
});

test("a set reference does not change the family it was written under", () => {
  assert.match(editExpr("ip6 saddr @a", { saddr: "@b" }), /ip6 saddr @b/);
});

/* iif resolves to a device index at load time and iifname compares the name.
   Rewriting one as the other changes what survives a device being recreated. */
test("iif stays iif and iifname stays iifname", () => {
  assert.equal(editExpr("iif lo accept", { iif: "lo" }), "iif lo accept");
  assert.equal(editExpr('iifname "eth0"', { iif: "eth1" }), 'iifname "eth1"');
  assert.equal(editExpr("", { iif: "wan0" }), 'iifname "wan0"');
  assert.equal(editExpr('iifname { "a", "b" }', { iif: '{ "a", "c" }' }), 'iifname { "a", "c" }');
});

test("a negation is part of the match, not decoration", () => {
  assert.equal(editExpr('iifname != "wan0"', { iif: "wan1" }), 'iifname != "wan1"');
  assert.equal(editExpr("ip saddr != 10.0.0.0/8", { saddr: "192.168.0.0/16" }),
    "ip saddr != 192.168.0.0/16");
  assert.equal(editExpr("ct state != invalid", { state: "new" }), "ct state != new");
});

test("clearing a field removes that fragment and only that one", () => {
  assert.equal(editExpr("ip saddr 10.0.0.1 tcp dport 22", { saddr: "" }), "tcp dport 22");
  assert.equal(editExpr("ip saddr 10.0.0.1 tcp dport 22", { dport: "" }), "ip saddr 10.0.0.1");
});

test("a field the expression never had is added", () => {
  assert.equal(editExpr("tcp dport 22", { saddr: "10.0.0.0/8" }), "tcp dport 22 ip saddr 10.0.0.0/8");
  assert.equal(editExpr("", { dport: "443", proto: "tcp" }), "meta l4proto tcp tcp dport 443");
});

/* A port belongs to a transport. Changing the protocol has to move the ports
   with it, or the rule says udp and filters tcp. */
test("changing the protocol moves the ports with it", () => {
  assert.equal(editExpr("tcp dport 53 tcp sport 1024", { proto: "udp" }), "udp dport 53 udp sport 1024");
  assert.equal(setProto("meta l4proto tcp ip saddr 1.2.3.4", "sctp"), "meta l4proto sctp ip saddr 1.2.3.4");
  assert.equal(setProto("ip protocol icmp", "igmp"), "ip protocol igmp");
});

test("clearing the protocol never strips the transport a port needs", () => {
  assert.equal(setProto("meta l4proto tcp tcp dport 22", ""), "tcp dport 22");
});

/* `log prefix "x "` without the log keyword is not a rule nft will take. */
test("turning logging off takes its arguments with it", () => {
  assert.equal(setLog('ip saddr 1.2.3.4 log prefix "drop " level warn', false), "ip saddr 1.2.3.4");
  assert.equal(setLog("ip saddr 1.2.3.4", true), "ip saddr 1.2.3.4 log");
  assert.equal(setLog('log prefix "keep "', true), 'log prefix "keep "',
    "an existing log statement is left as its author wrote it");
});

test("editing the rate keeps the burst", () => {
  assert.equal(setLimit("limit rate 5/second burst 10 packets", { rate: "3/minute" }),
    "limit rate 3/minute burst 10 packets");
  assert.equal(setLimit("limit rate 5/second burst 10 packets", { over: true }),
    "limit rate over 5/second burst 10 packets");
  assert.equal(setLimit("ip saddr 1.2.3.4 limit rate 5/second", { rate: "" }), "ip saddr 1.2.3.4");
});

test("reading an expression reports what is in it", () => {
  const q = readExpr(RICH);
  assert.equal(q.proto, "tcp");
  assert.equal(q.saddr, "@admins");
  assert.equal(q.dport, "22");
  assert.equal(q.limit, "3/minute");
  assert.equal(q.burst, "3");
  assert.equal(q.log, true);
  assert.equal(q.over, false);
});

/* Editing an unrelated field re-emits every field the panel models; the
   protocol must not be bolted on when the rule already implies it. */
test("setting the protocol it already has adds no redundant meta l4proto", () => {
  for (const [e, proto] of [
    ["icmp type echo-request", "icmp"],
    ["ip6 saddr @x icmpv6 type nd-router-advert", "icmpv6"],
    ["esp spi 0x1", "esp"],
    ["tcp flags syn", "tcp"],
  ]) {
    assert.equal(setProto(e, proto), e, `${e} gained a redundant meta l4proto ${proto}`);
    /* rebuild() re-reads the proto field and passes it back on any edit */
    assert.equal(editExpr(e, { proto }), e);
  }
  /* a genuinely protocol-less rule still gains one when asked */
  assert.equal(setProto("ip saddr 1.2.3.4", "tcp"), "meta l4proto tcp ip saddr 1.2.3.4");
});

test("a rule made only of things the panel cannot show is left exactly alone", () => {
  const odd = 'meta mark set 0x1 ct mark set meta mark tcp option maxseg size 1-500';
  assert.equal(editExpr(odd, {}), odd);
  assert.equal(editExpr(odd, { saddr: "" }), odd);
});

/* ── the three matches the panel learned to show ─────────────────────── */

test("icmp type, tcp flags and the firewall mark are read out of a rule", () => {
  const q = readExpr('icmp type echo-request tcp flags syn / syn,ack meta mark 0x1 accept');
  assert.equal(q.icmptype, "echo-request");
  assert.equal(q.tcpflags, "syn / syn,ack");
  assert.equal(q.metamark, "0x1");
});

test("each of the three edits only its own fragment", () => {
  const base = 'ip saddr 10.0.0.1 icmp type echo-request tcp dport 22';
  assert.equal(editExpr(base, { icmptype: "echo-reply" }),
    'ip saddr 10.0.0.1 icmp type echo-reply tcp dport 22');
  assert.equal(editExpr('tcp flags syn accept', { tcpflags: "syn / fin,syn,rst,ack" }),
    'tcp flags syn / fin,syn,rst,ack accept');
  assert.equal(editExpr('meta mark 0x1 drop', { metamark: "0x2" }), 'meta mark 0x2 drop');
});

test("the icmp family follows the rule's protocol when one is added", () => {
  assert.match(editExpr('meta l4proto icmpv6', { icmptype: "nd-router-advert" }),
    /icmpv6 type nd-router-advert/);
  assert.match(editExpr('tcp dport 22', { icmptype: "echo-request" }), /\bicmp type echo-request/);
  /* a rule that already named the family keeps it */
  assert.match(editExpr('icmpv6 type echo-request', { icmptype: "echo-reply" }), /icmpv6 type echo-reply/);
});

test("clearing one of the three removes only that fragment", () => {
  assert.equal(editExpr('icmp type echo-request tcp dport 22', { icmptype: "" }), "tcp dport 22");
  assert.equal(editExpr('meta mark 0x1 tcp dport 22', { metamark: "" }), "tcp dport 22");
  assert.equal(editExpr('tcp flags syn tcp dport 22', { tcpflags: "" }), "tcp dport 22");
});

/* `meta mark` read as a match must never catch it where it is not one: the
   `meta mark set` statement, the value on the right of a `set`, or a map. */
test("meta-mark reading does not collide with meta mark used elsewhere", () => {
  assert.equal(readExpr("meta mark set 0x1 accept").metamark, "", "the set statement is not a match");
  assert.equal(readExpr("ct mark set meta mark accept").metamark, "", "the value after set is not a match");
  assert.equal(readExpr("meta mark map { 0x1 : accept }").metamark, "", "a map is not a plain match");
  /* and editing another field carries each of them through untouched */
  assert.equal(editExpr("meta mark set 0x1 accept", { dport: "22" }),
    "meta mark set 0x1 accept tcp dport 22");
  assert.equal(editExpr("ct mark set meta mark accept", { saddr: "1.2.3.4" }),
    "ct mark set meta mark accept ip saddr 1.2.3.4");
});

/* ── log prefix and level ────────────────────────────────────────────── */

test("the log prefix and level are read and set without disturbing the rest", () => {
  const q = readLog('log prefix "drop " snaplen 64 level warn');
  assert.deepEqual(q, { on: true, prefix: "drop ", level: "warn", group: "" });
  /* set the prefix on a bare log */
  assert.equal(editLogParts("ip saddr 1.2.3.4 log", { prefix: "ssh " }),
    'ip saddr 1.2.3.4 log prefix "ssh "');
  /* set the level, keeping the prefix and the snaplen the author wrote */
  assert.equal(editLogParts('log prefix "x " snaplen 64', { level: "info" }),
    'log prefix "x " snaplen 64 level info');
  /* clear the prefix, keep the level */
  assert.equal(editLogParts('log prefix "x " level info', { prefix: "" }), "log level info");
});

/* nftables refuses a log that is both syslog (level) and nflog (group). */
test("a level is not forced onto an nflog group", () => {
  assert.equal(readLog('log prefix "x " group 2').group, "2");
  assert.equal(editLogParts('log prefix "x " group 2', { level: "info" }),
    'log prefix "x " group 2', "the invalid combination is refused, the rule left as it was");
  /* the prefix still edits freely alongside a group */
  assert.equal(editLogParts('log group 2', { prefix: "drop " }), 'log group 2 prefix "drop "');
});

test("setting a log prefix on a rule with no log adds the log too", () => {
  assert.equal(editLogParts("tcp dport 22 drop", { prefix: "denied " }),
    'tcp dport 22 drop log prefix "denied "');
  /* but not when the field is only being cleared */
  assert.equal(editLogParts("tcp dport 22 drop", { prefix: "" }), "tcp dport 22 drop");
});
