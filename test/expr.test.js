/* Editing one field of a rule must not cost you the rest of it. */
import test from "node:test";
import assert from "node:assert/strict";

import { readExpr, editExpr, setProto, setLog, setLimit } from "../src/core/expr.js";

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

test("a rule made only of things the panel cannot show is left exactly alone", () => {
  const odd = 'meta mark set 0x1 ct mark set meta mark tcp option maxseg size 1-500';
  assert.equal(editExpr(odd, {}), odd);
  assert.equal(editExpr(odd, { saddr: "" }), odd);
});
