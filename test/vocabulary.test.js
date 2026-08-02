import test from "node:test";
import assert from "node:assert/strict";
import { SERVICES, PROTOCOLS, HELPERS, TEMPLATES, templateById,
         parseService, validPort, catalogue, protoOf, OWNABLE } from "../src/core/vocabulary.js";

/* These are dragged straight onto rules, so a wrong port here becomes a wrong
   firewall quietly. */

for (const [label, list] of [["services", SERVICES], ["helpers", HELPERS]]) {
  test(`${label}: every entry is complete and plausible`, () => {
    assert.ok(list.length >= 9, `${label} is too thin to be a catalogue`);
    for (const s of list) {
      assert.match(s.n, /^[a-z0-9][\w.-]*$/, `${s.n} is not a usable name`);
      assert.ok(validPort(s.p), `${s.n}: ${s.p} is not a port, a range or a set`);
      assert.ok(["tcp", "udp"].includes(s.proto), `${s.n}: ${s.proto} is not a transport`);
    }
    const names = list.map((s) => s.n);
    assert.equal(new Set(names).size, names.length, `${label} lists a name twice`);
  });
}

test("the services people actually asked for are there", () => {
  const names = SERVICES.map((s) => s.n);
  for (const n of ["ftp", "telnet", "ssh", "smtp", "dns", "http", "https", "rdp", "smb"])
    assert.ok(names.includes(n), `${n} is missing from the catalogue`);
});

test("well-known ports are the well-known ones", () => {
  const port = (n) => SERVICES.find((s) => s.n === n);
  assert.equal(port("ftp").p, "21");
  assert.equal(port("telnet").p, "23");
  assert.equal(port("ssh").p, "22");
  assert.equal(port("https").p, "443");
  assert.equal(port("dns").proto, "udp", "dns over udp is the default one");
  assert.equal(port("rdp").p, "3389");
});

test("protocols are names nftables would accept after meta l4proto", () => {
  assert.ok(PROTOCOLS.length >= 12);
  for (const p of PROTOCOLS) assert.match(p.n, /^[a-z0-9][\w.-]*$/);
  const names = PROTOCOLS.map((p) => p.n);
  for (const n of ["tcp", "udp", "icmp", "icmpv6", "esp", "ah", "gre", "sctp"])
    assert.ok(names.includes(n), `${n} is missing`);
});

test("a port is a port, a range, or a set — and nothing else", () => {
  assert.ok(validPort("22"));
  assert.ok(validPort("10000-20000"));
  assert.ok(validPort("{ 80, 443 }"));
  assert.ok(!validPort("0"), "port zero is not a port");
  assert.ok(!validPort("65536"));
  assert.ok(!validPort("443-80"), "a range has to run forwards");
  assert.ok(!validPort("http"));
  assert.ok(!validPort(""));
});

test("the add box reads what people would type", () => {
  assert.deepEqual(parseService("telnet 23"), { n: "telnet", p: "23", proto: "tcp" });
  assert.deepEqual(parseService("tftp 69/udp"), { n: "tftp", p: "69", proto: "udp" });
  assert.deepEqual(parseService("RTP 10000-20000/UDP"),
    { n: "rtp", p: "10000-20000", proto: "udp" });
  assert.equal(parseService("telnet"), null, "a service without a port is not a service");
  assert.equal(parseService("telnet 99999"), null);
  assert.equal(parseService(""), null);
});

test("your own entry replaces the built-in of the same name", () => {
  const mine = catalogue([{ n: "ssh", p: "2222", proto: "tcp" }]);
  const ssh = mine.filter((s) => s.n === "ssh");
  assert.equal(ssh.length, 1, "a name must not appear twice");
  assert.equal(ssh[0].p, "2222", "yours wins");
  assert.equal(ssh[0].own, true, "and is marked as yours, so it can be edited");
  assert.equal(catalogue([]).find((s) => s.n === "ssh").own, false);
});

test("protoOf answers for built-ins and for yours", () => {
  assert.equal(protoOf("dns"), "udp");
  assert.equal(protoOf("http"), "tcp");
  assert.equal(protoOf("weird", [{ n: "weird", p: "9", proto: "udp" }]), "udp");
  assert.equal(protoOf("nothing-like-this"), "tcp", "tcp is the fallback, not a crash");
});

test("only the open-ended vocabularies are open", () => {
  assert.deepEqual(Object.keys(OWNABLE).sort(), ["HL", "PR", "SV"]);
  for (const k of Object.keys(OWNABLE)) {
    assert.ok(OWNABLE[k].hint.en && OWNABLE[k].hint.es, `${k}: hint is not bilingual`);
    assert.ok(typeof OWNABLE[k].parse === "function");
    assert.ok(OWNABLE[k].parse(OWNABLE[k].example), `${k}: its own example does not parse`);
  }
});

/* Templates used to be four labels with invented counts that did nothing. */
test("every template is a real group of rules", () => {
  assert.ok(TEMPLATES.length >= 3);
  for (const x of TEMPLATES) {
    assert.ok(x.title.en && x.title.es, `${x.id}: not bilingual`);
    assert.ok(x.rules.length >= 2, `${x.id}: one rule is not a template`);
    for (const r of x.rules) {
      assert.ok(typeof r.expr === "string", `${x.id}: a rule with no expression`);
      assert.ok(r.verdict, `${x.id}: a rule with no verdict`);
    }
  }
  assert.equal(templateById("no-such-template"), null);
});

/* A template that shipped somebody's addresses would write them into a real
   ruleset without the user ever typing them. */
test("no template names an address", () => {
  for (const x of TEMPLATES)
    for (const r of x.rules)
      assert.doesNotMatch(r.expr, /\b\d{1,3}(\.\d{1,3}){3}\b/,
        `${x.id} carries an address the user did not write`);
});
