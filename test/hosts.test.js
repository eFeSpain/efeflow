/* The firewalls you look after, as a list.
 *
 * The tool remembered exactly one, so moving between the edge box and the
 * database box meant retyping a hostname you had typed a hundred times. */
import test from "node:test";
import assert from "node:assert/strict";

import {
  HOST, label, readHosts, writeHosts, addHost, updateHost, removeHost,
  findHost, asTarget, matching,
} from "../src/core/hosts.js";

test("a host needs somewhere to go and nothing else", () => {
  const h = HOST({ host: "fw01" });
  assert.equal(h.kind, "ssh");
  assert.equal(h.host, "fw01");
  assert.equal(h.sudo, true, "reading a live ruleset needs root more often than not");
  assert.ok(h.id, "it has to be nameable by something that survives a rename");
});

test("what to call one that has not been named", () => {
  assert.equal(label(HOST({ host: "fw01", user: "ana", port: "2222" })), "ana@fw01:2222");
  assert.equal(label(HOST({ host: "fw01" })), "fw01");
  assert.equal(label(HOST({ name: "Edge", host: "fw01" })), "Edge");
  assert.equal(label(HOST({ kind: "local" })), "local");
});

/* The same login on the same box is one firewall, however you spell it. */
test("pointing at a box you already have selects it", () => {
  let list = [];
  ({ list } = addHost(list, { name: "Edge", host: "fw01", user: "ana" }));
  const r = addHost(list, { host: "FW01", user: "ana" });
  assert.equal(r.list.length, 1, "a second copy of the same machine is not a second machine");
  assert.equal(r.host.name, "Edge", "and the name you gave it survives");
});

test("a different port is a different way in", () => {
  let list = [];
  ({ list } = addHost(list, { host: "fw01", user: "ana" }));
  ({ list } = addHost(list, { host: "fw01", user: "ana", port: "2222" }));
  assert.equal(list.length, 2);
});

test("renaming does not make it a different host", () => {
  let list = [];
  let host;
  ({ list, host } = addHost(list, { name: "Edge", host: "fw01" }));
  list = updateHost(list, host.id, { name: "Perimeter" });
  assert.equal(list.length, 1);
  assert.equal(list[0].name, "Perimeter");
  assert.equal(list[0].id, host.id, "the identity is the id, not the label");

  const r = addHost(list, { host: "fw01" });
  assert.equal(r.list.length, 1, "still the same box");
});

test("a host with nowhere to go is not stored", () => {
  const r = addHost([], { name: "someday", host: "" });
  assert.deepEqual(r.list, []);
  assert.equal(r.host, null);
});

test("removing takes one and leaves the rest", () => {
  let list = [];
  let a, b;
  ({ list, host: a } = addHost(list, { host: "fw01" }));
  ({ list, host: b } = addHost(list, { host: "fw02" }));
  list = removeHost(list, a.id);
  assert.equal(list.length, 1);
  assert.equal(findHost(list, b.id).host, "fw02");
  assert.equal(findHost(list, a.id), null);
});

/* It is read back from a file a person can edit, and from an older version. */
test("a stored list survives being read back", () => {
  let list = [];
  ({ list } = addHost(list, { name: "Edge", host: "fw01", user: "ana", port: "2222" }));
  ({ list } = addHost(list, { name: "DB", host: "fw02", sudo: false }));
  const back = readHosts(writeHosts(list));
  assert.deepEqual(back, list);
});

test("rubbish in the store is dropped, not thrown", () => {
  assert.deepEqual(readHosts("not json at all"), []);
  assert.deepEqual(readHosts("null"), []);
  assert.deepEqual(readHosts('{"host":"fw01"}'), [], "a list, or nothing");
  assert.deepEqual(readHosts('[null, 3, "fw01"]'), []);
  const one = readHosts('[{"host":"fw01"},{"host":""},{"host":"fw01"}]');
  assert.equal(one.length, 1, "the empty one goes and the duplicate folds in");
});

test("it converts to the shape the transport wants, and back", () => {
  const h = HOST({ name: "Edge", host: "fw01", user: "ana", port: "2222", sudo: false });
  const tg = asTarget(h);
  assert.deepEqual(tg, { kind: "ssh", host: "fw01", user: "ana", port: "2222", sudo: false });
  assert.ok(!("id" in tg) && !("name" in tg), "a transport has no use for a label");

  assert.equal(matching([h], tg).id, h.id, "and the entry in use can be found again");
  assert.equal(matching([h], { kind: "ssh", host: "other" }), null);
  assert.deepEqual(asTarget(null), { kind: "local", host: "", user: "", port: "", sudo: true });
});

/* An inventory names your firewalls. A project file is a thing people attach
   to a bug report. */
test("the inventory is not part of a project", async () => {
  const project = await import("../src/core/project.js");
  const saved = JSON.parse(project.serialise());
  for (const k of ["hosts", "inventory", "targets"])
    assert.ok(!(k in saved), `a project must not carry your ${k}`);
});
