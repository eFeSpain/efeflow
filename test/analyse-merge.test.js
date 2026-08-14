/* The "these rules differ only by port, use a set" hint must not collapse
 * rules that also differ by where they send the packet — merging dnat rules
 * with different targets onto the first one's target is a silent mis-NAT. */
import test from "node:test";
import assert from "node:assert/strict";
import { MODEL } from "../src/core/model.js";
import { analyse } from "../src/core/analyse.js";
import { parseNft } from "../src/core/parse.js";

const load = (src) => {
  const p = parseNft(src);
  Object.assign(MODEL, {
    chains: p.chains, sets: p.sets, objects: p.objects, tables: p.tables, prelude: p.prelude,
  });
};
const merges = () => analyse().filter((f) => f.kind === "merge");

const NAT = (targets) => `table ip nat {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		tcp dport 80 dnat to ${targets[0]}
		tcp dport 81 dnat to ${targets[1]}
		tcp dport 82 dnat to ${targets[2]}
	}
}`;

test("dnat rules with different targets are not offered as mergeable", () => {
  load(NAT(["10.0.0.1", "10.0.0.2", "10.0.0.3"]));
  assert.equal(merges().length, 0, "three different NAT targets were collapsed into one");
});

test("dnat rules with the same target still are", () => {
  load(NAT(["10.0.0.1", "10.0.0.1", "10.0.0.1"]));
  assert.equal(merges().length, 1, "identical-target siblings are a genuine merge candidate");
});
