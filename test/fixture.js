/* Loads the flawed ruleset the analyser tests are written against.
   It is a fixture, deliberately kept out of the product. */
import { readFileSync } from "node:fs";
import { MODEL } from "../src/core/model.js";
import { parseNft } from "../src/core/parse.js";

export const flawedSource = () =>
  readFileSync(new URL("./fixtures/flawed.nft", import.meta.url), "utf8");

export function loadFlawed() {
  const p = parseNft(flawedSource());
  MODEL.chains = p.chains;
  MODEL.sets = p.sets.map((s) => ({ ...s }));
  return p;
}
