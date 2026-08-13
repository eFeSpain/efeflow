/* The one string that decides whether a firewall keeps its net.
 *
 * applyWithNet disarms the rollback only when it is certain nothing was
 * applied, and the only thing that certifies that is nft's own pre-flight
 * refusal — recognised by looksLikeValidationFailure matching a phrase that
 * nft_apply writes in Rust. Two copies of the same words, in two languages, in
 * two files, on the path where being wrong strands a machine with no way back.
 *
 * jsdom tests cannot catch this drifting: apply.test.js feeds the predicate a
 * hand-written copy of the phrase, so it agrees with itself whatever the Rust
 * side says. This is the check that actually reads the Rust and holds the two
 * to each other. Change the message in nft.rs and this fails here, in a second,
 * instead of in a lockout, in the field.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { looksLikeValidationFailure, VALIDATION_FAILURE_MARK } from "../src/apply.js";

const nftRs = readFileSync(new URL("../src-tauri/src/nft.rs", import.meta.url), "utf8");

test("nft_apply still produces the phrase the disarm decision keys on", () => {
  /* The `format!` in nft_apply's failure branch. Its literal is what reaches
     the app as stderr, minus the `{}` that nft's own error fills in. */
  const m = nftRs.match(/format!\(\s*"([^"]*)"/g)?.find((s) => s.includes("validation failed"));
  assert.ok(m, "nft_apply no longer formats a 'validation failed' message — the contract moved, and the JS side must move with it");
  assert.ok(m.includes(VALIDATION_FAILURE_MARK),
    `the Rust message no longer contains "${VALIDATION_FAILURE_MARK}" — a failed apply would stop being recognised as a refusal, and a real lockout could get disarmed`);
});

test("the string nft_apply builds is recognised by the predicate", () => {
  /* Reconstruct the stderr the app receives: the Rust prefix, then nft's error
     where the `{}` was. If the predicate does not match this, applyWithNet
     treats a plain rejection as a lockout — safe, but wasteful, and a sign the
     two sides have drifted. */
  const stderr = `${VALIDATION_FAILURE_MARK}:\nError: syntax error, unexpected string`;
  assert.equal(looksLikeValidationFailure({ stderr }), true);
});

test("a dropped connection is never mistaken for a refusal", () => {
  for (const line of [
    "client_loop: send disconnect: Broken pipe",
    "Timeout, server fw1 not responding.",
    "Connection to fw1 closed by remote host.",
    "kex_exchange_identification: read: Connection reset by peer",
    "",
  ]) assert.equal(looksLikeValidationFailure({ stderr: line }), false, line);
});
