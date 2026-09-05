/*
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE in the project root for license information.
 */

import assert from "node:assert/strict";
import test from "node:test";
import {
  InMemoryReplayGuard,
  canonicalJson,
  createAuthenticationInitiation,
  createAuthenticationPresentation,
  createDiscoveryAdvertisement,
  generateIdentityKeyPair,
  verifyAuthenticationPresentation,
  type AuthenticationPresentation,
} from "../src/legacy.js";

const start = new Date("2026-08-08T00:00:00.000Z");
const verifyAt = new Date("2026-08-08T00:00:01.000Z");

test("omits undefined object members in the alpha JSON mapping", () => {
  assert.equal(canonicalJson({ z: undefined, a: 1 }), '{"a":1}');
});

function fixture() {
  const presenter = generateIdentityKeyPair();
  const advertisement = createDiscoveryAdvertisement({ now: start, ttlMs: 60_000 });
  const initiation = createAuthenticationInitiation(advertisement, {
    now: start,
    ttlMs: 60_000,
  });
  const presentation = createAuthenticationPresentation(
    advertisement,
    initiation,
    presenter,
    { now: start, ttlMs: 60_000 },
  );
  return { presenter, advertisement, initiation, presentation };
}

test("verifies proof against locally supplied trust material", () => {
  const value = fixture();
  const report = verifyAuthenticationPresentation(
    value.advertisement,
    value.initiation,
    value.presentation,
    {
      trustedKeys: { [value.presenter.keyId]: value.presenter.publicKey },
      now: verifyAt,
    },
  );

  assert.equal(report.overall, "verified");
  assert.equal(report.proofOfPossession.status, "verified");
  assert.equal(report.trustBinding.status, "verified");
  assert.equal(report.physicalBinding.status, "endpoint-only");
});

test("keeps a valid self-presented key unresolved when trust material is absent", () => {
  const value = fixture();
  const report = verifyAuthenticationPresentation(
    value.advertisement,
    value.initiation,
    value.presentation,
    { now: verifyAt },
  );

  assert.equal(report.overall, "unresolved");
  assert.deepEqual(report.reasonCodes, ["TRUST_BINDING_UNRESOLVED"]);
});

test("rejects a modified signed presentation", () => {
  const value = fixture();
  const tampered: AuthenticationPresentation = {
    ...value.presentation,
    presenterNonce: "attacker-controlled-value",
  };
  const report = verifyAuthenticationPresentation(
    value.advertisement,
    value.initiation,
    tampered,
    {
      trustedKeys: { [value.presenter.keyId]: value.presenter.publicKey },
      now: verifyAt,
    },
  );

  assert.equal(report.overall, "failed");
  assert.deepEqual(report.reasonCodes, ["INVALID_TRANSCRIPT_PROOF"]);
});

test("rejects an expired session", () => {
  const value = fixture();
  const report = verifyAuthenticationPresentation(
    value.advertisement,
    value.initiation,
    value.presentation,
    {
      trustedKeys: { [value.presenter.keyId]: value.presenter.publicKey },
      now: new Date("2026-08-08T00:02:00.000Z"),
    },
  );

  assert.equal(report.overall, "failed");
  assert.deepEqual(report.reasonCodes, ["STALE_SESSION"]);
});

test("rejects reuse through the replay guard", () => {
  const value = fixture();
  const replayGuard = new InMemoryReplayGuard();
  const options = {
    trustedKeys: { [value.presenter.keyId]: value.presenter.publicKey },
    replayGuard,
    now: verifyAt,
  };

  const first = verifyAuthenticationPresentation(
    value.advertisement,
    value.initiation,
    value.presentation,
    options,
  );
  const second = verifyAuthenticationPresentation(
    value.advertisement,
    value.initiation,
    value.presentation,
    options,
  );

  assert.equal(first.overall, "verified");
  assert.equal(second.overall, "failed");
  assert.deepEqual(second.reasonCodes, ["REPLAY_DETECTED"]);
});

test("rejects a locally trusted key binding that does not match", () => {
  const value = fixture();
  const other = generateIdentityKeyPair();
  const report = verifyAuthenticationPresentation(
    value.advertisement,
    value.initiation,
    value.presentation,
    {
      trustedKeys: { [value.presenter.keyId]: other.publicKey },
      now: verifyAt,
    },
  );

  assert.equal(report.overall, "failed");
  assert.deepEqual(report.reasonCodes, ["TRUST_KEY_MISMATCH"]);
});
