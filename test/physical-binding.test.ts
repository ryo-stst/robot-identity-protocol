/*
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE in the project root for license information.
 */

import assert from "node:assert/strict";
import test from "node:test";
import {
  PHYSICAL_BINDING_PROFILE_ID,
  PHYSICAL_BINDING_RESPONSE_SCHEMA,
  createAuthenticationInitiation,
  createAuthenticationPresentation,
  createDiscoveryAdvertisement,
  createPhysicalBindingRequest,
  createPhysicalBindingResponseAttribute,
  generateIdentityKeyPair,
  physicalBindingChallengeHash,
  verifyAuthenticationPresentation,
  verifyPhysicalBindingObservation,
} from "../src/legacy.js";

const now = new Date("2026-08-23T00:00:00.000Z");

function fixture() {
  const presenter = generateIdentityKeyPair();
  const advertisement = createDiscoveryAdvertisement({ now, ttlMs: 60_000 });
  const request = createPhysicalBindingRequest({ method: "optical-challenge", now });
  const initiation = createAuthenticationInitiation(advertisement, {
    requestedSchemas: [PHYSICAL_BINDING_RESPONSE_SCHEMA],
    extensions: { [PHYSICAL_BINDING_PROFILE_ID]: request },
    now,
    ttlMs: 60_000,
  });
  const response = createPhysicalBindingResponseAttribute(initiation, request, {
    subject: presenter.keyId,
    issuer: presenter.keyId,
    now,
  });
  const presentation = createAuthenticationPresentation(advertisement, initiation, presenter, {
    attributes: [response],
    now,
    ttlMs: 60_000,
  });
  const report = verifyAuthenticationPresentation(advertisement, initiation, presentation, {
    trustedKeys: { [presenter.keyId]: presenter.publicKey },
    now: new Date(now.getTime() + 500),
  });
  return { presenter, advertisement, request, initiation, presentation, report };
}

test("binds a verifier-local optical observation to a verified RIP session", () => {
  const value = fixture();
  const result = verifyPhysicalBindingObservation(
    value.initiation,
    value.presentation,
    value.report,
    {
      sessionId: value.initiation.sessionId,
      localTrackId: "camera-track-02",
      method: "optical-challenge",
      challengeHash: physicalBindingChallengeHash(value.initiation, value.request),
      observedAt: new Date(now.getTime() + 250).toISOString(),
      sensorReference: "camera-01",
      confidence: 0.99,
    },
  );

  assert.equal(result.status, "verified");
  assert.equal(result.localTrackId, "camera-track-02");
  assert.equal(result.observationMatched, true);
});

test("rejects a local observation that does not match the signed challenge", () => {
  const value = fixture();
  const result = verifyPhysicalBindingObservation(
    value.initiation,
    value.presentation,
    value.report,
    {
      sessionId: value.initiation.sessionId,
      localTrackId: "camera-track-03",
      method: "optical-challenge",
      challengeHash: "wrong-challenge",
      observedAt: new Date(now.getTime() + 250).toISOString(),
      sensorReference: "camera-01",
    },
  );

  assert.equal(result.status, "failed");
  assert.equal(result.observationMatched, false);
});
