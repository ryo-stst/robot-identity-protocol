/*
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE in the project root for license information.
 */

import {
  InMemoryReplayGuard,
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

const now = new Date();

// Discovery sees three independent communication endpoints. It does not verify them.
const candidates = ["Presenter B1", "Presenter B2", "Presenter B3"].map((label, index) => ({
  label,
  localTrackId: `camera-track-${String(index + 1).padStart(2, "0")}`,
  identity: generateIdentityKeyPair(),
  advertisement: createDiscoveryAdvertisement({ now, ttlMs: 60_000 }),
}));

// A local selection step chooses one candidate before authentication begins.
const selected = candidates[1]!;
const bindingRequest = createPhysicalBindingRequest({
  method: "optical-challenge",
  now,
  ttlMs: 60_000,
});
const initiation = createAuthenticationInitiation(selected.advertisement, {
  requestedSchemas: [PHYSICAL_BINDING_RESPONSE_SCHEMA],
  extensions: { [PHYSICAL_BINDING_PROFILE_ID]: bindingRequest },
  now,
  ttlMs: 60_000,
});
const bindingResponse = createPhysicalBindingResponseAttribute(initiation, bindingRequest, {
  subject: selected.identity.keyId,
  issuer: selected.identity.keyId,
  now,
});
const presentation = createAuthenticationPresentation(
  selected.advertisement,
  initiation,
  selected.identity,
  { attributes: [bindingResponse], now, ttlMs: 60_000 },
);
const coreReport = verifyAuthenticationPresentation(
  selected.advertisement,
  initiation,
  presentation,
  {
    trustedKeys: { [selected.identity.keyId]: selected.identity.publicKey },
    replayGuard: new InMemoryReplayGuard(),
    now: new Date(now.getTime() + 500),
  },
);

// This is verifier-local sensor evidence. The example deliberately simulates it.
const profileReport = verifyPhysicalBindingObservation(
  initiation,
  presentation,
  coreReport,
  {
    sessionId: initiation.sessionId,
    localTrackId: selected.localTrackId,
    method: "optical-challenge",
    challengeHash: physicalBindingChallengeHash(initiation, bindingRequest),
    observedAt: new Date(now.getTime() + 250).toISOString(),
    sensorReference: "simulated-camera-01",
    confidence: 0.99,
    simulated: true,
  },
);

console.log(JSON.stringify({
  candidatesObserved: candidates.length,
  selectedCandidate: selected.label,
  coreAuthentication: coreReport.overall,
  corePhysicalBinding: coreReport.physicalBinding.status,
  optionalPhysicalBinding: profileReport.status,
  verifierLocalTrackId: profileReport.localTrackId,
  productionBodyProof: false,
}, null, 2));
