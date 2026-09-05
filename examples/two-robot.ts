/*
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE in the project root for license information.
 */

import {
  InMemoryReplayGuard,
  createAuthenticationInitiation,
  createAuthenticationPresentation,
  createDiscoveryAdvertisement,
  generateIdentityKeyPair,
  verifyAuthenticationPresentation,
} from "../src/legacy.js";

const warehouseVerifier = generateIdentityKeyPair();
const deliveryRobot = generateIdentityKeyPair();

// A future bearer adapter may carry the same objects over BLE or another link.
const advertisement = createDiscoveryAdvertisement({ profiles: ["in-memory-1"] });
const initiation = createAuthenticationInitiation(advertisement);
const presentation = createAuthenticationPresentation(
  advertisement,
  initiation,
  deliveryRobot,
);

const localTrustMaterial = {
  [deliveryRobot.keyId]: deliveryRobot.publicKey,
};

const report = verifyAuthenticationPresentation(
  advertisement,
  initiation,
  presentation,
  {
    trustedKeys: localTrustMaterial,
    replayGuard: new InMemoryReplayGuard(),
  },
);

console.log(JSON.stringify({
  verifierKeyId: warehouseVerifier.keyId,
  peerKeyId: report.peerKeyId,
  authentication: report.overall,
  physicalBinding: report.physicalBinding.status,
  authorizationDecision: "outside-this-protocol",
}, null, 2));
