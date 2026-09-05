/*
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE in the project root for license information.
 */

import {
  createAuthenticationInitiation,
  createAuthenticationPresentation,
  createDiscoveryAdvertisement,
  generateIdentityKeyPair,
  verifyAuthenticationPresentation,
  type AttributeEnvelope,
} from "../src/legacy.js";

// This schema belongs to the adopting logistics domain, not to RIP core.
const capabilitySchema = "https://example.com/schemas/robot-handoff-capability/v1";
const now = new Date();
const presenter = generateIdentityKeyPair();
const advertisement = createDiscoveryAdvertisement({ now, ttlMs: 60_000 });
const initiation = createAuthenticationInitiation(advertisement, {
  requestedSchemas: [capabilitySchema],
  now,
  ttlMs: 60_000,
});
const capability: AttributeEnvelope = {
  schema: capabilitySchema,
  subject: presenter.keyId,
  issuer: "urn:example:logistics-operator",
  issuedAt: now.toISOString(),
  expiresAt: new Date(now.getTime() + 300_000).toISOString(),
  content: {
    nominalPayloadKg: 80,
    cargoBay: "temperature-controlled",
  },
  proof: {},
};
const presentation = createAuthenticationPresentation(
  advertisement,
  initiation,
  presenter,
  { attributes: [capability], now, ttlMs: 60_000 },
);
const report = verifyAuthenticationPresentation(advertisement, initiation, presentation, {
  trustedKeys: { [presenter.keyId]: presenter.publicKey },
  now: new Date(now.getTime() + 500),
});

console.log(JSON.stringify({
  coreAuthentication: report.overall,
  domainAttribute: {
    schema: capability.schema,
    content: capability.content,
    issuerProof: report.attributes[0]?.status,
  },
  applicationDecision: "outside-rip",
}, null, 2));
