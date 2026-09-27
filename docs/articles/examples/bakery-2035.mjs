// SPDX-License-Identifier: Apache-2.0
// Fictional article fixture: local process, synthetic identities, no robot control.
// Run `npm run build`, then `node docs/articles/examples/bakery-2035.mjs`.
import assert from "node:assert/strict";
import {
  AuthenticationSession, generateIdentityKeyPair, issueStatement,
  issuerCredentials, verifyStatement, IDENTITY_SCHEMA,
} from "../../../dist/src/index.js";

const now = Date.now();
const cargoSchema = "https://example.com/bakery/cargo-capability/v1";
const identityIssuer = generateIdentityKeyPair();
const inspectionIssuer = generateIdentityKeyPair();
const bakery = generateIdentityKeyPair();
const robots = [1, 2, 3].map(() => generateIdentityKeyPair());

// Trusted fixture bootstrap, NOT trust acquired from an untrusted advertisement.
const credentials = new Map();
for (const peer of [bakery, ...robots]) {
  credentials.set(peer.keyId, await issueStatement(identityIssuer, {
    schema: IDENTITY_SCHEMA, subject: peer.keyId,
    issuedAt: now, expiresAt: now + 300_000,
    content: { publicKey: peer.publicKey },
  }));
}
const resolvePeer = issuerCredentials({
  lookup: async id => credentials.get(id),
  issuers: [{ keyId: identityIssuer.keyId, publicKey: identityIssuer.publicKey, schemas: [IDENTITY_SCHEMA] }],
  now: () => now,
});
const claimTrust = [{ keyId: inspectionIssuer.keyId, publicKey: inspectionIssuer.publicKey, schemas: [cargoSchema] }];
const cargoContent = { nominalPayloadKg: 12, cargoBayVolumeL: 42, compartmentClass: "dry-food" };
const b3Claim = await issueStatement(inspectionIssuer, {
  schema: cargoSchema, subject: robots[2].keyId,
  issuedAt: now, expiresAt: now + 300_000, content: cargoContent,
});

async function authenticate(robot) {
  // Robot is the initiator here. This role choice does not guarantee anonymity.
  const initiator = new AuthenticationSession({ role: "initiator", identity: robot, resolvePeer });
  const responder = new AuthenticationSession({ role: "responder", identity: bakery, resolvePeer });
  await responder.receive(await initiator.start());
  await initiator.receive(await responder.respond());
  await responder.receive(await initiator.respond());
  return { robot: initiator.report(), bakery: responder.report() };
}

const rows = [];
let firstB3Report;
for (const [index, robot] of robots.entries()) {
  // Three independent sessions, not a single broadcast/multi-party handshake.
  const reports = await authenticate(robot);
  const subject = reports.bakery.peerKeyId;
  assert.equal(subject, robot.keyId);
  assert.equal(reports.bakery.identity, "verified");
  assert.equal(reports.robot.identity, "verified");
  // B1 supplies nothing. B2 copies B3's unmodified signed claim. B3 supplies its own.
  const claim = index === 0 ? null : await verifyStatement(b3Claim, { subject, schema: cargoSchema, issuers: claimTrust, now });
  rows.push({
    candidate: `B${index + 1}`, identity: reports.bakery.identity,
    cargoClaim: claim?.status ?? "not-provided", reason: claim?.reason ?? "NO_STATEMENT",
    content: claim?.status === "verified" ? claim.statement.content : null,
    physicalBinding: reports.bakery.physicalBinding,
    handoffDecision: "outside-this-example",
  });
  if (index === 2) firstB3Report = reports.bakery;
}
assert.deepEqual(rows.map(row => row.cargoClaim), ["not-provided", "failed", "verified"]);
assert.equal(rows[1].reason, "CLAIM_BINDING_MISMATCH");

// Publication promises are tested: expiry, issuer scope, and repeat-visit linkability.
const options = { subject: robots[2].keyId, schema: cargoSchema, issuers: claimTrust, now };
assert.equal((await verifyStatement(b3Claim, { ...options, now: now + 300_000 })).status, "failed");
assert.equal((await verifyStatement(b3Claim, { ...options, issuers: [] })).status, "unresolved");
assert.equal((await verifyStatement(b3Claim, {
  ...options, issuers: [{ ...claimTrust[0], schemas: [IDENTITY_SCHEMA] }],
})).status, "unresolved");
const secondB3Report = (await authenticate(robots[2])).bakery;
assert.equal(firstB3Report.peerKeyId, secondB3Report.peerKeyId);
assert.notEqual(firstB3Report.exchangeId, secondB3Report.exchangeId);

// A local active-probing check, against a synthetic responder only. The requester
// learns the responder's credential ID before proving its own identity in m3.
let probedIdentifier;
const probe = new AuthenticationSession({
  role: "initiator", identity: generateIdentityKeyPair(),
  resolvePeer: async id => { probedIdentifier = id; throw new Error("STOP_LOCAL_PRIVACY_PROBE"); },
});
const probeTarget = new AuthenticationSession({ role: "responder", identity: robots[2], resolvePeer });
await probeTarget.receive(await probe.start());
await assert.rejects(probe.receive(await probeTarget.respond()));
assert.equal(probedIdentifier, robots[2].keyId);
assert.equal(probeTarget.state, "wait-3");

// Generic signature validation does not establish that a domain value is sensible.
const nonsense = await issueStatement(inspectionIssuer, {
  schema: cargoSchema, subject: robots[2].keyId,
  issuedAt: now, expiresAt: now + 300_000, content: { nominalPayloadKg: -12 },
});
assert.equal((await verifyStatement(nonsense, options)).status, "verified");
const privacy = {
  permanentSerialRequired: false, sameKeyLinksRepeatVisits: true,
  unauthenticatedInitiatorCanObserveResponderKeyId: true, unlinkabilityDemonstrated: false,
};
console.log(JSON.stringify({
  environment: "fictional bakery / local process / synthetic issuer trust / real cryptography",
  cases: rows, privacy,
  extraChecks: ["expired claim rejected", "unknown issuer unresolved", "wrong issuer scope unresolved", "fresh sessions still share a reused key ID", "active requester observes responder ID before completing authentication", "signed nonsense requires a domain validator"],
  limits: ["no radio or physical-body proof", "no order allocation or handoff control", "signed claims are not encrypted", "no pseudonym lifecycle or selective-disclosure implementation"],
}, null, 2));
