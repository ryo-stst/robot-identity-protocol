// SPDX-License-Identifier: Apache-2.0
import type { EdhocCryptoManager } from "edhoc";
import {
  AuthenticationSession, DomainExtensionSession, generateIdentityKeyPair,
  pinnedCredentials, issueStatement, type DomainValidator,
} from "./index.js";

/** Synthetic peers in one trusted process; no external robot inputs. */
export async function runDomainDemo(options: { crypto?: EdhocCryptoManager } = {}) {
  // These example namespaces are identifiers, not URLs to fetch or mandatory RIP vocabularies.
  const CARGO = "https://example.com/delivery/cargo/v1";
  const INSPECTION = "https://example.com/inspection/tool/v1";
  const delivery = generateIdentityKeyPair(), inspection = generateIdentityKeyPair();
  const cargoIssuer = generateIdentityKeyPair(), toolIssuer = generateIdentityKeyPair();
  // Synthetic, independently installed local trust. Discovery does not create trust.
  const resolvePeer = pinnedCredentials([delivery, inspection].map(key => ({ subject: key.keyId, publicKey: key.publicKey })));
  const adapter = options.crypto ? { crypto: options.crypto } : {};
  const a = new AuthenticationSession({ role: "initiator", identity: delivery, resolvePeer, ...adapter });
  const b = new AuthenticationSession({ role: "responder", identity: inspection, resolvePeer, ...adapter });
  await b.receive(await a.start());
  await a.receive(await b.respond());
  await b.receive(await a.respond());
  const authentication = { delivery: a.report(), inspection: b.report() };

  const now = Date.now();
  const cargo = await issueStatement(cargoIssuer, {
    schema: CARGO, subject: delivery.keyId, issuedAt: now, expiresAt: now + 60_000,
    content: { nominalPayloadKg: 12 },
  });
  const tool = await issueStatement(toolIssuer, {
    schema: INSPECTION, subject: inspection.keyId, issuedAt: now, expiresAt: now + 60_000,
    content: { toolClass: "visual-inspection", calibratedUntil: now + 60_000 },
  });
  const cargoValidator: DomainValidator = {
    schema: CARGO,
    validate: statement => Object.keys(statement.content).join() === "nominalPayloadKg"
      && typeof statement.content.nominalPayloadKg === "number"
      && Number.isFinite(statement.content.nominalPayloadKg) && statement.content.nominalPayloadKg >= 0,
  };
  const toolValidator: DomainValidator = {
    schema: INSPECTION,
    validate: (statement, context) => Object.keys(statement.content).sort().join() === "calibratedUntil,toolClass"
      && statement.content.toolClass === "visual-inspection"
      && Number.isSafeInteger(statement.content.calibratedUntil)
      && (statement.content.calibratedUntil as number) > context.now,
  };
  const deliveryExtensions = new DomainExtensionSession({
    mode: "local-test-only", session: a,
    providers: [{ schema: CARGO, provide: async () => cargo }], validators: [cargoValidator],
    issuers: [{ keyId: cargoIssuer.keyId, publicKey: cargoIssuer.publicKey, schemas: [CARGO] }],
  });
  const inspectionExtensions = new DomainExtensionSession({
    mode: "local-test-only", session: b,
    providers: [{ schema: INSPECTION, provide: async () => tool }], validators: [toolValidator],
    issuers: [{ keyId: toolIssuer.keyId, publicKey: toolIssuer.publicKey, schemas: [INSPECTION] }],
  });

  // Copy complete byte frames only inside this trusted local process. There is no encrypted app transport.
  const deliveryAsksForCargo = await deliveryExtensions.verify(
    await inspectionExtensions.respond(deliveryExtensions.request([CARGO])),
  );
  const inspectionAsksForTool = await inspectionExtensions.verify(
    await deliveryExtensions.respond(inspectionExtensions.request([INSPECTION])),
  );

  // A developer explicitly installs the other domain's validator AND independently trusted issuer.
  // Same completed authentication; no core edit, schema guessing, network fetch or automatic trust.
  const deliveryWithToolSupport = new DomainExtensionSession({
    mode: "local-test-only", session: a, validators: [toolValidator],
    issuers: [{ keyId: toolIssuer.keyId, publicKey: toolIssuer.publicKey, schemas: [INSPECTION] }],
  });
  const knownTool = await deliveryWithToolSupport.verify(
    await inspectionExtensions.respond(deliveryWithToolSupport.request([INSPECTION])),
  );

  return {
    sdkVersion: "0.2.0-alpha.2",
    environment: "synthetic peers, trusted local process, no radio or encrypted application channel",
    authentication,
    differentDomains: {
      deliveryAsksForCargo: deliveryAsksForCargo.items,
      inspectionAsksForTool: inspectionAsksForTool.items,
    },
    explicitDomainSupport: knownTool,
    privacy: { permanentAssetIdSent: false, reusedCredentialRemainsLinkable: true, unlinkabilityDemonstrated: false },
    operationDecision: "outside-protocol",
  };
}
