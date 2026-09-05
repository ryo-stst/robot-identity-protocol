// SPDX-License-Identifier: Apache-2.0
// Demonstration fixture: all actors and issuers are ephemeral and controlled by this process.
import { randomBytes } from "node:crypto";
import type { EdhocCryptoManager } from "edhoc";
import { generateIdentityKeyPair } from "../crypto.js";
import { AuthenticationSession, BASELINE_PROFILE, correlateOpticalObservation, issuerCredentials, RipError } from "./edhoc.js";
import { IDENTITY_SCHEMA, issueStatement, verifyStatement, type StatementResult } from "./claims.js";

export type DemoScenario = "success" | "tamper" | "replay" | "unknown-issuer" | "expired";
export const PAYLOAD_SCHEMA = "https://example.com/robot/payload/v1";
export async function runBaselineDemo(options: {
  scenario?: DemoScenario; target?: number; multiple?: boolean; attribute?: boolean; optical?: boolean;
  /** Host-supplied adapter; does not change the fixed EDHOC method or cipher suite. */
  crypto?: EdhocCryptoManager;
} = {}) {
  const scenario = options.scenario ?? "success";
  const now = Date.now();
  let time = now;
  const issuer = generateIdentityKeyPair();
  const a = generateIdentityKeyPair();
  const candidates = Array.from({ length: options.multiple ? 3 : 1 }, () => generateIdentityKeyPair());
  const target = options.multiple && Number.isInteger(options.target) && options.target! >= 0 && options.target! < 3 ? options.target! : 0;
  const b = candidates[target]!;
  const label = `B${target + 1}`;
  const trust = { keyId: issuer.keyId, publicKey: issuer.publicKey, schemas: [IDENTITY_SCHEMA, PAYLOAD_SCHEMA] };
  const bundle = new Map<string, Uint8Array>();
  for (const peer of [a, ...candidates]) bundle.set(peer.keyId, await issueStatement(issuer, {
    schema: IDENTITY_SCHEMA, subject: peer.keyId, issuedAt: now, expiresAt: now + 300_000, content: { publicKey: peer.publicKey },
  }));
  const resolvePeer = issuerCredentials({ lookup: async id => bundle.get(id), issuers: scenario === "unknown-issuer" ? [] : [trust], now: () => time });
  const adapter = options.crypto ? { crypto: options.crypto } : {};
  const initiator = new AuthenticationSession({ role: "initiator", identity: a, resolvePeer, now: () => time, ...adapter });
  const responder = new AuthenticationSession({ role: "responder", identity: b, resolvePeer, now: () => time, ...adapter });
  const steps: Array<{ title: string; direction: string; result: string; explanation: string; core: Record<string, unknown>; extension: Record<string, unknown> | null }> = [{
    title: "Choose a candidate", direction: "Local discovery → A", result: "observed",
    explanation: "These are simulated discovery handles, not authenticated names or physical positions. Only the selected candidate receives this handshake.",
    core: { candidateCount: candidates.length, selectedLocalLabel: label, discovery: "simulated; not an EDHOC message" }, extension: null,
  }];
  let failure: string | null = null;
  let current: (typeof steps)[number] | undefined;
  const add = (title: string, direction: string, explanation: string, bytes: Uint8Array) => {
    current = { title, direction, result: "sent", explanation, core: { profile: BASELINE_PROFILE, bytes: bytes.length, wireHex: Buffer.from(bytes).toString("hex") }, extension: null };
    steps.push(current);
  };
  try {
    const m1 = await initiator.start();
    add("Start a fresh exchange", `A → ${label}`, "EDHOC message_1 proposes the fixed method and suite and sends a fresh ephemeral public key. No identity is verified yet.", m1);
    await responder.receive(m1); current!.result = "accepted; unauthenticated";
    const m2 = await responder.respond();
    if (scenario === "tamper") m2[m2.length - 1] = m2[m2.length - 1]! ^ 1;
    add("A authenticates its peer", `${label} → A`, "EDHOC message_2 proves the responder's key. A resolves its issuer-signed credential from an offline bundle.", m2);
    if (scenario === "expired") time += 60_000;
    await initiator.receive(m2); current!.result = "peer verified by A";
    if (scenario === "replay") {
      add("Reject a duplicate message", `${label} → A (duplicate)`, "The same message_2 cannot advance this session twice.", m2);
      await initiator.receive(m2);
    }
    const m3 = await initiator.respond();
    add("The peer authenticates A", `A → ${label}`, "EDHOC message_3 proves the initiator's key. The responder verifies A locally. No operation is authorized.", m3);
    await responder.receive(m3); current!.result = `A verified by ${label}`;
  } catch (error) {
    failure = error instanceof RipError ? error.code : "AUTHENTICATION_FAILED";
    if (current && !current.result.includes("verified") && !current.result.includes("accepted")) current.result = `rejected: ${failure}`;
    else steps.push({ title: "Exchange could not continue", direction: "Local processing", result: `rejected: ${failure}`,
      explanation: "The next message could not be prepared. Earlier verification results do not establish a completed exchange.", core: {}, extension: null });
  }
  const reports = failure ? null : { a: initiator.report(), b: responder.report() };
  let attribute: StatementResult | null = null;
  let optical: ReturnType<typeof correlateOpticalObservation> | null = null;
  if (reports && options.attribute) {
    const bytes = await issueStatement(issuer, { schema: PAYLOAD_SCHEMA, subject: reports.a.peerKeyId, issuedAt: now, expiresAt: now + 300_000, content: { nominalPayloadKg: 80 } });
    attribute = await verifyStatement(bytes, { schema: PAYLOAD_SCHEMA, subject: reports.a.peerKeyId, issuers: [trust], now });
    steps.push({ title: "Read an optional domain claim", direction: `${label} → A (separate signed object)`, result: attribute.status,
      explanation: "An example issuer states 80 kg. COSE signature, schema, subject and expiry are verified; this is not a live capacity measurement or confidential channel.",
      core: { authenticatedSubject: reports.a.peerKeyId }, extension: { encoding: "COSE_Sign1", statement: attribute.statement, checks: attribute, wireHex: Buffer.from(bytes).toString("hex") } });
  }
  if (reports && options.optical) {
    const challenge = randomBytes(32);
    const expected = await initiator.opticalResponse(challenge, b.keyId);
    const observed = await responder.opticalResponse(challenge, b.keyId);
    optical = correlateOpticalObservation(expected, observed, [`simulated-track-${target + 1}`]);
    steps.push({ title: "Correlate a simulated sensor track", direction: `${label} signal → A's simulated camera`, result: "simulated correlation",
      explanation: "Both peers derive a response from the shared session secret and a fresh challenge. Here the camera observation is simulated. Relaying the signal is still possible.",
      core: { exchangeId: reports.a.exchangeId }, extension: { ...optical, simulated: true, challengeHex: challenge.toString("hex"), matchedResponse: true } });
  }
  return {
    profile: BASELINE_PROFILE, sdkVersion: "0.2.0-alpha.1", scenario, target, label,
    environment: "single-process simulation; real cryptography; no radio or physical proof",
    status: reports ? "verified" : "rejected", failure, reports, attribute, optical, steps,
    candidates: candidates.map((peer, index) => ({ label: `B${index + 1}`, selected: target === index, identity: reports && index === target ? "verified" : "not-verified", keyId: reports && index === target ? peer.keyId : null })),
  };
}
