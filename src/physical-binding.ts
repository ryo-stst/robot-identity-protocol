/*
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE in the project root for license information.
 */

import { randomBase64Url, sameJson, sha256Base64Url } from "./encoding.js";
import type {
  AttributeEnvelope,
  AuthenticationInitiation,
  AuthenticationPresentation,
  VerificationReport,
  VerificationStatus,
} from "./model.js";

export const PHYSICAL_BINDING_PROFILE_ID = "org.robot-identity.physical-binding" as const;
export const PHYSICAL_BINDING_PROFILE_VERSION = "0.1" as const;
export const PHYSICAL_BINDING_RESPONSE_SCHEMA =
  "https://robotidentity.dev/schema/physical-binding-response/v0.1" as const;

export type PhysicalBindingMethod =
  | "optical-challenge"
  | "secure-range"
  | "direction"
  | "acoustic-challenge"
  | "multi-modal";

export interface PhysicalBindingRequest {
  profile: typeof PHYSICAL_BINDING_PROFILE_ID;
  version: typeof PHYSICAL_BINDING_PROFILE_VERSION;
  method: PhysicalBindingMethod;
  challengeNonce: string;
  issuedAt: string;
  expiresAt: string;
}

export interface PhysicalBindingObservation {
  sessionId: string;
  localTrackId: string;
  method: PhysicalBindingMethod;
  challengeHash: string;
  observedAt: string;
  sensorReference: string;
  confidence?: number;
  simulated?: boolean;
}

export interface PhysicalBindingProfileReport {
  profile: typeof PHYSICAL_BINDING_PROFILE_ID;
  version: typeof PHYSICAL_BINDING_PROFILE_VERSION;
  status: VerificationStatus | "not-run";
  method: PhysicalBindingMethod;
  localTrackId: string | null;
  challengeHash: string;
  observationMatched: boolean;
  simulated: boolean;
  detail: string;
}

function addMilliseconds(now: Date, milliseconds: number): string {
  return new Date(now.getTime() + milliseconds).toISOString();
}

export function createPhysicalBindingRequest(options: {
  method: PhysicalBindingMethod;
  now?: Date;
  ttlMs?: number;
}): PhysicalBindingRequest {
  const now = options.now ?? new Date();
  return {
    profile: PHYSICAL_BINDING_PROFILE_ID,
    version: PHYSICAL_BINDING_PROFILE_VERSION,
    method: options.method,
    challengeNonce: randomBase64Url(24),
    issuedAt: now.toISOString(),
    expiresAt: addMilliseconds(now, options.ttlMs ?? 30_000),
  };
}

export function physicalBindingChallengeHash(
  initiation: AuthenticationInitiation,
  request: PhysicalBindingRequest,
): string {
  return sha256Base64Url({
    profile: request.profile,
    version: request.version,
    method: request.method,
    challengeNonce: request.challengeNonce,
    sessionId: initiation.sessionId,
    verifierNonce: initiation.verifierNonce,
  });
}

export function createPhysicalBindingResponseAttribute(
  initiation: AuthenticationInitiation,
  request: PhysicalBindingRequest,
  options: { subject: string; issuer: string; now?: Date },
): AttributeEnvelope {
  const now = options.now ?? new Date();
  return {
    schema: PHYSICAL_BINDING_RESPONSE_SCHEMA,
    subject: options.subject,
    issuer: options.issuer,
    issuedAt: now.toISOString(),
    expiresAt: request.expiresAt,
    content: {
      profile: request.profile,
      version: request.version,
      method: request.method,
      challengeHash: physicalBindingChallengeHash(initiation, request),
    },
    proof: {},
  };
}

export function verifyPhysicalBindingObservation(
  initiation: AuthenticationInitiation,
  presentation: AuthenticationPresentation,
  coreReport: VerificationReport,
  observation: PhysicalBindingObservation,
): PhysicalBindingProfileReport {
  const embedded = initiation.extensions[PHYSICAL_BINDING_PROFILE_ID];
  const request = embedded as PhysicalBindingRequest | undefined;
  const fallbackMethod = observation.method;
  const fallbackHash = observation.challengeHash;
  const failed = (detail: string): PhysicalBindingProfileReport => ({
    profile: PHYSICAL_BINDING_PROFILE_ID,
    version: PHYSICAL_BINDING_PROFILE_VERSION,
    status: "failed",
    method: request?.method ?? fallbackMethod,
    localTrackId: observation.localTrackId,
    challengeHash: request ? physicalBindingChallengeHash(initiation, request) : fallbackHash,
    observationMatched: false,
    simulated: observation.simulated === true,
    detail,
  });

  if (!request || request.profile !== PHYSICAL_BINDING_PROFILE_ID) {
    return failed("The initiation did not contain this physical-binding profile request.");
  }
  if (!sameJson(embedded, request)) {
    return failed("The embedded profile request could not be interpreted consistently.");
  }

  const challengeHash = physicalBindingChallengeHash(initiation, request);
  if (coreReport.overall !== "verified") {
    return {
      ...failed("A physical observation exists, but the RIP endpoint identity is not verified."),
      status: "unresolved",
    };
  }

  const response = presentation.attributes.find(
    (attribute) => attribute.schema === PHYSICAL_BINDING_RESPONSE_SCHEMA,
  );
  const content = response?.content;
  const responseMatches = response?.subject === presentation.presenterKeyId
    && content?.profile === request.profile
    && content?.version === request.version
    && content?.method === request.method
    && content?.challengeHash === challengeHash;
  const observationMatches = observation.sessionId === initiation.sessionId
    && observation.method === request.method
    && observation.challengeHash === challengeHash
    && Date.parse(request.issuedAt) <= Date.parse(observation.observedAt)
    && Date.parse(observation.observedAt) <= Date.parse(request.expiresAt);

  if (!responseMatches || !observationMatches) {
    return failed("The signed response and local physical observation did not match the session challenge.");
  }

  return {
    profile: PHYSICAL_BINDING_PROFILE_ID,
    version: PHYSICAL_BINDING_PROFILE_VERSION,
    status: "verified",
    method: request.method,
    localTrackId: observation.localTrackId,
    challengeHash,
    observationMatched: true,
    simulated: observation.simulated === true,
    detail: "The signed endpoint response and verifier-local observation matched this RIP session challenge.",
  };
}
