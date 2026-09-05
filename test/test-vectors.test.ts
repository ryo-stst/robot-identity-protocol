/*
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE in the project root for license information.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  verifyAuthenticationPresentation,
  type AuthenticationInitiation,
  type AuthenticationPresentation,
  type DiscoveryAdvertisement,
  type TrustedKeySet,
} from "../src/legacy.js";

type SuccessVector = {
  verificationTime: string;
  advertisement: DiscoveryAdvertisement;
  initiation: AuthenticationInitiation;
  presentation: AuthenticationPresentation;
  trustedKeys: TrustedKeySet;
  expected: {
    overall: "verified";
    peerKeyId: string;
    transcriptHash: string;
  };
};

const vectorPath = new URL("../../test-vectors/one-way-success.json", import.meta.url);
const vector = JSON.parse(readFileSync(vectorPath, "utf8")) as SuccessVector;

test("matches the fixed one-way success vector", () => {
  const report = verifyAuthenticationPresentation(
    vector.advertisement,
    vector.initiation,
    vector.presentation,
    { trustedKeys: vector.trustedKeys, now: new Date(vector.verificationTime) },
  );

  assert.equal(report.overall, vector.expected.overall);
  assert.equal(report.peerKeyId, vector.expected.peerKeyId);
  assert.equal(report.transcriptHash, vector.expected.transcriptHash);
});

test("rejects a modified fixed-vector presentation", () => {
  const report = verifyAuthenticationPresentation(
    vector.advertisement,
    vector.initiation,
    { ...vector.presentation, presenterNonce: "tampered" },
    { trustedKeys: vector.trustedKeys, now: new Date(vector.verificationTime) },
  );

  assert.equal(report.overall, "failed");
  assert.deepEqual(report.reasonCodes, ["INVALID_TRANSCRIPT_PROOF"]);
});
