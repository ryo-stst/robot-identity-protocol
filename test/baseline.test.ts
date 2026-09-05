// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import test from "node:test";
import { randomBytes, createPublicKey, verify } from "node:crypto";
import cbor from "cbor";
import { DefaultEdhocCryptoManager } from "edhoc";
import { readFileSync } from "node:fs";
import { AuthenticationSession, pinnedCredentials, generateIdentityKeyPair, issueStatement, verifyStatement, verifyStatusSnapshot, STATUS_SCHEMA, correlateOpticalObservation } from "../src/baseline/index.js";
import { runBaselineDemo } from "../src/baseline/demo.js";

test("generated identities use the same minimal JWK profile in every runtime", () => {
  assert.deepEqual(Object.keys(generateIdentityKeyPair().publicKey).sort(), ["crv", "kty", "x"]);
});

test("demo attributes a message preparation failure to a separate step", async () => {
  class UnavailableCipher extends DefaultEdhocCryptoManager {
    override async encrypt(): Promise<Buffer> { throw new Error("unavailable cipher"); }
  }
  const result = await runBaselineDemo({ crypto: new UnavailableCipher() });
  assert.equal(result.status, "rejected");
  assert.equal(result.steps[2]!.result, "peer verified by A");
  assert.equal(result.steps.at(-1)!.title, "Exchange could not continue");
});

test("machine-readable conformance scenario catalog", async () => {
  const catalog = JSON.parse(readFileSync(new URL("../../test-vectors/baseline-cases.json", import.meta.url), "utf8"));
  for (const entry of catalog.cases) {
    const result = await runBaselineDemo({ scenario: entry.scenario });
    assert.equal(result.status, entry.status, entry.scenario);
    assert.equal(result.failure, entry.failure, entry.scenario);
  }
});

function pair() {
  const a = generateIdentityKeyPair(), b = generateIdentityKeyPair();
  const resolvePeer = pinnedCredentials([a, b].map(x => ({ subject: x.keyId, publicKey: x.publicKey })));
  return { a, b, i: new AuthenticationSession({ role: "initiator", identity: a, resolvePeer }), r: new AuthenticationSession({ role: "responder", identity: b, resolvePeer }) };
}
async function exchange(p = pair()) {
  const m1 = await p.i.start(); await p.r.receive(m1);
  const m2 = await p.r.respond(); await p.i.receive(m2);
  const m3 = await p.i.respond(); await p.r.receive(m3);
  return { ...p, m1, m2, m3 };
}
test("EDHOC baseline performs local mutual authentication and keeps all evidence separate", async () => {
  const result = await runBaselineDemo({ multiple: true, target: 2, attribute: true, optical: true });
  assert.equal(result.status, "verified");
  assert.equal(result.reports!.a.exchangeId, result.reports!.b.exchangeId);
  assert.notEqual(result.reports!.a.peerKeyId, result.reports!.b.peerKeyId);
  assert.equal(result.attribute!.status, "verified");
  assert.equal(result.attribute!.statement!.content.nominalPayloadKg, 80);
  assert.equal(result.candidates[0]!.identity, "not-verified");
  assert.equal(result.candidates[2]!.identity, "verified");
  assert.equal(result.optical!.physicalIdentityProven, false);
  assert.equal(result.reports!.a.peerAcceptanceConfirmed, false);
  assert.doesNotMatch(JSON.stringify(result), /masterSecret|privateKey|prkExporter/);
});
for (const scenario of ["tamper", "replay", "unknown-issuer", "expired"] as const) test(`negative scenario: ${scenario}`, async () => {
  const result = await runBaselineDemo({ scenario });
  assert.equal(result.status, "rejected"); assert.equal(result.reports, null);
});
test("wire frames are CBOR, fixed method/suite; reject unsupported method and unbounded frames", async () => {
  const p = pair(); const m1 = await p.i.start();
  const fields = cbor.decodeAllSync(m1); assert.deepEqual(fields.slice(0, 2), [0, 0]);
  fields[0] = 3;
  await assert.rejects(p.r.receive(Buffer.concat(fields.map(x => cbor.encode(x)))), /UNSUPPORTED_PROFILE/);
  await assert.rejects(pair().r.receive(new Uint8Array(4097)), /FRAME_SIZE/);
  await assert.rejects(pair().r.receive(Buffer.from("9fffff", "hex")), /AUTHENTICATION_FAILED/);
});
test("sessions reject out-of-order, repeated and cross-session message_2", async () => {
  const p = await exchange();
  await assert.rejects(p.i.receive(p.m2), /UNEXPECTED_MESSAGE_OR_REPLAY/);
  await assert.rejects(pair().r.respond(), /UNEXPECTED_MESSAGE_OR_REPLAY/);
  const other = pair(); await other.i.start();
  await assert.rejects(other.i.receive(p.m2));
});
test("optical response is session-secret bound and cannot label multiple tracks as a unique body", async () => {
  const p = await exchange(), q = await exchange(); const challenge = randomBytes(32);
  const x = await p.i.opticalResponse(challenge, p.b.keyId), y = await p.r.opticalResponse(challenge, p.b.keyId);
  assert.deepEqual(x, y);
  assert.notDeepEqual(x, await q.i.opticalResponse(challenge, p.b.keyId));
  assert.notDeepEqual(x, await p.i.opticalResponse(challenge, p.a.keyId));
  assert.equal(correlateOpticalObservation(x, y, ["1", "2"]).status, "ambiguous");
  assert.equal(correlateOpticalObservation(x, randomBytes(32), ["1"]).status, "mismatch");
  await assert.rejects(pair().i.opticalResponse(challenge, p.b.keyId), /SESSION_INCOMPLETE/);
});
test("COSE uses a standard Sig_structure independently checked with Node crypto", async () => {
  const issuer = generateIdentityKeyPair();
  const bytes = await issueStatement(issuer, { schema: "https://example.com/schema", subject: "test-subject", issuedAt: 1000, expiresAt: 3000, content: { custom: "domain-owned" } });
  const tagged = cbor.decodeFirstSync(bytes); assert.equal(tagged.tag, 18);
  const [protectedBytes, , payload, signature] = tagged.value;
  const sigStructure = cbor.encode(["Signature1", protectedBytes, Buffer.alloc(0), payload]);
  assert.equal(verify(null, sigStructure, createPublicKey({ key: issuer.publicKey, format: "jwk" }), signature), true);
  const options = { subject: "test-subject", schema: "https://example.com/schema", issuers: [{ keyId: issuer.keyId, publicKey: issuer.publicKey, schemas: ["https://example.com/schema"] }], now: 2000 };
  assert.equal((await verifyStatement(bytes, options)).status, "verified");
  assert.equal((await verifyStatement(bytes, { ...options, now: 3000 })).status, "failed");
  assert.equal((await verifyStatement(bytes, { ...options, subject: "different-robot" })).status, "failed");
  assert.equal((await verifyStatement(bytes, { ...options, schema: "https://example.com/another-schema" })).status, "unresolved");
  const changed = Buffer.from(bytes); changed[changed.length - 1] = changed[changed.length - 1]! ^ 1;
  assert.equal((await verifyStatement(changed, options)).status, "failed");
  assert.equal((await verifyStatement(Buffer.concat([bytes, Buffer.from([0])]), options)).status, "failed");
});
test("offline status never reports stale or missing knowledge as good", async () => {
  const key = generateIdentityKeyPair();
  const issuer = { keyId: key.keyId, publicKey: key.publicKey, schemas: [STATUS_SCHEMA] };
  const bytes = await issueStatement(key, { schema: STATUS_SCHEMA, subject: "credential-01", issuedAt: 1000, expiresAt: 4000, content: { status: "good" } });
  assert.equal((await verifyStatusSnapshot(bytes, { credentialId: "credential-01", issuer, now: 2000, maxAgeMs: 2000 })).status, "good");
  assert.equal((await verifyStatusSnapshot(bytes, { credentialId: "credential-01", issuer, now: 3000, maxAgeMs: 2000 })).status, "unknown");
  assert.equal((await verifyStatusSnapshot(bytes, { credentialId: "another", issuer, now: 2000, maxAgeMs: 2000 })).status, "unknown");
});
