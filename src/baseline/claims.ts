// SPDX-License-Identifier: Apache-2.0
import { randomUUID } from "node:crypto";
import { Sign1, Algorithms, Headers } from "@auth0/cose";
import cbor from "cbor";
import { type IdentityKeyPair, keyIdFor } from "../crypto.js";
import type { PublicKeyJwk } from "../model.js";

export const IDENTITY_SCHEMA = "urn:rip:identity:0.2";
export const STATUS_SCHEMA = "urn:rip:credential-status:0.2";
export const MAX_STATEMENT_BYTES = 16_384;
export type ClaimStatus = "verified" | "failed" | "unresolved";
export interface Statement {
  id: string;
  schema: string;
  subject: string;
  issuer: string;
  issuedAt: number;
  expiresAt: number;
  content: Record<string, unknown>;
}
export interface IssuerTrust {
  keyId: string;
  publicKey: PublicKeyJwk;
  /** Exact schema names; trusting an identity issuer does not trust its payload claims. */
  schemas: readonly string[];
}
export interface StatementResult {
  status: ClaimStatus;
  reason: string;
  statement?: Statement;
  /** Signature/issuer/subject validation is not a physical measurement or live status check. */
  revocation: "not-checked";
}

function checkShape(value: unknown): asserts value is Statement {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("MALFORMED_STATEMENT");
  const v = value as Statement;
  if ([v.id, v.schema, v.subject, v.issuer].some(x => typeof x !== "string" || !x.length || x.length > 512)
    || !Number.isSafeInteger(v.issuedAt) || !Number.isSafeInteger(v.expiresAt)
    || v.issuedAt >= v.expiresAt || !v.content || typeof v.content !== "object" || Array.isArray(v.content)
    || Object.keys(v).sort().join() !== "content,expiresAt,id,issuedAt,issuer,schema,subject") {
    throw new Error("MALFORMED_STATEMENT");
  }
}

/** CBOR payload in standard tagged COSE_Sign1. The payload is signed as bytes, never reserialized for verification. */
export async function issueStatement(
  issuer: IdentityKeyPair,
  input: Omit<Statement, "id" | "issuer"> & { id?: string },
): Promise<Uint8Array> {
  const statement: Statement = { ...input, id: input.id ?? randomUUID(), issuer: issuer.keyId };
  checkShape(statement);
  const payload = cbor.encodeCanonical(statement);
  if (payload.length > MAX_STATEMENT_BYTES - 256) throw new Error("STATEMENT_TOO_LARGE");
  const signingKey = await globalThis.crypto.subtle.importKey("jwk", issuer.privateKey.export({ format: "jwk" }), { name: "Ed25519" }, false, ["sign"]);
  return (await Sign1.sign(
    [[Headers.Algorithm, Algorithms.EdDSA], [Headers.KeyID, Buffer.from(issuer.keyId)]],
    undefined, payload, signingKey,
  )).encode();
}

export async function verifyStatement(
  bytes: Uint8Array,
  options: { subject: string; schema: string; issuers: readonly IssuerTrust[]; now?: number },
): Promise<StatementResult> {
  const result = (status: ClaimStatus, reason: string): StatementResult => ({ status, reason, revocation: "not-checked" });
  try {
    if (!(bytes instanceof Uint8Array) || bytes.length > MAX_STATEMENT_BYTES || !bytes.length) return result("failed", "STATEMENT_SIZE");
    const decoded = cbor.decodeFirstSync(Buffer.from(bytes), { preferMap: true, max_depth: 16, preventDuplicateKeys: true });
    if (!(decoded instanceof cbor.Tagged) || decoded.tag !== 18 || !Array.isArray(decoded.value) || decoded.value.length !== 4) return result("failed", "COSE_STRUCTURE");
    const [protectedBytes, unprotected, payload, signature] = decoded.value;
    if (!Buffer.isBuffer(protectedBytes) || !Buffer.isBuffer(payload) || !Buffer.isBuffer(signature) || signature.length !== 64) return result("failed", "COSE_STRUCTURE");
    const headers = cbor.decodeFirstSync(protectedBytes, { preferMap: true, max_depth: 4, preventDuplicateKeys: true });
    // This small profile permits only alg and kid. Unknown headers cannot silently change semantics.
    if (!(headers instanceof Map) || headers.size !== 2 || headers.get(1) !== -8 || !Buffer.isBuffer(headers.get(4))
      || !(unprotected instanceof Map) || unprotected.size !== 0) return result("failed", "UNSUPPORTED_COSE_HEADER");
    const issuerId = headers.get(4).toString("utf8");
    const trust = options.issuers.find(x => x.keyId === issuerId && x.schemas.includes(options.schema));
    if (!trust) return result("unresolved", "ISSUER_NOT_TRUSTED_FOR_SCHEMA");
    if (keyIdFor(trust.publicKey) !== trust.keyId) return result("failed", "ISSUER_KEY_MISMATCH");
    const verifyingKey = await globalThis.crypto.subtle.importKey("jwk", trust.publicKey, { name: "Ed25519" }, false, ["verify"]);
    await Sign1.decode(bytes).verify(verifyingKey, { algorithms: [Algorithms.EdDSA] });
    const statement: unknown = cbor.decodeFirstSync(payload, { max_depth: 12, preventDuplicateKeys: true });
    checkShape(statement);
    if (statement.issuer !== issuerId || statement.schema !== options.schema || statement.subject !== options.subject) return result("failed", "CLAIM_BINDING_MISMATCH");
    const now = options.now ?? Date.now();
    if (!Number.isFinite(now) || now < statement.issuedAt || now >= statement.expiresAt) return result("failed", "CLAIM_EXPIRED_OR_NOT_YET_VALID");
    return { status: "verified", reason: "ISSUER_SIGNATURE_SUBJECT_SCHEMA_AND_TIME_VERIFIED", statement, revocation: "not-checked" };
  } catch { return result("failed", "INVALID_STATEMENT"); }
}

/** A signed, offline snapshot. 'good' means good as of issuedAt, never live global revocation knowledge. */
export async function verifyStatusSnapshot(bytes: Uint8Array, options: {
  credentialId: string; issuer: IssuerTrust; maxAgeMs: number; now?: number;
}): Promise<{ status: "good" | "revoked" | "unknown"; asOf?: number; reason: string }> {
  const now = options.now ?? Date.now();
  if (!Number.isSafeInteger(options.maxAgeMs) || options.maxAgeMs <= 0) return { status: "unknown", reason: "INVALID_MAX_AGE" };
  const result = await verifyStatement(bytes, { subject: options.credentialId, schema: STATUS_SCHEMA, issuers: [options.issuer], now });
  if (result.status !== "verified" || !result.statement) return { status: "unknown", reason: result.reason };
  const { issuedAt, content } = result.statement;
  if (now - issuedAt >= options.maxAgeMs) return { status: "unknown", asOf: issuedAt, reason: "STALE_STATUS_SNAPSHOT" };
  if (content.status !== "good" && content.status !== "revoked") return { status: "unknown", reason: "INVALID_STATUS_VALUE" };
  return { status: content.status, asOf: issuedAt, reason: "SIGNED_OFFLINE_SNAPSHOT" };
}
