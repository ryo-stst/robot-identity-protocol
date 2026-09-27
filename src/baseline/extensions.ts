// SPDX-License-Identifier: Apache-2.0
import { randomBytes } from "node:crypto";
import cbor from "cbor";
import { AuthenticationSession, RipError } from "./edhoc.js";
import { MAX_STATEMENT_BYTES, verifyStatement, type IssuerTrust, type Statement } from "./claims.js";

export const DOMAIN_EXCHANGE_PROFILE = "rip-domain-exchange-0.1";
export const MAX_DOMAIN_FRAME_BYTES = 150_000;
export const MAX_DOMAIN_SCHEMAS = 8;
export const MAX_DOMAIN_REQUESTS = 32;

export interface DomainProvider {
  schema: string;
  /** Trusted local disclosure callback. undefined withholds data; no operation permission is decided. */
  provide(context: { peerKeyId: string; schema: string }): Promise<Uint8Array | undefined>;
}
export interface DomainValidator {
  schema: string;
  /** Trusted local code; gets a detached statement after COSE checks, never remotely loaded code. */
  validate(statement: Statement, context: { now: number }): boolean;
}
export interface DomainItemResult {
  schema: string;
  status: "verified" | "failed" | "unresolved" | "unsupported" | "unavailable";
  source: "local-check" | "envelope-report";
  reason: string;
  revocation: "not-checked";
  statement?: Statement;
}
export interface DomainExchangeResult {
  profile: typeof DOMAIN_EXCHANGE_PROFILE;
  envelopeAuthentication: "not-provided";
  confidentiality: "not-provided";
  items: DomainItemResult[];
}

type Entry = [string, "provided", Buffer] | [string, "unsupported" | "unavailable"];
type Frame = [typeof DOMAIN_EXCHANGE_PROFILE, 0 | 1, string, Buffer, unknown[]];

function schemaId(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 512;
}
function schemas(value: unknown): asserts value is string[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > MAX_DOMAIN_SCHEMAS
    || value.some(x => !schemaId(x)) || new Set(value).size !== value.length) {
    throw new RipError("INVALID_DOMAIN_SCHEMAS");
  }
}
function encode(frame: Frame): Uint8Array {
  const bytes = cbor.encodeCanonical(frame);
  if (bytes.length > MAX_DOMAIN_FRAME_BYTES) throw new RipError("DOMAIN_FRAME_SIZE");
  return bytes;
}
function decode(bytes: Uint8Array, kind: 0 | 1, exchangeId: string): Frame {
  if (!(bytes instanceof Uint8Array) || !bytes.length || bytes.length > MAX_DOMAIN_FRAME_BYTES) {
    throw new RipError("DOMAIN_FRAME_SIZE");
  }
  let value: unknown;
  try { value = cbor.decodeFirstSync(Buffer.from(bytes), { max_depth: 6, preventDuplicateKeys: true, preferMap: true }); }
  catch { throw new RipError("MALFORMED_DOMAIN_FRAME"); }
  if (!Array.isArray(value) || value.length !== 5 || value[0] !== DOMAIN_EXCHANGE_PROFILE
    || value[1] !== kind || value[2] !== exchangeId || !Buffer.isBuffer(value[3]) || value[3].length !== 16
    || !Array.isArray(value[4]) || value[4].length < 1 || value[4].length > MAX_DOMAIN_SCHEMAS) {
    throw new RipError("DOMAIN_FRAME_MISMATCH");
  }
  return value as Frame;
}
function entries(value: unknown[], expected: readonly string[]): Entry[] {
  if (value.length !== expected.length) throw new RipError("DOMAIN_RESPONSE_MISMATCH");
  for (let i = 0; i < value.length; i++) {
    const item = value[i];
    if (!Array.isArray(item) || item[0] !== expected[i]) throw new RipError("DOMAIN_RESPONSE_MISMATCH");
    if (item[1] === "provided") {
      if (item.length !== 3 || !Buffer.isBuffer(item[2]) || !item[2].length || item[2].length > MAX_STATEMENT_BYTES) {
        throw new RipError("INVALID_DOMAIN_ENTRY");
      }
    } else if ((item[1] !== "unsupported" && item[1] !== "unavailable") || item.length !== 2) {
      throw new RipError("INVALID_DOMAIN_ENTRY");
    }
  }
  return value as Entry[];
}

/** Experimental local-test helper. These envelopes have NO transport authentication or encryption. */
export class DomainExtensionSession {
  readonly #peerKeyId: string;
  readonly #exchangeId: string;
  readonly #now: () => number;
  readonly #deadline: number;
  #lastTime: number;
  readonly #issuers: readonly IssuerTrust[];
  readonly #providers = new Map<string, DomainProvider["provide"]>();
  readonly #validators = new Map<string, DomainValidator["validate"]>();
  readonly #received = new Set<string>();
  #outgoingCount = 0;
  #pending: { id: Buffer; schemas: string[] } | undefined;
  #responding = false;
  #verifying = false;

  constructor(options: {
    mode: "local-test-only";
    session: AuthenticationSession;
    issuers?: readonly IssuerTrust[];
    providers?: readonly DomainProvider[];
    validators?: readonly DomainValidator[];
    timeoutMs?: number;
    now?: () => number;
  }) {
    if (options.mode !== "local-test-only") throw new RipError("DOMAIN_PROTECTED_TRANSPORT_NOT_IMPLEMENTED");
    const report = options.session.report();
    this.#peerKeyId = report.peerKeyId;
    this.#exchangeId = report.exchangeId;
    this.#now = options.now ?? Date.now;
    const start = this.#now(), ttl = options.timeoutMs ?? 30_000;
    if (!Number.isSafeInteger(start) || !Number.isSafeInteger(ttl) || ttl < 1 || ttl > 120_000
      || !Number.isSafeInteger(start + ttl)) throw new RipError("INVALID_DOMAIN_TIMEOUT");
    this.#deadline = start + ttl;
    this.#lastTime = start;
    this.#issuers = structuredClone(options.issuers ?? []);
    for (const provider of options.providers ?? []) {
      if (!schemaId(provider.schema) || this.#providers.has(provider.schema) || typeof provider.provide !== "function") {
        throw new RipError("INVALID_DOMAIN_PROVIDER");
      }
      this.#providers.set(provider.schema, provider.provide);
    }
    for (const validator of options.validators ?? []) {
      if (!schemaId(validator.schema) || this.#validators.has(validator.schema) || typeof validator.validate !== "function") {
        throw new RipError("INVALID_DOMAIN_VALIDATOR");
      }
      this.#validators.set(validator.schema, validator.validate);
    }
  }

  #checkTime(): number {
    const now = this.#now();
    if (!Number.isSafeInteger(now) || now < this.#lastTime || now >= this.#deadline) throw new RipError("DOMAIN_EXCHANGE_EXPIRED");
    this.#lastTime = now;
    return now;
  }

  /** Request only exact versioned schema IDs. No catalog broadcast and no network fetching. */
  request(requestedSchemas: readonly string[]): Uint8Array {
    this.#checkTime();
    if (this.#pending || this.#verifying) throw new RipError("DOMAIN_REQUEST_PENDING");
    if (this.#outgoingCount >= MAX_DOMAIN_REQUESTS) throw new RipError("DOMAIN_REQUEST_LIMIT");
    const selected: unknown = [...requestedSchemas]; schemas(selected);
    const id = randomBytes(16);
    const frame = encode([DOMAIN_EXCHANGE_PROFILE, 0, this.#exchangeId, id, selected]);
    this.#pending = { id, schemas: selected };
    this.#outgoingCount++;
    return frame;
  }

  async respond(request: Uint8Array): Promise<Uint8Array> {
    this.#checkTime();
    if (this.#responding) throw new RipError("DOMAIN_OPERATION_BUSY");
    const frame = decode(request, 0, this.#exchangeId);
    schemas(frame[4]);
    const requestId = frame[3].toString("hex");
    if (this.#received.has(requestId)) throw new RipError("DOMAIN_REQUEST_REPLAY");
    if (this.#received.size >= MAX_DOMAIN_REQUESTS) throw new RipError("DOMAIN_REQUEST_LIMIT");
    this.#received.add(requestId);
    this.#responding = true;
    try {
      const result: Entry[] = [];
      for (const schema of frame[4]) {
        this.#checkTime();
        const provider = this.#providers.get(schema);
        if (!provider) { result.push([schema, "unsupported"]); continue; }
        let statement: Uint8Array | undefined;
        try { statement = await provider({ peerKeyId: this.#peerKeyId, schema }); }
        catch { /* Do not expose provider errors or inventory details in the envelope. */ }
        this.#checkTime();
        if (!statement) { result.push([schema, "unavailable"]); continue; }
        if (!(statement instanceof Uint8Array) || !statement.length || statement.length > MAX_STATEMENT_BYTES) {
          throw new RipError("DOMAIN_STATEMENT_SIZE");
        }
        result.push([schema, "provided", Buffer.from(statement)]);
      }
      const response = encode([DOMAIN_EXCHANGE_PROFILE, 1, this.#exchangeId, frame[3], result]);
      this.#checkTime();
      return response;
    } finally { this.#responding = false; }
  }

  /** Single consumption, even for a bad response. This does not mutate the EDHOC report. */
  async verify(response: Uint8Array): Promise<DomainExchangeResult> {
    const pending = this.#pending;
    if (!pending || this.#verifying) throw new RipError("NO_PENDING_DOMAIN_REQUEST");
    this.#pending = undefined;
    this.#verifying = true;
    try {
      this.#checkTime();
      const frame = decode(response, 1, this.#exchangeId);
      if (!frame[3].equals(pending.id)) throw new RipError("DOMAIN_REQUEST_MISMATCH");
      const received = entries(frame[4], pending.schemas);
      const items: DomainItemResult[] = [];
      for (const entry of received) {
        const [schema, status] = entry;
        const base = { schema, revocation: "not-checked" as const };
        if (status !== "provided") {
          items.push({ ...base, status, source: "envelope-report", reason: `PEER_REPORTED_${status.toUpperCase()}` });
          continue;
        }
        const validate = this.#validators.get(schema);
        if (!validate) {
          items.push({ ...base, status: "unsupported", source: "local-check", reason: "NO_LOCAL_SCHEMA_VALIDATOR" });
          continue;
        }
        const claim = await verifyStatement(entry[2], {
          subject: this.#peerKeyId, schema, issuers: this.#issuers, now: this.#checkTime(),
        });
        this.#checkTime();
        if (claim.status !== "verified" || !claim.statement) {
          items.push({ ...base, status: claim.status === "verified" ? "failed" : claim.status, source: "local-check", reason: claim.reason });
          continue;
        }
        let valid = false;
        // Validation cannot modify the signed statement subsequently exposed to callers.
        try { valid = validate(structuredClone(claim.statement), { now: this.#checkTime() }) === true; }
        catch { /* A throwing validator never yields verified or leaks local error text. */ }
        const now = this.#checkTime();
        if (now < claim.statement.issuedAt || now >= claim.statement.expiresAt) {
          items.push({ ...base, status: "failed", source: "local-check", reason: "CLAIM_EXPIRED_OR_NOT_YET_VALID" });
        } else if (!valid) {
          items.push({ ...base, status: "failed", source: "local-check", reason: "DOMAIN_CONTENT_REJECTED" });
        } else {
          items.push({ ...base, status: "verified", source: "local-check", reason: "SIGNED_STATEMENT_AND_DOMAIN_VALIDATOR_PASSED", statement: claim.statement });
        }
      }
      this.#checkTime();
      return { profile: DOMAIN_EXCHANGE_PROFILE, envelopeAuthentication: "not-provided", confidentiality: "not-provided", items };
    } finally { this.#verifying = false; }
  }
}
