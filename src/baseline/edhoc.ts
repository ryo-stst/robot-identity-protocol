// SPDX-License-Identifier: Apache-2.0
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import cbor from "cbor";
import { EDHOC, DefaultEdhocCryptoManager, EdhocCredentialsFormat, type EdhocCredentialManager, type EdhocCryptoManager } from "edhoc";
import { keyIdFor, type IdentityKeyPair } from "../crypto.js";
import type { PublicKeyJwk } from "../model.js";
import { IDENTITY_SCHEMA, verifyStatement, type IssuerTrust } from "./claims.js";

export const BASELINE_PROFILE = "rip-edhoc-ccs-0.2";
export const MAX_FRAME_BYTES = 4096;
export class RipError extends Error {
  constructor(readonly code: string) { super(code); this.name = "RipError"; }
}
export interface PeerCredential { subject: string; publicKey: PublicKeyJwk; }
/** Only return credentials accepted by a locally configured trust policy. No implicit network lookups. */
export type CredentialResolver = (keyId: string) => Promise<PeerCredential>;
export interface ByteTransport {
  send(frame: Uint8Array): Promise<void>;
  receive(signal: AbortSignal): Promise<Uint8Array>;
}

function rawKey(publicKey: PublicKeyJwk): Buffer {
  if (!publicKey || publicKey.kty !== "OKP" || publicKey.crv !== "Ed25519" || typeof publicKey.x !== "string"
    || Object.keys(publicKey).sort().join() !== "crv,kty,x") throw new RipError("UNSUPPORTED_KEY");
  const bytes = Buffer.from(publicKey.x, "base64url");
  if (bytes.length !== 32 || bytes.toString("base64url") !== publicKey.x) throw new RipError("INVALID_KEY");
  return bytes;
}
function ccs(peer: PeerCredential): Buffer {
  const key = new Map<number, unknown>([[1, 1], [-1, 6], [-2, rawKey(peer.publicKey)]]);
  return cbor.encodeCanonical(new Map<number, unknown>([[2, peer.subject], [8, new Map([[1, key]])]]));
}

export function pinnedCredentials(peers: readonly PeerCredential[]): CredentialResolver {
  const material = new Map(peers.map(peer => [keyIdFor(peer.publicKey), structuredClone(peer)]));
  return async id => {
    const peer = material.get(id);
    if (!peer) throw new RipError("UNKNOWN_PEER");
    return structuredClone(peer);
  };
}

/** Credentials may come from a local file/bundle; issuer trust is schema-scoped and supplied separately. */
export function issuerCredentials(options: {
  lookup: (keyId: string) => Promise<Uint8Array | undefined>;
  issuers: readonly IssuerTrust[];
  now?: () => number;
}): CredentialResolver {
  const issuers = structuredClone(options.issuers);
  return async id => {
    const bytes = await options.lookup(id);
    if (!bytes) throw new RipError("UNKNOWN_PEER");
    const result = await verifyStatement(bytes, { subject: id, schema: IDENTITY_SCHEMA, issuers, now: options.now?.() ?? Date.now() });
    if (result.status !== "verified" || !result.statement) throw new RipError(result.reason);
    const publicKey = result.statement.content.publicKey as PublicKeyJwk;
    rawKey(publicKey);
    if (keyIdFor(publicKey) !== id) throw new RipError("CREDENTIAL_KEY_MISMATCH");
    return { subject: id, publicKey };
  };
}

type State = "new" | "wait-2" | "send-2" | "wait-3" | "send-3" | "complete" | "failed";
export class AuthenticationSession {
  readonly #engine: EDHOC;
  readonly #deadline: number;
  readonly #now: () => number;
  readonly #role: "initiator" | "responder";
  #state: State = "new";
  #busy = false;
  #peer: PeerCredential | undefined;
  #peerKeyId: string | undefined;
  readonly #frames: Buffer[] = [];

  constructor(options: {
    role: "initiator" | "responder";
    identity: IdentityKeyPair;
    resolvePeer: CredentialResolver;
    timeoutMs?: number;
    now?: () => number;
    /** Alternate cryptography adapter. This alpha still requires an exportable software identity key. */
    crypto?: EdhocCryptoManager;
  }) {
    const identity = options.identity;
    rawKey(identity.publicKey);
    if (identity.keyId !== keyIdFor(identity.publicKey)) throw new RipError("LOCAL_KEY_MISMATCH");
    const ttl = options.timeoutMs ?? 30_000;
    if (!Number.isSafeInteger(ttl) || ttl <= 0 || ttl > 120_000) throw new RipError("INVALID_TIMEOUT");
    this.#now = options.now ?? Date.now;
    this.#deadline = this.#now() + ttl;
    this.#role = options.role;
    const credentials: EdhocCredentialManager = {
      fetch: () => ({
        format: EdhocCredentialsFormat.kid,
        publicKey: rawKey(identity.publicKey),
        privateKey: Buffer.from(identity.privateKey.export({ format: "jwk" }).d!, "base64url"),
        kid: { kid: Buffer.from(identity.keyId), credentials: ccs({ subject: identity.keyId, publicKey: identity.publicKey }), isCBOR: true },
      }),
      verify: async (_engine, offered) => {
        if (offered.format !== EdhocCredentialsFormat.kid || !("kid" in offered)) throw new RipError("UNSUPPORTED_CREDENTIAL");
        const kid = (offered as { kid: { kid: unknown } }).kid.kid;
        if (!Buffer.isBuffer(kid) || kid.length > 128) throw new RipError("INVALID_KID");
        const id = kid.toString("utf8");
        const peer = await options.resolvePeer(id);
        if (peer.subject !== id || keyIdFor(peer.publicKey) !== id) throw new RipError("CREDENTIAL_KEY_MISMATCH");
        this.#peer = structuredClone(peer);
        this.#peerKeyId = id;
        return { format: EdhocCredentialsFormat.kid, publicKey: rawKey(peer.publicKey), kid: { kid, credentials: ccs(peer), isCBOR: true } };
      },
    };
    this.#engine = new EDHOC(randomBytes(8), [0], [0], credentials, options.crypto ?? new DefaultEdhocCryptoManager());
  }

  get state(): State { return this.#state; }
  async #step<T>(expected: State, next: State, task: () => Promise<T>): Promise<T> {
    if (this.#busy || this.#state !== expected) throw new RipError("UNEXPECTED_MESSAGE_OR_REPLAY");
    if (this.#now() >= this.#deadline) { this.#state = "failed"; throw new RipError("SESSION_EXPIRED"); }
    this.#busy = true;
    try {
      const value = await task();
      if (this.#now() >= this.#deadline) throw new RipError("SESSION_EXPIRED");
      this.#state = next;
      return value;
    } catch (error) {
      this.#state = "failed";
      throw error instanceof RipError ? error : new RipError("AUTHENTICATION_FAILED");
    } finally { this.#busy = false; }
  }
  #validate(frame: Uint8Array, message: 1 | 2 | 3): Buffer {
    if (!(frame instanceof Uint8Array) || frame.length < 1 || frame.length > MAX_FRAME_BYTES) throw new RipError("FRAME_SIZE");
    const bytes = Buffer.from(frame);
    const values = cbor.decodeAllSync(bytes, { max_depth: 4, preventDuplicateKeys: true });
    if (message === 1) {
      if (values.length !== 4 || values[0] !== 0 || values[1] !== 0 || !Buffer.isBuffer(values[2]) || values[2].length !== 32
        || !Buffer.isBuffer(values[3]) || values[3].length !== 8) throw new RipError("UNSUPPORTED_PROFILE_OR_MESSAGE");
    } else if (values.length !== 1 || !Buffer.isBuffer(values[0])) throw new RipError("MALFORMED_MESSAGE");
    return bytes;
  }
  async start(): Promise<Uint8Array> {
    if (this.#role !== "initiator") throw new RipError("WRONG_ROLE");
    return this.#step("new", "wait-2", async () => {
      const frame = await this.#engine.composeMessage1(); this.#frames.push(Buffer.from(frame)); return frame;
    });
  }
  async receive(frame: Uint8Array): Promise<void> {
    const message = this.#role === "initiator" ? 2 : this.#state === "new" ? 1 : 3;
    const expected = message === 1 ? "new" : message === 2 ? "wait-2" : "wait-3";
    return this.#step(expected, message === 1 ? "send-2" : message === 2 ? "send-3" : "complete", async () => {
      const bytes = this.#validate(frame, message);
      const ead = message === 1 ? await this.#engine.processMessage1(bytes) : message === 2 ? await this.#engine.processMessage2(bytes) : await this.#engine.processMessage3(bytes);
      if (ead.length) throw new RipError("UNSUPPORTED_EXTENSION");
      this.#frames.push(bytes);
    });
  }
  async respond(): Promise<Uint8Array> {
    const initiator = this.#role === "initiator";
    return this.#step(initiator ? "send-3" : "send-2", initiator ? "complete" : "wait-3", async () => {
      const frame = initiator ? await this.#engine.composeMessage3() : await this.#engine.composeMessage2();
      this.#frames.push(Buffer.from(frame)); return frame;
    });
  }
  report() {
    if (this.#state !== "complete" || !this.#peer) throw new RipError("SESSION_INCOMPLETE");
    return {
      profile: BASELINE_PROFILE, role: this.#role, peerKeyId: this.#peerKeyId!, identity: "verified" as const,
      trust: "locally-resolved-credential", physicalBinding: "not-evaluated", authorization: "outside-protocol",
      revocation: "not-checked", peerAcceptanceConfirmed: false,
      // Length framing makes the diagnostic identifier unambiguous. Not an authentication proof.
      exchangeId: createHash("sha256").update(cbor.encode(this.#frames)).digest("base64url"),
    };
  }
  /** Optional optical experiment, private-use exporter label 40001. Never log/export the underlying secret. */
  async opticalResponse(challenge: Uint8Array, targetKeyId: string): Promise<Uint8Array> {
    this.report();
    if (challenge.length !== 32 || !targetKeyId || targetKeyId.length > 128) throw new RipError("INVALID_OPTICAL_CHALLENGE");
    const key = await this.#engine.exportKey(40001, 32);
    try { return createHmac("sha256", key).update(cbor.encodeCanonical([BASELINE_PROFILE, "optical-v0.2", targetKeyId, Buffer.from(challenge)])).digest(); }
    finally { key.fill(0); }
  }
}

export function correlateOpticalObservation(expected: Uint8Array, observed: Uint8Array, tracks: readonly string[]) {
  const matched = expected.length === 32 && observed.length === 32 && timingSafeEqual(expected, observed);
  return {
    status: !matched ? "mismatch" : tracks.length === 1 ? "correlated" : "ambiguous",
    localTrackId: matched && tracks.length === 1 ? tracks[0]! : null,
    assurance: "sensor-correlation-only", relayResistance: "not-established", physicalIdentityProven: false,
  };
}

/** Transport carries complete bounded frames; adapters own discovery, framing, loss/retry and admission limits. */
export async function authenticateOverTransport(session: AuthenticationSession, transport: ByteTransport, role: "initiator" | "responder", signal: AbortSignal) {
  if (role === "initiator") {
    await transport.send(await session.start());
    await session.receive(await transport.receive(signal));
    await transport.send(await session.respond());
  } else {
    await session.receive(await transport.receive(signal));
    await transport.send(await session.respond());
    await session.receive(await transport.receive(signal));
  }
  return session.report();
}
