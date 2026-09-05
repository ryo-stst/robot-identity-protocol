/*
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE in the project root for license information.
 */

import {
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
  type JsonWebKey,
  type KeyObject,
} from "node:crypto";
import { canonicalBytes, sha256Base64Url } from "./encoding.js";

export interface IdentityKeyPair {
  keyId: string;
  publicKey: JsonWebKey;
  privateKey: KeyObject;
}

export function keyIdFor(publicKey: JsonWebKey): string {
  return `urn:rip:key:sha256:${sha256Base64Url(publicKey)}`;
}

export function generateIdentityKeyPair(): IdentityKeyPair {
  const pair = generateKeyPairSync("ed25519");
  const exported = pair.publicKey.export({ format: "jwk" }) as JsonWebKey;
  // Some Node-compatible runtimes also export alg/key_ops/ext metadata. The
  // profile's identity and fingerprint must use only its three public fields.
  const publicKey: JsonWebKey = { kty: exported.kty!, crv: exported.crv!, x: exported.x! };
  return {
    keyId: keyIdFor(publicKey),
    publicKey,
    privateKey: pair.privateKey,
  };
}

export function signObject(value: unknown, privateKey: KeyObject): string {
  return sign(null, canonicalBytes(value), privateKey).toString("base64url");
}

export function verifyObject(
  value: unknown,
  signature: string,
  publicKey: JsonWebKey,
): boolean {
  try {
    const key = createPublicKey({ key: publicKey, format: "jwk" });
    return verify(
      null,
      canonicalBytes(value),
      key,
      Buffer.from(signature, "base64url"),
    );
  } catch {
    return false;
  }
}
