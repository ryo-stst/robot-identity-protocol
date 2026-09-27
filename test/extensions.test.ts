// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import test from "node:test";
import cbor from "cbor";
import {
  AuthenticationSession, DomainExtensionSession, generateIdentityKeyPair, pinnedCredentials,
  issueStatement, DOMAIN_EXCHANGE_PROFILE, MAX_DOMAIN_FRAME_BYTES, MAX_DOMAIN_REQUESTS,
  type DomainValidator, type DomainProvider,
} from "../src/index.js";

const CARGO = "https://example.com/delivery/cargo/v1";
const TOOL = "https://example.com/inspection/tool/v1";
const TIME = 1_800_000_000_000;
const cargoValidator: DomainValidator = {
  schema: CARGO,
  validate: statement => typeof statement.content.nominalPayloadKg === "number"
    && Number.isFinite(statement.content.nominalPayloadKg) && statement.content.nominalPayloadKg >= 0,
};
async function fixture() {
  const delivery = generateIdentityKeyPair(), inspection = generateIdentityKeyPair(), issuer = generateIdentityKeyPair();
  const resolvePeer = pinnedCredentials([delivery, inspection].map(x => ({ subject: x.keyId, publicKey: x.publicKey })));
  const a = new AuthenticationSession({ role: "initiator", identity: delivery, resolvePeer });
  const b = new AuthenticationSession({ role: "responder", identity: inspection, resolvePeer });
  await b.receive(await a.start()); await a.receive(await b.respond()); await b.receive(await a.respond());
  const issuers = [{ keyId: issuer.keyId, publicKey: issuer.publicKey, schemas: [CARGO] }];
  const issue = (overrides: Partial<Parameters<typeof issueStatement>[1]> = {}) => issueStatement(issuer, {
    schema: CARGO, subject: inspection.keyId, issuedAt: TIME - 1000, expiresAt: TIME + 10_000,
    content: { nominalPayloadKg: 12 }, ...overrides,
  });
  const statement = await issue();
  const consumer = (overrides: Partial<ConstructorParameters<typeof DomainExtensionSession>[0]> = {}) => new DomainExtensionSession({
    mode: "local-test-only", session: a, issuers, validators: [cargoValidator], now: () => TIME, ...overrides,
  });
  const provider = (overrides: Partial<ConstructorParameters<typeof DomainExtensionSession>[0]> = {}) => new DomainExtensionSession({
    mode: "local-test-only", session: b, providers: [{ schema: CARGO, provide: async () => statement }], now: () => TIME, ...overrides,
  });
  return { a, b, delivery, inspection, issuer, issuers, statement, issue, consumer, provider };
}
function change(bytes: Uint8Array, edit: (frame: any[]) => void): Uint8Array {
  const frame = cbor.decodeFirstSync(bytes); edit(frame); return cbor.encodeCanonical(frame);
}

test("different domains authenticate; unavailable extensions never mutate either core report", async () => {
  const f = await fixture(), a = f.consumer(), b = f.provider({ providers: [] });
  const before = [f.a.report(), f.b.report()];
  const x = await a.verify(await b.respond(a.request([CARGO])));
  const y = await b.verify(await a.respond(b.request([TOOL])));
  assert.equal(x.items[0]!.status, "unsupported");
  assert.equal(y.items[0]!.status, "unsupported");
  assert.equal(x.items[0]!.source, "envelope-report");
  assert.equal(x.confidentiality, "not-provided");
  assert.equal(x.envelopeAuthentication, "not-provided");
  assert.deepEqual([f.a.report(), f.b.report()], before);
  assert.equal(before[0]!.identity, "verified");
  assert.equal(before[1]!.identity, "verified");
});

test("known signed extension needs issuer trust AND an exact local validator", async () => {
  const f = await fixture(), b = f.provider();
  for (const [options, status, reason] of [
    [{}, "verified", "SIGNED_STATEMENT_AND_DOMAIN_VALIDATOR_PASSED"],
    [{ validators: [] }, "unsupported", "NO_LOCAL_SCHEMA_VALIDATOR"],
    [{ issuers: [] }, "unresolved", "ISSUER_NOT_TRUSTED_FOR_SCHEMA"],
    [{ issuers: [{ ...f.issuers[0]!, schemas: [TOOL] }] }, "unresolved", "ISSUER_NOT_TRUSTED_FOR_SCHEMA"],
  ] as const) {
    const a = f.consumer(options);
    const result = await a.verify(await b.respond(a.request([CARGO])));
    assert.equal(result.items[0]!.status, status);
    assert.equal(result.items[0]!.reason, reason);
    assert.equal("statement" in result.items[0]!, status === "verified");
  }
});

test("only requested providers run; omission/withholding/errors share unavailable, with no serial leak", async () => {
  const f = await fixture(); let requested = 0, other = 0;
  const b = f.provider({ providers: [
    { schema: CARGO, provide: async context => { requested++; assert.equal(context.peerKeyId, f.delivery.keyId); return undefined; } },
    { schema: TOOL, provide: async () => { other++; throw new Error("secret inventory entry"); } },
  ] });
  const a = f.consumer(); const request = a.request([CARGO]);
  assert.deepEqual(cbor.decodeFirstSync(request)[4], [CARGO]);
  const response = await b.respond(request);
  const result = await a.verify(response);
  assert.equal(result.items[0]!.status, "unavailable");
  assert.equal(requested, 1); assert.equal(other, 0);
  assert.doesNotMatch(Buffer.from(response).toString(), /serial|assetId|secret inventory/);
  const a2 = f.consumer();
  assert.equal((await a2.verify(await b.respond(a2.request([TOOL])))).items[0]!.status, "unavailable");
});

test("version mismatch is unsupported; unknown local schema does not decode or infer payload", async () => {
  const f = await fixture(), a = f.consumer(), b = f.provider();
  const result = await a.verify(await b.respond(a.request([CARGO.replace("/v1", "/v2")])));
  assert.equal(result.items[0]!.status, "unsupported");
  const unknown = f.consumer({ validators: [] });
  const opaque = f.provider({ providers: [{ schema: CARGO, provide: async () => Buffer.from("not even CBOR") }] });
  assert.equal((await unknown.verify(await opaque.respond(unknown.request([CARGO])))).items[0]!.reason, "NO_LOCAL_SCHEMA_VALIDATOR");
});

test("tampered, copied, expired, future and schema-substituted claims fail before domain validation", async () => {
  const f = await fixture(); const tampered = Buffer.from(f.statement); tampered[tampered.length - 1]! ^= 1;
  const bytes = [
    tampered, await f.issue({ subject: f.delivery.keyId }),
    await f.issue({ expiresAt: TIME }), await f.issue({ issuedAt: TIME + 1 }), await f.issue({ schema: TOOL }),
    Buffer.from("bad COSE"),
  ];
  for (const value of bytes) {
    let called = false;
    const a = f.consumer({ validators: [{ schema: CARGO, validate: () => { called = true; return true; } }] });
    const b = f.provider({ providers: [{ schema: CARGO, provide: async () => value }] });
    const result = await a.verify(await b.respond(a.request([CARGO])));
    assert.equal(result.items[0]!.status, "failed");
    assert.equal(called, false); assert.equal(result.items[0]!.statement, undefined);
    assert.equal(f.a.report().identity, "verified");
  }
});

test("domain validator rejects signed nonsense, stale measurements and exceptions", async () => {
  const f = await fixture();
  for (const [content, validator] of [
    [{ nominalPayloadKg: -12 }, cargoValidator],
    [{ observedAt: TIME - 60_000 }, { schema: CARGO, validate: (s, context) => typeof s.content.observedAt === "number" && context.now - s.content.observedAt < 1000 }],
    [{ nominalPayloadKg: 12 }, { schema: CARGO, validate: () => { throw new Error("private validator detail"); } }],
  ] satisfies [Record<string, unknown>, DomainValidator][]) {
    const a = f.consumer({ validators: [validator] }); const bytes = await f.issue({ content });
    const b = f.provider({ providers: [{ schema: CARGO, provide: async () => bytes }] });
    const result = await a.verify(await b.respond(a.request([CARGO])));
    assert.equal(result.items[0]!.reason, "DOMAIN_CONTENT_REJECTED");
    assert.equal(result.items[0]!.statement, undefined);
  }
});

test("validator cannot change the signed statement exposed to the caller", async () => {
  const f = await fixture(), b = f.provider();
  const a = f.consumer({ validators: [{ schema: CARGO, validate: statement => { statement.content.nominalPayloadKg = 999; return true; } }] });
  const result = await a.verify(await b.respond(a.request([CARGO])));
  assert.equal(result.items[0]!.statement!.content.nominalPayloadKg, 12);
});

test("each domain result is independent: one failed attribute does not erase another verified attribute", async () => {
  const f = await fixture();
  const badCargo = await f.issue({ content: { nominalPayloadKg: -12 } });
  const tool = await f.issue({ schema: TOOL, content: { toolClass: "inspection" } });
  const a = f.consumer({
    issuers: [{ ...f.issuers[0]!, schemas: [CARGO, TOOL] }],
    validators: [cargoValidator, { schema: TOOL, validate: s => s.content.toolClass === "inspection" }],
  });
  const b = f.provider({ providers: [
    { schema: CARGO, provide: async () => badCargo }, { schema: TOOL, provide: async () => tool },
  ] });
  const result = await a.verify(await b.respond(a.request([CARGO, TOOL])));
  assert.deepEqual(result.items.map(x => x.status), ["failed", "verified"]);
  assert.equal(result.items[0]!.statement, undefined);
  assert.equal(result.items[1]!.statement!.schema, TOOL);
  assert.equal(f.a.report().identity, "verified");
});

test("request/response replays and overlapping local requests are rejected", async () => {
  const f = await fixture(), a = f.consumer(), b = f.provider();
  const request = a.request([CARGO]);
  assert.throws(() => a.request([CARGO]), /DOMAIN_REQUEST_PENDING/);
  const response = await b.respond(request);
  await assert.rejects(b.respond(request), /DOMAIN_REQUEST_REPLAY/);
  await a.verify(response);
  await assert.rejects(a.verify(response), /NO_PENDING_DOMAIN_REQUEST/);
  const fresh = a.request([CARGO]);
  assert.notDeepEqual(cbor.decodeFirstSync(fresh)[3], cbor.decodeFirstSync(request)[3]);
  await assert.rejects(a.verify(response), /DOMAIN_REQUEST_MISMATCH/);
  await assert.rejects(a.verify(await b.respond(fresh)), /NO_PENDING_DOMAIN_REQUEST/);
});

test("unrequested/duplicate/missing/reordered entries, malformed status and wrong correlation fail atomically", async () => {
  const f = await fixture();
  const edits: ((frame: any[]) => void)[] = [
    frame => { frame[0] = "future-profile"; }, frame => { frame[1] = 0; },
    frame => { frame[2] = "different-exchange"; }, frame => { frame[3] = Buffer.alloc(16); },
    frame => { frame[4].pop(); }, frame => { frame[4].push(frame[4][0]); },
    frame => { frame[4].reverse(); }, frame => { frame[4][0][0] = "https://example.com/unrequested/v1"; },
    frame => { frame[4][0][1] = "safe"; }, frame => { frame[4][1].push("extra"); },
    frame => { frame[4][0][2] = Buffer.alloc(16385); }, frame => { frame[4][0][2] = "not bytes"; },
  ];
  for (const edit of edits) {
    let called = false;
    const a = f.consumer({ validators: [{ schema: CARGO, validate: () => { called = true; return true; } }] });
    const response = await f.provider().respond(a.request([CARGO, TOOL]));
    await assert.rejects(a.verify(change(response, edit)));
    assert.equal(called, false);
    await assert.rejects(a.verify(response), /NO_PENDING_DOMAIN_REQUEST/);
  }
});

test("bounded frames, nesting, request count, exact schema strings and trailing objects", async () => {
  const f = await fixture();
  for (const invalid of [[], [CARGO, CARGO], [""], ["x".repeat(513)], Array.from({ length: 9 }, (_, i) => String(i))]) {
    assert.throws(() => f.consumer().request(invalid), /INVALID_DOMAIN_SCHEMAS/);
  }
  const request = f.consumer().request([CARGO]);
  for (const bytes of [Buffer.alloc(0), Buffer.alloc(MAX_DOMAIN_FRAME_BYTES + 1),
    Buffer.concat([request, Buffer.from([0])]), Buffer.from("9f".repeat(40) + "ff".repeat(40), "hex"),
    change(request, frame => { frame[4] = [CARGO, CARGO]; }),
    change(request, frame => { frame[4] = [null]; }),
  ]) await assert.rejects(f.provider().respond(bytes));
  const b = f.provider();
  for (let i = 0; i < MAX_DOMAIN_REQUESTS; i++) await b.respond(f.consumer().request([CARGO]));
  await assert.rejects(b.respond(f.consumer().request([CARGO])), /DOMAIN_REQUEST_LIMIT/);
  const a = f.consumer();
  for (let i = 0; i < MAX_DOMAIN_REQUESTS; i++) await a.verify(await f.provider().respond(a.request([CARGO])));
  assert.throws(() => a.request([CARGO]), /DOMAIN_REQUEST_LIMIT/);
});

test("requires completed authentication, explicit local-test mode and valid local registrations", async () => {
  const f = await fixture();
  const fresh = new AuthenticationSession({ role: "initiator", identity: f.delivery, resolvePeer: pinnedCredentials([]) });
  assert.throws(() => f.consumer({ session: fresh }), /SESSION_INCOMPLETE/);
  assert.throws(() => f.consumer({ mode: "production" as "local-test-only" }), /DOMAIN_PROTECTED_TRANSPORT_NOT_IMPLEMENTED/);
  assert.throws(() => f.consumer({ timeoutMs: 120001 }), /INVALID_DOMAIN_TIMEOUT/);
  assert.throws(() => f.consumer({ validators: [cargoValidator, cargoValidator] }), /INVALID_DOMAIN_VALIDATOR/);
  const p: DomainProvider = { schema: CARGO, provide: async () => undefined };
  assert.throws(() => f.provider({ providers: [p, p] }), /INVALID_DOMAIN_PROVIDER/);
  const b = f.provider({ providers: [{ schema: CARGO, provide: async () => Buffer.alloc(16385) }] });
  await assert.rejects(b.respond(f.consumer().request([CARGO])), /DOMAIN_STATEMENT_SIZE/);
});

test("helper expiry is checked after async providers and validators; no late success", async () => {
  const f = await fixture(); let time = TIME;
  const a = f.consumer({ now: () => time, timeoutMs: 5 });
  const request = a.request([CARGO]);
  const b = f.provider({ now: () => time, timeoutMs: 5, providers: [{ schema: CARGO, provide: async () => { time += 5; return f.statement; } }] });
  await assert.rejects(b.respond(request), /DOMAIN_EXCHANGE_EXPIRED/);
  const response = await f.provider().respond(request);
  await assert.rejects(a.verify(response), /DOMAIN_EXCHANGE_EXPIRED/);
  await assert.rejects(a.verify(response), /NO_PENDING_DOMAIN_REQUEST/);
  time = TIME;
  const a2 = f.consumer({ now: () => time, timeoutMs: 5, validators: [{ schema: CARGO, validate: () => { time += 5; return true; } }] });
  await assert.rejects(a2.verify(await f.provider().respond(a2.request([CARGO]))), /DOMAIN_EXCHANGE_EXPIRED/);
  const rollback = f.consumer({ now: () => time });
  time--;
  assert.throws(() => rollback.request([CARGO]), /DOMAIN_EXCHANGE_EXPIRED/);
});

test("concurrent responder and verifier work is rejected without duplicate callback execution", async () => {
  const f = await fixture(), a = f.consumer();
  let release!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const b = f.provider({ providers: [{ schema: CARGO, provide: async () => { await gate; return f.statement; } }] });
  const request = a.request([CARGO]);
  const pending = b.respond(request);
  await assert.rejects(b.respond(request), /DOMAIN_OPERATION_BUSY/);
  release(); const response = await pending;
  const verification = a.verify(response);
  await assert.rejects(a.verify(response), /NO_PENDING_DOMAIN_REQUEST/);
  assert.throws(() => a.request([CARGO]), /DOMAIN_REQUEST_PENDING/);
  assert.equal((await verification).items[0]!.status, "verified");
});

test("same key remains linkable; separate signed attributes do not anonymize authentication", async () => {
  const f = await fixture();
  const resolvePeer = pinnedCredentials([f.delivery, f.inspection].map(x => ({ subject: x.keyId, publicKey: x.publicKey })));
  const a = new AuthenticationSession({ role: "initiator", identity: f.delivery, resolvePeer });
  const b = new AuthenticationSession({ role: "responder", identity: f.inspection, resolvePeer });
  await b.receive(await a.start()); await a.receive(await b.respond()); await b.receive(await a.respond());
  assert.equal(a.report().peerKeyId, f.a.report().peerKeyId);
  assert.notEqual(a.report().exchangeId, f.a.report().exchangeId);
  assert.doesNotMatch(JSON.stringify(a.report()), /serial|assetId/);
  await assert.rejects(new DomainExtensionSession({ mode: "local-test-only", session: b }).respond(f.consumer().request([CARGO])), /DOMAIN_FRAME_MISMATCH/);
});

test("unauthenticated active initiator can learn responder ID: not symmetric identity privacy", async () => {
  const f = await fixture(); let observed = "";
  const attacker = new AuthenticationSession({ role: "initiator", identity: generateIdentityKeyPair(), resolvePeer: async id => { observed = id; throw new Error("stop local test before m3"); } });
  const target = new AuthenticationSession({ role: "responder", identity: f.inspection, resolvePeer: pinnedCredentials([]) });
  await target.receive(await attacker.start());
  await assert.rejects(attacker.receive(await target.respond()));
  assert.equal(observed, f.inspection.keyId);
  assert.equal(target.state, "wait-3");
  assert.throws(() => target.report(), /SESSION_INCOMPLETE/);
});

test("public correlation IDs do not authenticate availability reports (explicit negative assurance)", async () => {
  const f = await fixture(), a = f.consumer();
  const request = cbor.decodeFirstSync(a.request([CARGO]));
  const forged = cbor.encodeCanonical([DOMAIN_EXCHANGE_PROFILE, 1, request[2], request[3], [[CARGO, "unsupported"]]]);
  const result = await a.verify(forged);
  assert.equal(result.items[0]!.status, "unsupported");
  assert.equal(result.items[0]!.source, "envelope-report");
  assert.equal(result.envelopeAuthentication, "not-provided");
  assert.equal(f.a.report().identity, "verified");
});
