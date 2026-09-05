// SPDX-License-Identifier: Apache-2.0
// Two local processes, each generating and retaining its own private key.
// IPC is a teaching transport, not a BLE/Wi-Fi bearer or a production credential-distribution mechanism.
import { fork } from "node:child_process";
import { fileURLToPath } from "node:url";
import { AuthenticationSession, authenticateOverTransport, generateIdentityKeyPair, pinnedCredentials, type PeerCredential } from "../src/baseline/index.js";

const childMode = process.argv.includes("--responder");
const identity = generateIdentityKeyPair();
const child = childMode ? undefined : fork(fileURLToPath(import.meta.url), ["--responder"], { stdio: ["ignore", "inherit", "inherit", "ipc"] });
const channel = child ?? process;
type Message = { kind: "credential"; peer: PeerCredential } | { kind: "frame"; hex: string } | { kind: "report"; report: unknown };
const queue: Message[] = [];
let notify: (() => void) | undefined;
channel.on("message", (value: Message) => { queue.push(value); notify?.(); });
const signal = AbortSignal.timeout(10_000);
async function next(): Promise<Message> {
  while (!queue.length) {
    signal.throwIfAborted();
    await new Promise<void>((resolve, reject) => {
      const abort = () => { notify = undefined; reject(new Error("IPC_TIMEOUT")); };
      notify = () => { signal.removeEventListener("abort", abort); notify = undefined; resolve(); };
      signal.addEventListener("abort", abort, { once: true });
    });
  }
  return queue.shift()!;
}
async function send(message: Message) {
  await new Promise<void>((resolve, reject) => {
    const done = (error: Error | null) => error ? reject(error) : resolve();
    if (child) child.send(message, done);
    else process.send!(message, done);
  });
}
try {
  await send({ kind: "credential", peer: { subject: identity.keyId, publicKey: identity.publicKey } });
  const offered = await next();
  if (offered.kind !== "credential") throw new Error("EXPECTED_DEMO_CREDENTIAL");
  const role = childMode ? "responder" : "initiator";
  const session = new AuthenticationSession({ role, identity, resolvePeer: pinnedCredentials([offered.peer]) });
  const report = await authenticateOverTransport(session, {
    send: frame => send({ kind: "frame", hex: Buffer.from(frame).toString("hex") }),
    receive: async () => { const message = await next(); if (message.kind !== "frame") throw new Error("EXPECTED_FRAME"); return Buffer.from(message.hex, "hex"); },
  }, role, signal);
  if (childMode) await send({ kind: "report", report });
  else {
    const other = await next(); if (other.kind !== "report") throw new Error("EXPECTED_REPORT");
    console.log(JSON.stringify({ environment: "two local processes / IPC / no internet", initiator: report, responder: other.report }, null, 2));
  }
} catch (error) { console.error(error instanceof Error ? error.message : "EXCHANGE_FAILED"); process.exitCode = 1; }
finally { if (child) { if (child.connected) child.disconnect(); child.kill(); } }
