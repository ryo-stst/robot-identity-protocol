// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { runDomainDemo } from "../src/baseline/domain-demo.js";

const result = await runDomainDemo();
assert.equal(result.authentication.delivery.identity, "verified");
assert.equal(result.authentication.inspection.identity, "verified");
assert.equal(result.differentDomains.deliveryAsksForCargo[0]!.status, "unsupported");
assert.equal(result.differentDomains.inspectionAsksForTool[0]!.status, "unsupported");
assert.equal(result.explicitDomainSupport.items[0]!.status, "verified");
console.log("1. Delivery and inspection endpoints: both authenticated.");
console.log("2. Different domain: unsupported, without changing authentication.");
console.log("3. Explicit validator + issuer trust added: inspection statement verified.");
console.log(JSON.stringify(result, null, 2));
