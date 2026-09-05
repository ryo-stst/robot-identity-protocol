// SPDX-License-Identifier: Apache-2.0
import { runBaselineDemo } from "../src/baseline/demo.js";
const result = await runBaselineDemo({ attribute: process.argv.includes("--attribute"), optical: process.argv.includes("--optical"), multiple: process.argv.includes("--multiple") });
console.log(JSON.stringify({ profile: result.profile, status: result.status, reports: result.reports, attribute: result.attribute, optical: result.optical }, null, 2));
if (result.status !== "verified") process.exitCode = 1;
