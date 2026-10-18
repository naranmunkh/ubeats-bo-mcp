#!/usr/bin/env node
/**
 * Offline check of the TOTP generator against the RFC 6238 Appendix B vectors
 * (SHA1, 8 digits, 30 s). Compiles nothing: extracts base32Decode/totpCode from
 * api/index.ts by transpiling it with the project's TypeScript.
 *   node scripts/test-totp.mjs
 */
import { readFileSync } from "node:fs";
import { createHmac } from "node:crypto";
import ts from "typescript";

const src = readFileSync(new URL("../api/index.ts", import.meta.url), "utf8");
const start = src.indexOf("export function base32Decode");
const end = src.indexOf("function totpPeriodMs");
const js = ts.transpileModule(src.slice(start, end).replace(/export /g, ""), { compilerOptions: { target: "ES2020" } }).outputText;
const { base32Decode, totpCode } = new Function("createHmac", "Buffer", `${js}; return { base32Decode, totpCode };`)(createHmac, Buffer);

const key = Buffer.from("12345678901234567890", "ascii");
const vectors = [[59, "94287082"], [1111111109, "07081804"], [1111111111, "14050471"], [1234567890, "89005924"], [2000000000, "69279037"], [20000000000, "65353130"]];
let fail = 0;
for (const [t, want] of vectors) {
  const got = totpCode(key, { now: t * 1000, digits: 8 });
  if (got !== want) { fail++; console.log("FAIL", t, got, "!=", want); }
}
// base32 of the same key ("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ") with spaces/lowercase as Keycloak shows it
const b32 = "gezd gnbv gy3t qojq gezd gnbv gy3t qojq";
if (base32Decode(b32).toString("ascii") !== "12345678901234567890") { fail++; console.log("FAIL base32"); }
if (totpCode(b32, { now: 59000, digits: 8 }) !== "94287082") { fail++; console.log("FAIL base32 totp"); }
if (totpCode(b32, { now: 59000 }).length !== 6) { fail++; console.log("FAIL default digits"); }
console.log(fail ? `${fail} failed` : `all ${vectors.length + 3} TOTP checks passed`);
process.exit(fail ? 1 : 0);
