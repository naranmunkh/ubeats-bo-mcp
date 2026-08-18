#!/usr/bin/env node
/**
 * Quick live test for ubeats-bo-mcp: authenticate against Keycloak, then pull
 * one page of the driver-revenue report.
 *
 * Usage:
 *   1. cp .env.example .env  &&  fill in UBEATS_BO_USERNAME / UBEATS_BO_PASSWORD
 *   2. node --env-file=.env scripts/test-login.mjs [beginDate] [endDate]
 *      e.g. node --env-file=.env scripts/test-login.mjs 2026-08-17 2026-08-18
 *
 * (Node 20.6+ supports --env-file. Otherwise export the vars manually.)
 * NOTE: endDate is EXCLUSIVE — for a single day pass the next day.
 */

const SSO_URL = process.env.UBEATS_BO_SSO_URL || "https://sso.ubcabtech.com";
const REALM = process.env.UBEATS_BO_REALM || "ubcab-bo";
const API_URL = process.env.UBEATS_BO_API_URL || "https://ubeats-bo-api.ubcabtech.com";
const CLIENT_ID = process.env.UBEATS_BO_CLIENT_ID || "ubeats-bo";
const ORIGIN = process.env.UBEATS_BO_ORIGIN || "https://office.ubeats.mn";
const TOKEN_URL = `${SSO_URL}/realms/${REALM}/protocol/openid-connect/token`;

const pad = (n) => String(n).padStart(2, "0");
const iso = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
const today = new Date();
const yesterday = new Date(today.getTime() - 86400000);
const beginDate = process.argv[2] || iso(yesterday);
const endDate = process.argv[3] || iso(today);

async function getToken() {
  let params;
  if (process.env.UBEATS_BO_REFRESH_TOKEN) {
    params = {
      grant_type: "refresh_token",
      refresh_token: process.env.UBEATS_BO_REFRESH_TOKEN,
      client_id: CLIENT_ID,
    };
  } else if (process.env.UBEATS_BO_USERNAME && process.env.UBEATS_BO_PASSWORD) {
    params = {
      grant_type: "password",
      client_id: CLIENT_ID,
      username: process.env.UBEATS_BO_USERNAME,
      password: process.env.UBEATS_BO_PASSWORD,
      scope: "openid",
    };
  } else {
    throw new Error("Set UBEATS_BO_USERNAME + UBEATS_BO_PASSWORD, or UBEATS_BO_REFRESH_TOKEN");
  }
  const res = await fetch(TOKEN_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
      Origin: ORIGIN,
      Referer: `${ORIGIN}/`,
    },
    body: new URLSearchParams(params).toString(),
  });
  const json = await res.json().catch(() => null);
  if (!res.ok) {
    throw new Error(`Keycloak auth failed (HTTP ${res.status}): ${JSON.stringify(json)}`);
  }
  const claims = JSON.parse(
    Buffer.from(json.access_token.split(".")[1], "base64url").toString("utf8")
  );
  console.log(`✓ Logged in as ${claims.preferred_username} (azp=${claims.azp}, iss=${claims.iss})`);
  return json.access_token;
}

const token = await getToken();

const res = await fetch(`${API_URL}/v1/api/reports/driver-revenue/list`, {
  method: "POST",
  headers: {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
    Accept: "application/json",
    "Accept-Language": "mn",
    Origin: ORIGIN,
    Referer: `${ORIGIN}/`,
  },
  body: JSON.stringify({ filter: { beginDate, endDate }, page: 1, limit: 3 }),
});
const json = await res.json().catch(() => null);
if (!res.ok || !json?.success) {
  console.error(`✗ driver-revenue/list HTTP ${res.status}`, JSON.stringify(json, null, 2));
  process.exit(1);
}
const d = json.data;
console.log(
  `✓ driver-revenue ${beginDate} → ${endDate} (endDate exclusive): ` +
    `total=${d.total} pages=${d.totalPage} orderAmount=${d.orderAmount} deliveryAmount=${d.deliveryAmount}`
);
console.log(`  first ${d.docs.length} rows:`);
for (const row of d.docs) {
  console.log(`   - ${row.orderNumber} | ${row.merchantName} | ${row.deliveryPriceValue} | ${row.driverInfo}`);
}
