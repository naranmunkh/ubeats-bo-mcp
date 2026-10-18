#!/usr/bin/env node
/**
 * One-time OTP login → long-lived Keycloak OFFLINE token for the MCP server.
 *
 * Why: the ubcab-bo realm requires an authenticator-app OTP. A server can't
 * produce a 30-second code, so instead you log in ONCE here (password + OTP)
 * with scope=offline_access. Keycloak returns an offline refresh token that
 * the MCP uses to mint access tokens — no password, no OTP — until it sits
 * unused for the realm's Offline Session Idle (default 30 days).
 *
 * Usage (from the repo folder, no inline # comments):
 *   npm run login              UBEats BO  (client ubeats-bo → UBEATS_BO_REFRESH_TOKEN)
 *   npm run login:bo           UBCab BO   (client ubcab-registration-bo → UBCAB_BO_REFRESH_TOKEN)
 *
 * Flags: --client <id> --var <ENV_NAME> --origin <url> --api <url> --user <email>
 *
 * The token is NEVER printed. It is written into ./.env under --var and, on
 * macOS, copied to the clipboard so you can paste it into Vercel → Settings →
 * Environment Variables. Then Redeploy.
 */

import { readFileSync, writeFileSync, existsSync, chmodSync } from "node:fs";
import { spawnSync } from "node:child_process";
import readline from "node:readline";
import { Writable } from "node:stream";

// ---------------------------------------------------------------- presets
const PRESETS = {
  ubeats: {
    client: "ubeats-bo",
    var: "UBEATS_BO_REFRESH_TOKEN",
    origin: "https://office.ubeats.mn",
    api: "https://ubeats-bo-api.ubcabtech.com",
    probe: { method: "GET", path: "/v1/api/reports/driver-revenue/meta?action=list" },
    userVars: ["UBCAB_BO_USERNAME", "UBEATS_BO_USERNAME", "UBEATS_USERNAME"],
    passVars: ["UBCAB_BO_PASSWORD", "UBEATS_BO_PASSWORD", "UBEATS_PASSWORD"],
  },
  bo: {
    client: "ubcab-registration-bo",
    var: "UBCAB_BO_REFRESH_TOKEN",
    origin: "https://operator.ubcab.mn",
    api: "https://registration-bo-api.ubcabtech.com",
    probe: { method: "GET", path: "/v1/driver/select-options/services" },
    userVars: ["UBCAB_BO_USERNAME"],
    passVars: ["UBCAB_BO_PASSWORD"],
  },
};

const argv = process.argv.slice(2);
const flag = (name) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 ? argv[i + 1] : undefined;
};
const presetName = flag("preset") || "ubeats";
const P = PRESETS[presetName];
if (!P) {
  console.error(`Unknown --preset ${presetName}. Use: ${Object.keys(PRESETS).join(", ")}`);
  process.exit(2);
}
const SSO = process.env.UBEATS_BO_SSO_URL || "https://sso.ubcabtech.com";
const REALM = process.env.UBEATS_BO_REALM || "ubcab-bo";
const CLIENT = flag("client") || P.client;
const VAR = flag("var") || P.var;
const ORIGIN = (flag("origin") || P.origin).replace(/\/+$/, "");
const API = (flag("api") || P.api).replace(/\/+$/, "");
const TOKEN_URL = `${SSO}/realms/${REALM}/protocol/openid-connect/token`;

// ---------------------------------------------------------------- .env I/O
const ENV_PATH = ".env";
const envText = existsSync(ENV_PATH) ? readFileSync(ENV_PATH, "utf8") : "";
const envGet = (k) => {
  const m = envText.match(new RegExp(`^${k}=(.*)$`, "m"));
  const v = m ? m[1].trim().replace(/^["']|["']$/g, "") : "";
  return v && v !== "replace-me" ? v : "";
};
const firstEnv = (keys) => keys.map((k) => process.env[k] || envGet(k)).find(Boolean) || "";

function upsertEnv(key, value) {
  let text = existsSync(ENV_PATH) ? readFileSync(ENV_PATH, "utf8") : "";
  const line = `${key}=${value}`;
  if (new RegExp(`^${key}=.*$`, "m").test(text)) {
    text = text.replace(new RegExp(`^${key}=.*$`, "m"), line);
  } else {
    if (text && !text.endsWith("\n")) text += "\n";
    text += `${line}\n`;
  }
  writeFileSync(ENV_PATH, text, { mode: 0o600 });
  try {
    chmodSync(ENV_PATH, 0o600);
  } catch {}
}

// ---------------------------------------------------------------- prompts
// One shared line reader for every prompt (separate readline instances drop
// buffered input). Output goes through a mutable stream so the password is
// never echoed — like sudo, nothing is shown while typing it.
let muted = false;
const out = new Writable({
  write(chunk, enc, cb) {
    if (!muted) process.stdout.write(chunk, enc);
    cb();
  },
});
const rl = readline.createInterface({ input: process.stdin, output: out, terminal: !!process.stdin.isTTY });
const lines = rl[Symbol.asyncIterator]();

async function ask(question, { hidden = false } = {}) {
  process.stdout.write(question);
  muted = hidden;
  const { value, done } = await lines.next();
  muted = false;
  if (hidden) process.stdout.write("\n");
  return done ? "" : String(value).trim();
}

const decode = (jwt) => {
  try {
    return JSON.parse(Buffer.from(jwt.split(".")[1], "base64url").toString("utf8"));
  } catch {
    return {};
  }
};

async function tokenPost(params) {
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
  const body = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, body };
}

function explain(status, body) {
  const e = body?.error;
  const d = body?.error_description || "";
  if (e === "invalid_grant")
    return `Нууц үг эсвэл OTP буруу (${d}). OTP 30 секундэд солигддог — апп дээрх ШИНЭ кодоор дахин оролд.`;
  if (e === "unauthorized_client")
    return `Client "${CLIENT}"-д direct grant (нууц үгээр нэвтрэх) хаалттай (${d}). UBCab tech багаас "Direct access grants"-ийг нээх, эсвэл service account үүсгэхийг хүс.`;
  if (e === "invalid_scope")
    return `offline_access scope зөвшөөрөгдөөгүй (${d}). Keycloak admin client "${CLIENT}"-д offline_access-ийг optional scope болгон нэмэх ёстой.`;
  if (e === "invalid_client") return `Client "${CLIENT}" олдсонгүй эсвэл confidential (${d}).`;
  return `HTTP ${status} ${e || ""} ${d}`.trim();
}

// ---------------------------------------------------------------- main
console.log(`\nKeycloak OTP login → offline token`);
console.log(`  realm  : ${REALM}`);
console.log(`  client : ${CLIENT}`);
console.log(`  env var: ${VAR}\n`);

let username = flag("user") || firstEnv(P.userVars);
if (!username) username = await ask("BO имэйл: ");
else console.log(`BO имэйл: ${username}`);
let password = firstEnv(P.passVars);
if (password) console.log("Нууц үг: (.env-ээс уншлаа)");
else password = await ask("Нууц үг (бичихэд харагдахгүй): ", { hidden: true });

let attempt = 0;
let result;
while (attempt < 3) {
  const otp = (await ask("Authenticator апп дээрх 6 оронтой код: ")).replace(/\s+/g, "");
  if (!/^\d{6,8}$/.test(otp)) {
    console.log("  6 оронтой тоо оруулна уу.");
    continue;
  }
  attempt++;
  result = await tokenPost({
    grant_type: "password",
    client_id: CLIENT,
    username,
    password,
    otp,
    totp: otp, // Keycloak < 12 compatibility
    scope: "openid offline_access",
  });
  if (result.ok) break;
  console.log(`  ✗ ${explain(result.status, result.body)}`);
  if (result.body?.error !== "invalid_grant") process.exit(1);
}
rl.close();
if (!result?.ok) process.exit(1);

const refresh = result.body.refresh_token;
const rt = decode(refresh);
const at = decode(result.body.access_token);
const isOffline = rt.typ === "Offline";
console.log(`\n✓ Нэвтэрлээ: ${at.preferred_username} (azp=${at.azp})`);
if (isOffline) {
  console.log(`✓ Offline token авлаа (typ=Offline${rt.exp ? `, дуусах ${new Date(rt.exp * 1000).toISOString()}` : ", хатуу дуусах хугацаагүй"}).`);
  console.log(`  ${result.body.refresh_expires_in ? `Ашиглагдахгүй ${Math.round(result.body.refresh_expires_in / 86400)} хоног болбол хүчингүй болно; ` : ""}MCP дуудлага бүр сунгана.`);
} else {
  console.log(`⚠ Энгийн refresh token ирлээ (typ=${rt.typ}) — offline_access зөвшөөрөгдөөгүй байна.`);
  console.log(`  Энэ token SSO session-той хамт (хэдхэн цагт) дуусна. Keycloak admin-аас client "${CLIENT}"-д offline_access нээхийг хүс.`);
}

// Prove the token works the way the server will use it: refresh → API call.
const r2 = await tokenPost({ grant_type: "refresh_token", refresh_token: refresh, client_id: CLIENT });
if (!r2.ok) {
  console.log(`✗ Refresh шалгалт амжилтгүй: ${explain(r2.status, r2.body)}`);
  process.exit(1);
}
const probe = await fetch(`${API}${P.probe.path}`, {
  method: P.probe.method,
  headers: {
    Authorization: `Bearer ${r2.body.access_token}`,
    Accept: "application/json",
    "Accept-Language": "mn",
    Origin: ORIGIN,
    Referer: `${ORIGIN}/`,
  },
});
console.log(`${probe.ok ? "✓" : "✗"} API шалгалт ${P.probe.path} → HTTP ${probe.status}`);

// The server keeps using the ORIGINAL offline token from env; Keycloak allows
// reuse unless "Revoke Refresh Token" is on for the realm. Save the original.
upsertEnv(VAR, refresh);
console.log(`✓ ${VAR} → .env-д бичлээ (token-ийг дэлгэцэнд хэвлэхгүй).`);

if (process.platform === "darwin") {
  const cp = spawnSync("pbcopy", { input: refresh });
  if (cp.status === 0) console.log("✓ Clipboard-д хууллаа — Vercel дээр шууд paste хийж болно.");
}

console.log(`
Дараагийн алхам:
  1. Vercel → project → Settings → Environment Variables
  2. ${VAR} = (clipboard), Production + Preview
  3. Нууц үгийн env (…_PASSWORD)-ийг устгаж болно — OTP-тэй үед ашиггүй
  4. Deployments → хамгийн сүүлийнх → Redeploy
`);
