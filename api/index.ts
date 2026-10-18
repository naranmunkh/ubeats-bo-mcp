#!/usr/bin/env node
/**
 * UBEats Backoffice MCP server — single self-contained entry point.
 *
 * Backend for office.ubeats.mn ("UBEats Backoffice V2"), API host
 * https://ubeats-bo-api.ubcabtech.com.
 *
 * Runs two ways from this one file:
 *   - HTTP mode (Vercel): Streamable HTTP at /mcp behind OAuth 2.1 (PKCE).
 *     EACH USER SIGNS IN WITH THEIR OWN BO ACCOUNT on /authorize (email +
 *     password + optional OTP → Keycloak direct grant, scope offline_access),
 *     gated by UBEATS_BO_ALLOWED_EMAILS. Tool calls then run with that user's
 *     own BO permissions. See the "HTTP mode" section below.
 *   - stdio mode (local / Claude Desktop): when run directly; uses the env
 *     service account.
 *
 * SELF-CONTAINED ON PURPOSE: no relative imports, so neither Vercel's bundler
 * nor Node's ESM loader has to resolve sibling ".ts"/".js" files.
 *
 * Keycloak (verified 2026-08-18 from a live office.ubeats.mn session):
 *   issuer https://sso.ubcabtech.com/realms/ubcab-bo, OIDC client "ubeats-bo",
 *   Origin/Referer https://office.ubeats.mn. Access tokens live ~5 min and are
 *   refreshed silently. office.ubeats.mn's browser login doesn't ask for OTP,
 *   but the realm's DIRECT-GRANT flow asks for it when the user has an
 *   authenticator configured (e.g. for the UBCab BO) — hence the optional field.
 *
 * Env (HTTP mode):
 *   UBEATS_BO_MCP_AUTH_TOKEN    REQUIRED. Secret that seals OAuth codes/tokens
 *                               (AES-256-GCM); also a break-glass bearer that
 *                               uses the service account. `openssl rand -hex 32`
 *   UBEATS_BO_ALLOWED_EMAILS    REQUIRED. Who may connect: emails, "@ubcab.mn"
 *                               (whole domain) or "*" (any BO user). Empty → nobody.
 * Env (service account — stdio and break-glass only; connector users don't use it):
 *   UBCAB_BO_USERNAME, UBCAB_BO_PASSWORD   the BO login (same account/env names as ubcab-bo-mcp)
 *   UBCAB_BO_TOTP_SECRET        base32 TOTP secret of that account; a fresh code is
 *                               generated for every password grant (realm 2FA, 2026-10-05)
 *   UBCAB_BO_TOTP_DIGITS / _PERIOD / _ALGORITHM  defaults 6 / 30 / SHA1
 *   UBEATS_BO_USERNAME/PASSWORD/TOTP_SECRET  fallback login when UBCAB_BO_* is unset
 *   UBEATS_BO_REFRESH_TOKEN     offline token from `npm run login` (must be a ubeats-bo token)
 * Env (overrides, defaults are production):
 *   UBEATS_BO_CLIENT_ID (ubeats-bo), UBEATS_BO_SSO_URL, UBEATS_BO_REALM,
 *   UBEATS_BO_API_URL, UBEATS_BO_ORIGIN
 *
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { timingSafeEqual, createHash, createHmac, createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { pathToFileURL } from "node:url";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

// ===========================================================================
// TOTP (RFC 6238) — Keycloak 2FA on the BO realm (2026-10-05)
// Same generator as ubcab-bo-mcp (verified against the RFC 6238 vectors:
// scripts/test-totp.mjs).
// ===========================================================================

/** Decode an RFC 4648 base32 secret (spaces, dashes, padding and case ignored). */
export function base32Decode(input: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = input.toUpperCase().replace(/[\s=-]/g, "");
  if (!clean) throw new Error("Empty TOTP secret");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = alphabet.indexOf(ch);
    if (idx < 0) throw new Error("TOTP secret is not valid base32");
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** RFC 6238 TOTP code. `secret` may be a base32 string or raw key bytes. */
export function totpCode(
  secret: string | Buffer,
  opts: { now?: number; period?: number; digits?: number; algorithm?: string } = {},
): string {
  const key = typeof secret === "string" ? base32Decode(secret) : secret;
  const period = opts.period ?? 30;
  const digits = opts.digits ?? 6;
  const algorithm = (opts.algorithm ?? "SHA1").toLowerCase().replace("-", "");
  const counter = Math.floor((opts.now ?? Date.now()) / 1000 / period);
  const msg = Buffer.alloc(8);
  msg.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  msg.writeUInt32BE(counter >>> 0, 4);
  const h = createHmac(algorithm, key).update(msg).digest();
  const offset = h[h.length - 1] & 0x0f;
  const bin = ((h[offset] & 0x7f) << 24) | (h[offset + 1] << 16) | (h[offset + 2] << 8) | h[offset + 3];
  return String(bin % 10 ** digits).padStart(digits, "0");
}

function totpPeriodMs(): number {
  return (Number(process.env.UBCAB_BO_TOTP_PERIOD) || 30) * 1000;
}

/** Current TOTP code for `secret` with the realm's OTP policy (env-overridable). */
function totpFromEnv(secret: string | undefined): string | undefined {
  if (!secret) return undefined;
  return totpCode(secret, {
    digits: Number(process.env.UBCAB_BO_TOTP_DIGITS) || 6,
    period: totpPeriodMs() / 1000,
    algorithm: process.env.UBCAB_BO_TOTP_ALGORITHM || "SHA1",
  });
}

function isInvalidGrant(err: unknown): boolean {
  if (!(err instanceof BOError) || (err.status !== 400 && err.status !== 401)) return false;
  const body = (err.body ?? {}) as Record<string, unknown>;
  return body.error === "invalid_grant";
}

// ===========================================================================
// UBEats BO API client (Keycloak auth)
// ===========================================================================

const DEFAULT_SSO_URL = "https://sso.ubcabtech.com";
const DEFAULT_REALM = "ubcab-bo";
const DEFAULT_API_URL = "https://ubeats-bo-api.ubcabtech.com";
const DEFAULT_CLIENT_ID = "ubeats-bo";
const DEFAULT_ORIGIN = "https://office.ubeats.mn";

type HttpMethod = "GET" | "POST" | "PATCH" | "PUT" | "DELETE";

interface BOResult {
  status: number;
  ok: boolean;
  /** Parsed JSON body (or raw text / null). */
  body: unknown;
}

class BOError extends Error {
  constructor(message: string, public status?: number, public body?: unknown) {
    super(message);
    this.name = "BOError";
  }
}

/**
 * Auth-code revision, printed in every Keycloak auth error together with the
 * (non-secret) login settings. One failing tool call then shows which build is
 * live and what it sent — a stale deploy and a wrong env var look identical
 * otherwise. Bump it with every auth change.
 */
const AUTH_BUILD = "2026-10-18 per-user-login+bo-totp";

interface RequestOptions {
  query?: Record<string, unknown>;
  body?: unknown;
  /** Override Accept-Language (default "mn"). */
  lang?: string;
}

interface AuthConfig {
  username: string;
  password: string;
  /** base32 TOTP secret; when set, every password grant carries a fresh `totp` code. */
  totpSecret?: string;
  /** Which env vars the login came from (e.g. "UBCAB_BO_*"), for error messages. Never a value. */
  loginSource?: string;
  refreshToken: string;
  clientId: string;
  ssoUrl: string;
  realm: string;
  apiUrl: string;
  origin: string;
  /**
   * "service": the env account (stdio / break-glass) — failures point at `npm run login`.
   * "user": a connector user's own Keycloak session — failures mean "reconnect".
   */
  mode?: "service" | "user";
}

/** The caller's Keycloak session is gone (offline token expired/revoked). */
class SessionExpiredError extends BOError {
  constructor(status?: number, body?: unknown) {
    super(
      "BO-гийн нэвтрэлт дууссан байна. Claude → Settings → Connectors → UBEats BO → " +
        "Disconnect, дараа нь Connect дарж өөрийн BO эрхээр дахин нэвтэрнэ үү.",
      status,
      body
    );
    this.name = "SessionExpiredError";
  }
}

class UBEatsBOClient {
  private readonly apiUrl: string;
  private readonly tokenUrl: string;
  private readonly origin: string;
  private readonly clientId: string;
  private token: string | null = null;
  private tokenExpiresAt = 0;
  private refreshToken: string;
  private loginInFlight: Promise<string> | null = null;

  constructor(private readonly cfg: AuthConfig) {
    this.apiUrl = (cfg.apiUrl || DEFAULT_API_URL).replace(/\/+$/, "");
    const sso = (cfg.ssoUrl || DEFAULT_SSO_URL).replace(/\/+$/, "");
    const realm = cfg.realm || DEFAULT_REALM;
    this.tokenUrl = `${sso}/realms/${encodeURIComponent(realm)}/protocol/openid-connect/token`;
    this.origin = (cfg.origin || DEFAULT_ORIGIN).replace(/\/+$/, "");
    this.clientId = cfg.clientId || DEFAULT_CLIENT_ID;
    this.refreshToken = cfg.refreshToken || "";
  }

  get apiBaseUrl(): string {
    return this.apiUrl;
  }

  /** Latest refresh token (Keycloak may rotate it on refresh). */
  get currentRefreshToken(): string {
    return this.refreshToken;
  }

  /** Get a valid access token, re-authenticating when expired. */
  async getToken(force = false): Promise<string> {
    if (!force && this.token && Date.now() < this.tokenExpiresAt) return this.token;
    if (this.loginInFlight) return this.loginInFlight;
    this.loginInFlight = this.authenticate().finally(() => {
      this.loginInFlight = null;
    });
    return this.loginInFlight;
  }

  private async authenticate(): Promise<string> {
    const hasPassword = !!(this.cfg.username && this.cfg.password);
    let refreshErr: unknown = null;
    // 1) Offline/refresh token — the ONLY path that works once Keycloak OTP is on.
    //    Get one with `npm run login` (password + 6-digit authenticator code).
    if (this.refreshToken) {
      try {
        return await this.tokenRequest({
          grant_type: "refresh_token",
          refresh_token: this.refreshToken,
          client_id: this.clientId,
        });
      } catch (err) {
        refreshErr = err;
        if (this.cfg.mode === "user") {
          const b = err instanceof BOError ? err : null;
          // invalid_grant = session gone; anything else (network, 5xx) is transient.
          const e = (b?.body as any)?.error;
          if (e === "invalid_grant" || e === "invalid_token" || b?.status === 400 || b?.status === 401)
            throw new SessionExpiredError(b?.status, b?.body);
          throw err;
        }
        if (!hasPassword) throw otpHelp(err, "refresh");
        // fall through to password grant (works only for accounts without OTP)
      }
    }
    // 2) Password grant — legacy; Keycloak rejects it with
    //    invalid_grant "Invalid user credentials" when the user has OTP configured.
    if (hasPassword) {
      const params: Record<string, string> = {
        grant_type: "password",
        client_id: this.clientId,
        username: this.cfg.username,
        password: this.cfg.password,
        scope: "openid",
      };
      try {
        // Keycloak enforces 2FA on the BO realm: without a code the password grant
        // fails with invalid_grant «Invalid user credentials». The code is generated
        // here, never logged.
        const totp = totpFromEnv(this.cfg.totpSecret);
        if (!totp) return await this.tokenRequest(params);
        try {
          return await this.tokenRequest({ ...params, totp });
        } catch (err) {
          // A TOTP code is single-use in Keycloak, and the BO login is shared with
          // ubcab-bo-mcp (and the owner's browser). When another login spends the
          // current step's code first, ours gets invalid_grant. The realm does not
          // accept the next step's code early (learned in ubcab-bo-mcp 2026-10-06), so
          // wait for the next step to begin and log in with that fresh code. ONE retry
          // only, so a wrong password/secret cannot trip Keycloak's brute-force lockout.
          // A login can therefore take ~35 s.
          if (!isInvalidGrant(err)) throw err;
          const period = totpPeriodMs();
          const waitMs = period - (Date.now() % period) + 1_000;
          await new Promise((resolve) => setTimeout(resolve, waitMs));
          return await this.tokenRequest(
            { ...params, totp: totpFromEnv(this.cfg.totpSecret) as string },
            "retried with the next 30 s code"
          );
        }
      } catch (err) {
        throw otpHelp(err, refreshErr ? "both" : "password");
      }
    }
    throw new BOError(
      "No service-account credentials. Set the BO login (UBCAB_BO_USERNAME + UBCAB_BO_PASSWORD + " +
        "UBCAB_BO_TOTP_SECRET) or UBEATS_BO_REFRESH_TOKEN (`npm run login`). " +
        "Connector users don't need these — they sign in with their own BO account."
    );
  }

  /** Non-secret description of a token request: build, client, origin, login source, OTP. */
  private authContext(params: Record<string, string>, note?: string): string {
    const parts = [`build ${AUTH_BUILD}`, `client=${this.clientId}`, `origin=${this.origin}`, `grant=${params.grant_type}`];
    if (params.grant_type === "password") {
      parts.push(`login=${this.cfg.loginSource ?? "custom"}`, `totp=${params.totp ? "sent" : "not configured"}`);
    }
    if (note) parts.push(note);
    return parts.join(", ");
  }

  private async tokenRequest(params: Record<string, string>, note?: string): Promise<string> {
    const res = await fetch(this.tokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
        Origin: this.origin,
        Referer: `${this.origin}/`,
      },
      body: new URLSearchParams(params).toString(),
    });
    const body = await safeJson(res);
    if (!res.ok) {
      throw new BOError(
        `Keycloak auth failed (HTTP ${res.status}) [${this.authContext(params, note)}]`,
        res.status,
        body
      );
    }
    const obj = (body ?? {}) as Record<string, any>;
    const token = obj.access_token;
    if (typeof token !== "string" || !token) {
      throw new BOError("Auth succeeded but no access_token in response.", res.status, body);
    }
    this.token = token;
    const expiresIn = typeof obj.expires_in === "number" ? obj.expires_in : 300;
    // 30s safety buffer.
    this.tokenExpiresAt = Date.now() + Math.max(0, expiresIn - 30) * 1000;
    // Keep the freshest refresh token if Keycloak rotated it.
    if (typeof obj.refresh_token === "string" && obj.refresh_token) {
      this.refreshToken = obj.refresh_token;
    }
    return token;
  }

  async request(method: HttpMethod, path: string, opts: RequestOptions = {}): Promise<BOResult> {
    const url = new URL(`${this.apiUrl}${path}`);
    if (opts.query) {
      for (const [k, v] of Object.entries(opts.query)) {
        if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, String(v));
      }
    }

    const buildHeaders = (token: string): Record<string, string> => {
      const h: Record<string, string> = {
        Authorization: `Bearer ${token}`,
        Accept: "application/json, text/plain, */*",
        "Accept-Language": opts.lang || "mn",
        Origin: this.origin,
        Referer: `${this.origin}/`,
      };
      if (opts.body !== undefined) h["Content-Type"] = "application/json";
      return h;
    };

    const doRequest = (token: string) =>
      fetch(url.toString(), {
        method,
        headers: buildHeaders(token),
        body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      });

    let token = await this.getToken();
    let res = await doRequest(token);
    if (res.status === 401 || res.status === 403) {
      token = await this.getToken(true);
      res = await doRequest(token);
    }
    const body = await safeJson(res);
    if (!res.ok) {
      throw new BOError(`UBEats BO API error on ${method} ${path} (HTTP ${res.status})`, res.status, body);
    }
    return { status: res.status, ok: true, body };
  }
}

/**
 * Wrap a Keycloak auth failure with an actionable hint. Since the ubcab-bo realm
 * turned on authenticator-app OTP, password grant without a code fails with the
 * deliberately vague `invalid_grant: Invalid user credentials`, and an expired
 * offline token fails with `invalid_grant: Offline session not active` / similar.
 */
function otpHelp(err: unknown, stage: "refresh" | "password" | "both"): BOError {
  const base = err instanceof BOError ? err : new BOError(String(err));
  const hint =
    stage === "password"
      ? "Service account-ийн нууц үгээр нэвтэрч чадсангүй — BO OTP шаарддаг; UBCAB_BO_TOTP_SECRET зөв эсэхийг шалга. "
      : "Offline/refresh token хүчингүй болсон (30 хоног ашиглагдаагүй, эсвэл logout/нууц үг солигдсон). ";
  return new BOError(
    `${base.message}. ${hint}` +
      "Энэ нь зөвхөн service account (stdio / break-glass)-д хамаатай; connector хэрэглэгчид өөрийн BO эрхээр нэвтэрдэг. " +
      "Засах: UBCAB_BO_USERNAME/PASSWORD/TOTP_SECRET-ийг шалгах, эсвэл `npm run login`-оор UBEATS_BO_REFRESH_TOKEN авч Vercel-д хийгээд Redeploy.",
    base.status,
    base.body
  );
}

async function safeJson(res: Response): Promise<unknown> {
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

type ToolResult = { content: { type: "text"; text: string }[]; isError?: boolean };

function toToolResult(result: BOResult): ToolResult {
  if (result.status === 204 || result.body === null) {
    return {
      content: [
        { type: "text", text: JSON.stringify({ note: `HTTP ${result.status} — empty response.` }, null, 2) },
      ],
    };
  }
  // The UBEats BO API wraps responses as {success, data} / {success:false, error}.
  const body = result.body as any;
  const isErr = body && typeof body === "object" && body.success === false;
  return {
    content: [{ type: "text", text: JSON.stringify(body, null, 2) }],
    isError: isErr || undefined,
  };
}

async function guarded(fn: () => Promise<BOResult>): Promise<ToolResult> {
  try {
    return toToolResult(await fn());
  } catch (err) {
    if (err instanceof BOError) {
      const detail = err.body != null ? `\n${JSON.stringify(err.body, null, 2)}` : "";
      return { content: [{ type: "text", text: `${err.message}${detail}` }], isError: true };
    }
    const message = err instanceof Error ? err.message : String(err);
    return { content: [{ type: "text", text: message }], isError: true };
  }
}

// ===========================================================================
// UBEats BO client factory
// ===========================================================================

/**
 * The UBEats BO is just another client ("ubeats-bo") of the same Keycloak realm as
 * the UBCab BO, so this server logs in with the BO login — the same account, TOTP
 * secret and env names as ubcab-bo-mcp. Username, password and TOTP secret always
 * come from one source, never mixed. The UBEATS_BO_* / UBEATS_* login is only a
 * fallback for deployments that have no BO login set.
 */
function loginFromEnv(): Pick<AuthConfig, "username" | "password" | "totpSecret" | "loginSource"> {
  const env = process.env;
  if (env.UBCAB_BO_USERNAME && env.UBCAB_BO_PASSWORD) {
    return {
      username: env.UBCAB_BO_USERNAME,
      password: env.UBCAB_BO_PASSWORD,
      totpSecret: env.UBCAB_BO_TOTP_SECRET ?? "",
      loginSource: "UBCAB_BO_*",
    };
  }
  return {
    username: env.UBEATS_BO_USERNAME ?? env.UBEATS_USERNAME ?? "",
    password: env.UBEATS_BO_PASSWORD ?? env.UBEATS_PASSWORD ?? "",
    totpSecret: env.UBEATS_BO_TOTP_SECRET ?? env.UBEATS_TOTP_SECRET ?? "",
    loginSource: "UBEATS_BO_* (fallback: UBCAB_BO_USERNAME/PASSWORD not set)",
  };
}

let cachedClient: UBEatsBOClient | null = null;
function getClient(): UBEatsBOClient {
  if (!cachedClient) {
    cachedClient = new UBEatsBOClient({
      ...loginFromEnv(),
      // Not UBCAB_BO_REFRESH_TOKEN: a refresh token is bound to the client that
      // issued it, and the BO's is "ubcab-registration-bo", not "ubeats-bo".
      refreshToken: process.env.UBEATS_BO_REFRESH_TOKEN ?? process.env.UBEATS_REFRESH_TOKEN ?? "",
      clientId: process.env.UBEATS_BO_CLIENT_ID ?? process.env.UBEATS_CLIENT_ID ?? DEFAULT_CLIENT_ID,
      ssoUrl: process.env.UBEATS_BO_SSO_URL ?? DEFAULT_SSO_URL,
      realm: process.env.UBEATS_BO_REALM ?? DEFAULT_REALM,
      apiUrl: process.env.UBEATS_BO_API_URL ?? process.env.UBEATS_API_URL ?? DEFAULT_API_URL,
      origin: process.env.UBEATS_BO_ORIGIN ?? DEFAULT_ORIGIN,
    });
  }
  return cachedClient;
}

/** Vercel keeps blank variables — treat "" / whitespace as unset. */
function envOr(...namesThenFallback: string[]): string {
  const fallback = namesThenFallback[namesThenFallback.length - 1];
  for (const n of namesThenFallback.slice(0, -1)) {
    const v = (process.env[n] ?? "").trim();
    if (v) return v;
  }
  return fallback;
}

function kcConfig() {
  return {
    ssoUrl: envOr("UBEATS_BO_SSO_URL", DEFAULT_SSO_URL).replace(/\/+$/, ""),
    realm: envOr("UBEATS_BO_REALM", DEFAULT_REALM),
    clientId: envOr("UBEATS_BO_CLIENT_ID", "UBEATS_CLIENT_ID", DEFAULT_CLIENT_ID),
    origin: envOr("UBEATS_BO_ORIGIN", DEFAULT_ORIGIN).replace(/\/+$/, ""),
    apiUrl: envOr("UBEATS_BO_API_URL", "UBEATS_API_URL", DEFAULT_API_URL),
  };
}

function decodeJwt(token: string): Record<string, any> {
  try {
    return JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8"));
  } catch {
    return {};
  }
}

interface UserLogin {
  email: string;
  name: string;
  refreshToken: string;
  offline: boolean;
}

/**
 * Log a connector user into Keycloak with THEIR credentials (direct grant).
 * `otp` is optional: Keycloak's direct-grant flow asks for it only when the
 * user has an authenticator configured — even if office.ubeats.mn's own
 * browser login doesn't. Asks for offline_access so the connection survives
 * SSO logout and lasts until unused for Offline Session Idle (default 30 days).
 */
async function keycloakUserLogin(username: string, password: string, otp: string): Promise<UserLogin> {
  const kc = kcConfig();
  const tokenUrl = `${kc.ssoUrl}/realms/${encodeURIComponent(kc.realm)}/protocol/openid-connect/token`;
  const post = async (scope: string) => {
    const params: Record<string, string> = {
      grant_type: "password",
      client_id: kc.clientId,
      username,
      password,
      scope,
    };
    if (otp) {
      params.otp = otp;
      params.totp = otp; // Keycloak < 12
    }
    const res = await fetch(tokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
        Origin: kc.origin,
        Referer: `${kc.origin}/`,
      },
      body: new URLSearchParams(params).toString(),
    });
    return { res, body: ((await safeJson(res)) ?? {}) as Record<string, any> };
  };
  let { res, body } = await post("openid offline_access");
  if (!res.ok && body.error === "invalid_scope") ({ res, body } = await post("openid"));
  if (!res.ok) {
    const e = body.error;
    let msg: string;
    if (e === "invalid_grant")
      msg = otp
        ? "Имэйл, нууц үг эсвэл OTP код буруу байна. OTP 30 секунд тутам солигддог — шинэ кодоор дахин оролдоно уу."
        : "Имэйл эсвэл нууц үг буруу байна. Хэрэв таны BO данс authenticator апп (OTP) ашигладаг бол 6 оронтой кодоо доор оруулна уу.";
    else if (e === "user_disabled" || /disabled/i.test(String(body.error_description ?? "")))
      msg = "Таны BO данс идэвхгүй болсон байна.";
    else if (e === "unauthorized_client")
      msg = "BO-гийн тохиргоо нууц үгээр нэвтрэхийг хаасан байна (direct grant). UBCab tech багт хандана уу.";
    else msg = `BO нэвтрэлт амжилтгүй (HTTP ${res.status}${e ? `, ${e}` : ""}).`;
    throw new BOError(msg, res.status, body);
  }
  const claims = decodeJwt(String(body.access_token ?? ""));
  const refreshToken = String(body.refresh_token ?? "");
  if (!refreshToken) throw new BOError("Keycloak refresh token буцаасангүй.", res.status);
  return {
    email: String(claims.email || claims.preferred_username || username).toLowerCase(),
    name: String(claims.name || claims.preferred_username || username),
    refreshToken,
    offline: decodeJwt(refreshToken).typ === "Offline",
  };
}

/**
 * Per-user clients, keyed by a hash of the user's refresh token, so a warm
 * serverless instance reuses each user's 5-minute access token instead of
 * hitting Keycloak on every MCP request.
 */
const userClients = new Map<string, UBEatsBOClient>();
function userClient(refreshToken: string): UBEatsBOClient {
  const key = createHash("sha256").update(refreshToken).digest("base64url");
  let c = userClients.get(key);
  if (c) {
    userClients.delete(key); // re-insert → most recently used last
  } else {
    const kc = kcConfig();
    c = new UBEatsBOClient({
      username: "",
      password: "",
      refreshToken,
      clientId: kc.clientId,
      ssoUrl: kc.ssoUrl,
      realm: kc.realm,
      apiUrl: kc.apiUrl,
      origin: kc.origin,
      mode: "user",
    });
  }
  userClients.set(key, c);
  while (userClients.size > 200) userClients.delete(userClients.keys().next().value as string);
  return c;
}

// ===========================================================================
// Shared schema fragments
// ===========================================================================

/**
 * filter.city enum — returned verbatim by the API's own zod validator
 * (POST a bad code and it lists the allowed ones). Mongolian aimag/city codes.
 * 11 = Улаанбаатар.
 */
const CITY_CODES = [
  "11", "21", "22", "23", "41", "42", "43", "44", "45", "46", "48",
  "61", "62", "63", "64", "65", "67", "81", "82", "83", "84", "85",
] as const;

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

const objectIdSchema = z
  .string()
  .min(1)
  .describe("Mongo ObjectId (ж: 68a1f0c2b3d4e5f60718293a). Холбогдох *_search tool-ын хариунаас _id-г ав.");

function createMcpServer(client: UBEatsBOClient): McpServer {
  const server = new McpServer({ name: "ubeats-bo-mcp", version: "1.1.0" });

  const reg = (
    name: string,
    description: string,
    shape: z.ZodRawShape,
    handler: (args: any) => Promise<ToolResult>
  ) => server.tool(name, description, shape, handler);

  const API = "/v1/api";

  // -------------------------------------------------------------------------
  // Тайлангийн НИЙТЛЭГ бие (7 тайлан бүгд ижил хэлбэртэй)
  //
  //   POST {API}/reports/{report}/list
  //   body: { filter: { beginDate, endDate, city?, ...}, page, limit }
  //
  // ⚠ page/limit нь ДЭЭД ТҮВШИНД байрлана — pagination:{...} дотор БИШ.
  //   pagination:{page,limit} явуулбал чимээгүйгээр үл тоомсорлож default 20
  //   мөр буцаана (2026-08-18-нд live туршиж баталгаажуулсан).
  // ⚠ endDate нь ЯЛГААТ (exclusive) — нэг өдрийн тайлан авахдаа дараагийн
  //   өдрийг endDate болгож өг (ж: 2026-08-17 → endDate 2026-08-18).
  //   beginDate === endDate бол 996 "Begin date or end date is wrong!".
  // ⚠ Огнооны формат ЗААВАЛ YYYY-MM-DD. ISO datetime ("...T00:00:00Z")
  //   эсвэл "YYYY-MM-DD HH:mm:ss" явуулбал 996 алдаа.
  // ⚠ Танихгүй filter түлхүүрийг backend чимээгүй УРУУЛНА (алдаа өгөхгүй,
  //   шүүлт ч хийхгүй) — тул үр дүнг үргэлж нүдээр шалга.
  // -------------------------------------------------------------------------
  const reportShape = {
    beginDate: z
      .string()
      .regex(DATE_RE, "YYYY-MM-DD форматтай байх ёстой.")
      .describe("Эхлэх огноо, YYYY-MM-DD (ж: 2026-08-17). Оролцоно (inclusive)."),
    endDate: z
      .string()
      .regex(DATE_RE, "YYYY-MM-DD форматтай байх ёстой.")
      .describe(
        "Дуусах огноо, YYYY-MM-DD. ⚠ ЯЛГААТ (exclusive) — нэг өдрийн тайланд " +
          "ДАРААГИЙН өдрийг өг. beginDate-тэй тэнцүү бол 996 алдаа."
      ),
    city: z
      .enum(CITY_CODES)
      .optional()
      .describe("Бүс/хотын код. 11 = Улаанбаатар. Хоосон бол бүх бүс."),
    page: z.number().int().positive().optional().describe("Хуудасны дугаар (default 1)."),
    limit: z
      .number()
      .int()
      .positive()
      .max(1000)
      .optional()
      .describe("Нэг хуудасны мөр (default 20). Дээд хязгаар серверт байхгүй ч 200-аас дээш бол хариу маш урт болно."),
    extraFilter: z
      .record(z.any())
      .optional()
      .describe("filter объектод нэмж нийлүүлэх түлхүүрүүд (шинэ/баримтжаагүй шүүлтүүр турших)."),
  };

  const reportBody = (a: {
    beginDate: string;
    endDate: string;
    city?: string;
    page?: number;
    limit?: number;
    extraFilter?: Record<string, unknown>;
  }) => ({
    filter: {
      beginDate: a.beginDate,
      endDate: a.endDate,
      ...(a.city ? { city: a.city } : {}),
      ...(a.extraFilter ?? {}),
    },
    page: a.page ?? 1,
    limit: a.limit ?? 20,
  });

  const regReport = (
    toolName: string,
    reportPath: string,
    description: string,
    extraShape: z.ZodRawShape = {},
    extraBody: (a: any) => Record<string, unknown> = () => ({})
  ) =>
    reg(toolName, description, { ...reportShape, ...extraShape }, (a) =>
      guarded(() =>
        client.request("POST", `${API}/reports/${reportPath}/list`, {
          body: (() => {
            const b = reportBody(a);
            return { ...b, filter: { ...b.filter, ...extraBody(a) } };
          })(),
        })
      )
    );

  // =========================================================================
  // ТАЙЛАН (7)
  // =========================================================================

  regReport(
    "ubeats_report_driver_revenue",
    "driver-revenue",
    "Жолоочийн цалин бодолт (office.ubeats.mn/driver-revenue). Захиалга тус бүрээр " +
      "жолоочийн хүргэлтийн төлбөр. Хариу: {total, totalPage, page, limit, orderAmount, " +
      "deliveryAmount, docs[]}. docs мөрийн талбарууд: orderNumber, _id, menuType, merchantName, " +
      "branchName, calculatedDistance (км), customerPhone, deliveryAddress, tripId, totalValue, " +
      "deliveryPriceValue, state, createdAt, paidDate/paidTime, deliveryDate/deliveryTime, " +
      "driverRevenueDirectTransact, driverInfo, driverPhone. " +
      "orderAmount = захиалгын нийт дүн, deliveryAmount = хүргэлтийн нийт дүн.",
    {
      driverRevenueDirectTransact: z
        .boolean()
        .optional()
        .describe(
          "Жолоочийн төлбөр АВТОМАТААР олгогдсон захиалгыг л харуулах эсэх. " +
            "true = зөвхөн автомат олгогдсон, false/хоосон = бүгд. Энэ шүүлтүүр backend дээр ажилладаг нь батлагдсан."
        ),
    },
    (a) => (a.driverRevenueDirectTransact === undefined ? {} : { driverRevenueDirectTransact: a.driverRevenueDirectTransact })
  );

  regReport(
    "ubeats_report_delivery",
    "delivery-report",
    "Хүргэлтийн тайлан. Хариу нэмэлт нийлбэрүүдтэй: orderAmount, deliveryAmount, " +
      "feeChargeTotal, couponTotal, grandTotal. docs мөр: paidDate/paidTime, createdAt, " +
      "orderNumber, menuType, branchName, totalValue, deliveryPriceValue, grandTotalValue, " +
      "paymentMethod, feeCharge (мөнгөн төлөлт), coupon (купон төлөлт), ebarimtFromDriver, " +
      "deliveryEbarimt, address, deliveryStartedAt, deliveredAt, driverInfo."
  );

  regReport(
    "ubeats_report_financial",
    "financial-report",
    "Санхүүгийн тайлан (бүрэн, 29 багана). docs мөр: paidDate/paidTime, createdAt, " +
      "ubpayInvoiceId, refNumber, clientOrderNumber (Qmenu захиалгын дугаар), orderNumber, " +
      "state, menuType, merchantName, branchName, total, deliveryPrice, kitchen, itemName, " +
      "customerPhoneNumber, paymentMethod, feeCharge, coupon, couponMerchant, couponCode, " +
      "couponMeta, ebarimtSent, ebarimtNumber, ebarimtAccount, customerBank, " +
      "customerBankAccount, address, driverInfo.",
    {
      includeCancelled: z
        .boolean()
        .optional()
        .describe(
          "Цуцалсан захиалгыг нэмж оруулах эсэх (BO-гийн 'Цуцалсан захиалгыг нэмж оруулах' checkbox, " +
            "filter.state). ⚠ Backend дээр ажиллаж буй эсэхийг live баталгаажуулаагүй — үр дүнг харьцуулж шалга."
        ),
    },
    (a) => (a.includeCancelled === undefined ? {} : { state: a.includeCancelled })
  );

  regReport(
    "ubeats_report_financial_short",
    "financial-short-report",
    "Санхүүгийн тайлан (хураангуй, 14 багана). docs мөр: paidDate/paidTime, ubpayInvoiceId, " +
      "refNumber, clientOrderNumber, merchantName, branchName, total, deliveryPrice, feeCharge, " +
      "coupon, couponMerchant, couponCode, couponMeta. Тооцоо нийлүүлэхэд хамгийн хурдан хувилбар."
  );

  regReport(
    "ubeats_report_items",
    "items-report",
    "Хоолны тайлан — захиалгын мөр (item) түвшний задаргаа. docs мөр: orderCreatedAt, " +
      "orderNumber, menuType, state, providerName (ресторан), branchName, kitchenName, itemName. " +
      "Аль хоол хэр зарагдсаныг тоолоход ашигла."
  );

  regReport(
    "ubeats_report_order_duration",
    "order-duration",
    "Мерчант захиалгын хугацаа (order-duration) — захиалга хүлээн авах/бэлтгэх хугацааны тайлан. " +
      "⚠ Энэ тайлангийн meta нь зарим эрхийн түвшинд 998 permission_denied буцаадаг ч /list " +
      "ажилладаг. Багануудыг хариунаас нь уншиж тодорхойл."
  );

  regReport(
    "ubeats_report_orders",
    "orders-report",
    "Захиалгын дэлгэрэнгүй тайлан. docs мөр: orderCreatedAt, orderNumber, menuType, " +
      "providerName, branchName, state, itemName, itemTotalPrice, deliveryPrice, paymentMethod, " +
      "feeCharge, coupon, customerPhone, customerBank, customerBankAccount, ebarimtSent, " +
      "ebarimtNumber, ebarimtAccountNo, address, addressDescription, driverInfo."
  );

  reg(
    "ubeats_report_meta",
    "Тайлангийн МЕТА тодорхойлолт — багана (form.fields: key/label) ба шүүлтүүрийн жагсаалт. " +
      "GET {API}/reports/{report}/meta?action=list. Тайлангийн бүтэц өөрчлөгдсөн эсэхийг шалгах, " +
      "эсвэл шинэ тайлан судлахад ашигла.",
    {
      report: z
        .string()
        .min(1)
        .describe(
          "Тайлангийн зам, ж: driver-revenue, delivery-report, financial-report, " +
            "financial-short-report, items-report, order-duration, orders-report."
        ),
      action: z.string().optional().describe("meta-гийн action (default 'list')."),
    },
    ({ report, action }) =>
      guarded(() =>
        client.request("GET", `${API}/reports/${encodeURIComponent(report)}/meta`, {
          query: { action: action ?? "list" },
        })
      )
  );

  // =========================================================================
  // ЗАХИАЛГА — Cloud Kitchen ба Merchant (хоёр ТУСДАА сан)
  // ⚠ Нэг утас хоёуланд захиалгатай байж болно — хоёуланг нь шалга.
  // =========================================================================

  const orderListShape = {
    customerPhone: z.string().optional().describe("Захиалагчийн утасны дугаар (filter.customerPhone)."),
    page: z.number().int().positive().optional().describe("Хуудасны дугаар (default 1)."),
    limit: z.number().int().positive().max(200).optional().describe("Нэг хуудасны мөр (default 20)."),
    includeTotal: z.boolean().optional().describe("Нийт тоог буцаах эсэх (default true)."),
    payload: z
      .record(z.any())
      .optional()
      .describe("Бүтэн body-г дарж бичих (нарийн шүүлтүүр туршихад). Өгвөл бусад параметрийг үл тоомсорлоно."),
  };

  const orderListBody = (a: {
    customerPhone?: string;
    page?: number;
    limit?: number;
    includeTotal?: boolean;
    payload?: Record<string, unknown>;
  }) =>
    a.payload ?? {
      page: a.page ?? 1,
      limit: a.limit ?? 20,
      includeTotal: a.includeTotal ?? true,
      filter: { ...(a.customerPhone ? { customerPhone: a.customerPhone } : {}) },
    };

  reg(
    "ubeats_order_search",
    "CLOUD KITCHEN захиалга хайх. POST {API}/orders/list. Мөр бүрт _id ирнэ → " +
      "ubeats_order_get / ubeats_order_state_histories-д ашигла. " +
      "📌 Merchant талыг ubeats_merchant_order_search-ээр ТУСАД НЬ хай.",
    orderListShape,
    (a) => guarded(() => client.request("POST", `${API}/orders/list`, { body: orderListBody(a) }))
  );

  reg(
    "ubeats_order_get",
    "Нэг Cloud Kitchen захиалгын дэлгэрэнгүй. GET {API}/orders/{orderId}.",
    { orderId: objectIdSchema },
    ({ orderId }) => guarded(() => client.request("GET", `${API}/orders/${encodeURIComponent(orderId)}`))
  );

  reg(
    "ubeats_order_state_histories",
    "Cloud Kitchen захиалгын төлвийн түүх (үүссэн → баталсан → бэлтгэсэн → хүргэсэн). " +
      "GET {API}/orders/{orderId}/state-histories.",
    { orderId: objectIdSchema },
    ({ orderId }) =>
      guarded(() => client.request("GET", `${API}/orders/${encodeURIComponent(orderId)}/state-histories`))
  );

  reg(
    "ubeats_merchant_order_search",
    "MERCHANT захиалга хайх. POST {API}/merchant-orders/list. Мөр бүрт _id → " +
      "ubeats_merchant_order_get. 📌 Cloud Kitchen талыг ubeats_order_search-ээр тусад нь хай.",
    orderListShape,
    (a) => guarded(() => client.request("POST", `${API}/merchant-orders/list`, { body: orderListBody(a) }))
  );

  reg(
    "ubeats_merchant_order_get",
    "Нэг Merchant захиалгын дэлгэрэнгүй. GET {API}/merchant-orders/{orderId}.",
    { orderId: objectIdSchema },
    ({ orderId }) =>
      guarded(() => client.request("GET", `${API}/merchant-orders/${encodeURIComponent(orderId)}`))
  );

  reg(
    "ubeats_merchant_order_state_histories",
    "Merchant захиалгын төлвийн түүх. GET {API}/merchant-orders/{orderId}/state-histories.",
    { orderId: objectIdSchema },
    ({ orderId }) =>
      guarded(() =>
        client.request("GET", `${API}/merchant-orders/${encodeURIComponent(orderId)}/state-histories`)
      )
  );

  // =========================================================================
  // КАТАЛОГ — нийлүүлэгч / салбар / мерчант / гал тогоо / цэс / мэдэгдэл
  // Бүгд POST {API}/{resource}/list, body {filter, page, limit}
  // =========================================================================

  const catalogShape = {
    page: z.number().int().positive().optional().describe("Хуудасны дугаар (default 1)."),
    limit: z.number().int().positive().max(500).optional().describe("Нэг хуудасны мөр (default 20)."),
    filter: z.record(z.any()).optional().describe("filter объект (доорх tool бүрийн тайлбарыг үз)."),
  };
  const catalogBody = (a: { page?: number; limit?: number; filter?: Record<string, unknown> }) => ({
    filter: a.filter ?? {},
    page: a.page ?? 1,
    limit: a.limit ?? 20,
  });
  const regCatalog = (toolName: string, resource: string, description: string) =>
    reg(toolName, description, catalogShape, (a) =>
      guarded(() => client.request("POST", `${API}/${resource}/list`, { body: catalogBody(a) }))
    );

  regCatalog(
    "ubeats_provider_search",
    "providers",
    "Үйлчилгээ үзүүлэгч (Provider / ресторан брэнд) жагсаалт. POST {API}/providers/list. " +
      "docs мөр: _id, name, merchantId, payload. Мета дээр тодорхойлсон шүүлтүүр байхгүй."
  );

  regCatalog(
    "ubeats_branch_search",
    "branches",
    "Салбар жагсаалт. POST {API}/branches/list. docs мөр: _id, name, phone, merchantId, " +
      "providerId, city/cityName, status/statusName, address/addressName, hours/opens/closes, " +
      "rate, logo, coverImage, ubeatsBranch, extClient/extClientName. " +
      "Шүүлтүүр: filter.name (текст), filter.status (select)."
  );

  regCatalog(
    "ubeats_merchant_search",
    "merchants",
    "Мерчант (гэрээт хуулийн этгээд) жагсаалт. POST {API}/merchants/list. " +
      "docs мөр: _id, name, phone, logo, regNumber (улсын бүртгэлийн дугаар)."
  );

  regCatalog(
    "ubeats_kitchen_search",
    "kitchens",
    "Гал тогоо (Cloud Kitchen) жагсаалт. POST {API}/kitchens/list."
  );

  regCatalog(
    "ubeats_menu_search",
    "menus",
    "Хоолны цэс жагсаалт. POST {API}/menus/list. docs мөр: _id, title, type, branchId, " +
      "merchantId, providerId, extCatId/extId/extClient, isPublished, isDeleted, isTest, " +
      "isPreOrder, isWeekendPreOrder, isCouponUsable, isUbeatsMenu, scheduleId, deliveryId, " +
      "image/coverImage, createdAt/createdBy, updatedAt/updatedBy."
  );

  regCatalog(
    "ubeats_notification_search",
    "notifications",
    "Мэдэгдлийн түүх. POST {API}/notifications/list. " +
      "Шүүлтүүр: filter.beginDate, filter.endDate (огноо), filter.sender, filter.senderRole (select), " +
      "filter.receiverPhoneNumber (текст)."
  );

  // =========================================================================
  // ЕРӨНХИЙ PASSTHROUGH — баримтжаагүй endpoint турших
  // =========================================================================

  reg(
    "ubeats_bo_request",
    "UBEats BO API руу ДУРЫН хүсэлт (шинэ/баримтжаагүй endpoint турших). " +
      "Keycloak нэвтрэлт, Origin толгой, токен сэргээлтийг автоматаар хийнэ. " +
      "⚠ Бичих метод (POST/PUT/PATCH/DELETE) нь өгөгдөл ӨӨРЧИЛЖ болзошгүй — эхлээд GET/list-ээр шалга. " +
      "Хэрэгтэй мэдлэг: жагсаалтын endpoint-ууд POST {path}/list + body {filter,page,limit}; " +
      "мета нь GET {path}/meta?action=list.",
    {
      method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]).describe("HTTP метод."),
      path: z
        .string()
        .min(1)
        .describe("API зам, / -оор эхэлнэ (ж: /v1/api/branches/list). Host автоматаар нэмэгдэнэ."),
      query: z.record(z.any()).optional().describe("Query параметрүүд."),
      body: z.any().optional().describe("JSON body (POST/PUT/PATCH-д)."),
    },
    ({ method, path, query, body }) =>
      guarded(() =>
        client.request(method, path.startsWith("/") ? path : `/${path}`, { query, body })
      )
  );

  return server;
}

// ===========================================================================
// HTTP mode (Vercel) — OAuth 2.1 (PKCE) where each user signs in with THEIR
// OWN BO account, plus an email allowlist.
//
//   Claude → /authorize (our page: BO email + password + optional OTP)
//          → Keycloak direct grant (scope offline_access) with those creds
//          → allowlist check on the VERIFIED email from Keycloak's token
//          → sealed auth code → /token → sealed access + refresh tokens.
//
// The user's Keycloak refresh token travels only inside AES-256-GCM sealed
// tokens (key derived from UBEATS_BO_MCP_AUTH_TOKEN). The password is used
// once for the Keycloak call and never stored or logged. Every MCP request
// runs with the caller's own BO permissions.
//
// Break-glass: the raw UBEATS_BO_MCP_AUTH_TOKEN as a bearer (or /mcp/<token>)
// still works and uses the env service account (UBEATS_BO_REFRESH_TOKEN).
// ===========================================================================

const ACCESS_TTL_MS = 12 * 60 * 60 * 1000; // 12h; the allowlist is re-checked on every request anyway
const REFRESH_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30d ≈ Keycloak Offline Session Idle
const CODE_TTL_MS = 5 * 60 * 1000;

function signingSecret(): string {
  return (process.env.UBEATS_BO_MCP_AUTH_TOKEN ?? "").trim();
}

function constantTimeEquals(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  if (x.length !== y.length) return false;
  return timingSafeEqual(x, y);
}

/** Break-glass bearer: the raw UBEATS_BO_MCP_AUTH_TOKEN (uses env credentials). */
function tokenMatches(provided: string | null | undefined): boolean {
  const expected = signingSecret();
  if (!expected || !provided) return false; // fail closed
  return constantTimeEquals(provided, expected);
}

/**
 * UBEATS_BO_ALLOWED_EMAILS: comma/space separated. Entries are full emails,
 * "@domain.mn" (whole domain) or "*" (any BO user). Empty → nobody (fail closed).
 */
function allowlist(): string[] {
  return (process.env.UBEATS_BO_ALLOWED_EMAILS ?? "")
    .split(/[,;\s]+/)
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

function emailAllowed(email: string): boolean {
  const list = allowlist();
  if (list.length === 0) return false;
  const e = email.trim().toLowerCase();
  if (!e.includes("@")) return list.includes("*");
  const domain = e.slice(e.indexOf("@"));
  return list.some((entry) => entry === "*" || (entry.startsWith("@") ? entry === domain : entry === e));
}

// ---- sealed tokens (AES-256-GCM) -----------------------------------------

function sealKey(): Buffer {
  return createHash("sha256").update(`ubeats-bo-mcp/seal/v1/${signingSecret()}`).digest();
}

function seal(obj: Record<string, unknown>): string {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", sealKey(), iv);
  const ct = Buffer.concat([c.update(JSON.stringify(obj), "utf8"), c.final()]);
  return `u1.${Buffer.concat([iv, ct, c.getAuthTag()]).toString("base64url")}`;
}

function unseal(token: string | null | undefined, type: "code" | "at" | "rt"): Record<string, any> | null {
  if (!token || !token.startsWith("u1.") || !signingSecret()) return null;
  try {
    const raw = Buffer.from(token.slice(3), "base64url");
    if (raw.length < 12 + 16 + 2) return null;
    const d = createDecipheriv("aes-256-gcm", sealKey(), raw.subarray(0, 12));
    d.setAuthTag(raw.subarray(raw.length - 16));
    const pt = Buffer.concat([d.update(raw.subarray(12, raw.length - 16)), d.final()]).toString("utf8");
    const obj = JSON.parse(pt);
    if (obj.t !== type) return null;
    if (typeof obj.exp !== "number" || Date.now() > obj.exp) return null;
    return obj;
  } catch {
    return null; // tampered, wrong key, or garbage
  }
}

function mintTokens(email: string, refreshToken: string) {
  const now = Date.now();
  return {
    access_token: seal({ t: "at", em: email, rt: refreshToken, exp: now + ACCESS_TTL_MS }),
    refresh_token: seal({ t: "rt", em: email, rt: refreshToken, exp: now + REFRESH_TTL_MS }),
    token_type: "Bearer",
    expires_in: Math.floor(ACCESS_TTL_MS / 1000),
    scope: "mcp",
  };
}

// ---- small HTTP helpers --------------------------------------------------

function bearerToken(req: IncomingMessage): string | null {
  const raw = req.headers["authorization"] ?? "";
  const header = Array.isArray(raw) ? raw[0] : raw;
  const match = /^Bearer\s+(.+)$/i.exec(header);
  return match ? match[1] : null;
}

/** Token embedded in the path, e.g. /mcp/<token>. */
function pathToken(url: URL): string | null {
  const segments = url.pathname.split("/").filter(Boolean);
  if (segments.length >= 2 && segments[0] === "mcp") return segments[1];
  return null;
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store" });
  res.end(JSON.stringify(body));
}

function sendHtml(res: ServerResponse, status: number, html: string): void {
  res.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https: http://localhost:* http://127.0.0.1:*; frame-ancestors 'none'",
    "Referrer-Policy": "no-referrer",
  });
  res.end(html);
}

async function readBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const raw = Buffer.concat(chunks).toString("utf8");
  if (!raw) return undefined;
  try {
    return JSON.parse(raw);
  } catch {
    return undefined;
  }
}

async function readForm(req: IncomingMessage): Promise<Record<string, string>> {
  const pre = (req as IncomingMessage & { body?: unknown }).body;
  if (pre && typeof pre === "object" && !Buffer.isBuffer(pre)) {
    return pre as Record<string, string>;
  }
  let raw = typeof pre === "string" ? pre : "";
  if (!raw) {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    raw = Buffer.concat(chunks).toString("utf8");
  }
  const out: Record<string, string> = {};
  for (const [k, v] of new URLSearchParams(raw)) out[k] = v;
  return out;
}

function pkceOk(verifier: string, challenge: string): boolean {
  const h = createHash("sha256").update(verifier).digest("base64url");
  return constantTimeEquals(h, challenge);
}

function baseUrl(req: IncomingMessage): string {
  const proto = (req.headers["x-forwarded-proto"] as string) || "https";
  const host = req.headers.host ?? "localhost";
  return `${proto}://${host}`;
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c] as string)
  );
}

const OAUTH_PARAMS = ["client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method", "scope", "response_type"];

/** Only hand codes to https redirect targets (or loopback for local clients). */
function redirectAllowed(uri: string): boolean {
  try {
    const u = new URL(uri);
    if (u.protocol === "https:") return true;
    return u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1");
  } catch {
    return false;
  }
}

function authorizePage(params: URLSearchParams, opts: { error?: string; email?: string; askOtp?: boolean } = {}): string {
  const hidden = OAUTH_PARAMS.map(
    (k) => `<input type="hidden" name="${k}" value="${escapeHtml(params.get(k) ?? "")}">`
  ).join("\n");
  const email = opts.email ?? "";
  return `<!doctype html><html lang="mn"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>UBEats BO — Нэвтрэх</title>
<style>
:root{color-scheme:light dark;--fg:#1a1a1a;--muted:#666;--bd:#ccc;--bg:#fff;--btn:#1f8f4e;--err:#b00020}
@media (prefers-color-scheme:dark){:root{--fg:#eee;--muted:#9a9a9a;--bd:#444;--bg:#161616;--err:#ff6b81}}
body{font-family:ui-sans-serif,system-ui,-apple-system,sans-serif;max-width:400px;margin:4rem auto;padding:0 1.25rem;color:var(--fg);background:var(--bg)}
h1{font-size:1.25rem;margin-bottom:.25rem}label{display:block;margin:1rem 0 .35rem;font-size:.9rem}
input[type=email],input[type=password],input[type=text]{width:100%;padding:.6rem;border:1px solid var(--bd);border-radius:8px;font-size:1rem;box-sizing:border-box;background:transparent;color:inherit}
button{margin-top:1.25rem;width:100%;padding:.65rem;border:0;border-radius:8px;background:var(--btn);color:#fff;font-size:1rem;cursor:pointer}
.err{color:var(--err);font-size:.9rem;margin-top:.75rem}.muted{color:var(--muted);font-size:.85rem;margin-top:.5rem;line-height:1.4}
.opt{font-weight:400;color:var(--muted)}</style></head>
<body><h1>UBEats Backoffice MCP</h1>
<p class="muted">office.ubeats.mn-д нэвтэрдэг <b>өөрийн BO эрхээрээ</b> нэвтэрнэ үү.</p>
<form method="POST" action="/authorize">${hidden}
<label for="em">Имэйл</label>
<input id="em" type="email" name="email" autocomplete="username" value="${escapeHtml(email)}" ${email ? "" : "autofocus"} required>
<label for="pw">Нууц үг</label>
<input id="pw" type="password" name="password" autocomplete="current-password" ${email && !opts.askOtp ? "autofocus" : ""} required>
<label for="otp">OTP код <span class="opt">${opts.askOtp ? "— authenticator апп дээрх 6 орон" : "(шаардлагатай бол)"}</span></label>
<input id="otp" type="text" name="otp" inputmode="numeric" pattern="[0-9]{6,8}" maxlength="8" autocomplete="one-time-code" ${opts.askOtp ? "autofocus" : ""} placeholder="123456">
${opts.error ? `<div class="err">${escapeHtml(opts.error)}</div>` : ""}
<button type="submit">Нэвтрэх ба зөвшөөрөх</button></form>
<p class="muted">Холболт таны эрхээр ажиллана — BO дээр танд харагддаг өгөгдөл л нээгдэнэ. Нууц үг хадгалагдахгүй; зөвхөн нэг удаа Keycloak руу дамжина.</p>
</body></html>`;
}

/** Write a JSON-RPC 401 that tells the client how to (re)authorize. */
function sendUnauthorized(req: IncomingMessage, res: ServerResponse, message = "Unauthorized"): void {
  res.writeHead(401, {
    "Content-Type": "application/json",
    "WWW-Authenticate": `Bearer resource_metadata="${baseUrl(req)}/.well-known/oauth-protected-resource"`,
  });
  res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32001, message }, id: null }));
}

export default async function handler(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
  const path = url.pathname;
  const method = req.method ?? "GET";

  if (method === "GET" && path === "/health") {
    sendJson(res, 200, {
      status: "ok",
      server: "ubeats-bo-mcp",
      auth: "per-user BO login (Keycloak) + email allowlist",
      allowlistConfigured: allowlist().length > 0,
      signingSecretConfigured: !!signingSecret(),
      build: AUTH_BUILD,
      serviceAccountConfigured:
        !!envOr("UBEATS_BO_REFRESH_TOKEN", "UBEATS_REFRESH_TOKEN", "") ||
        !!(loginFromEnv().username && loginFromEnv().password),
    });
    return;
  }

  // ---- OAuth discovery metadata ----
  if (method === "GET" && path.startsWith("/.well-known/oauth-protected-resource")) {
    const base = baseUrl(req);
    sendJson(res, 200, { resource: `${base}/mcp`, authorization_servers: [base], scopes_supported: ["mcp"] });
    return;
  }
  if (
    method === "GET" &&
    (path.startsWith("/.well-known/oauth-authorization-server") || path === "/.well-known/openid-configuration")
  ) {
    const base = baseUrl(req);
    sendJson(res, 200, {
      issuer: base,
      authorization_endpoint: `${base}/authorize`,
      token_endpoint: `${base}/token`,
      registration_endpoint: `${base}/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
      scopes_supported: ["mcp"],
    });
    return;
  }

  // ---- OAuth dynamic client registration (public clients, PKCE) ----
  if (method === "POST" && path === "/register") {
    let reg = (req as IncomingMessage & { body?: unknown }).body as Record<string, unknown> | string | undefined;
    if (reg === undefined || typeof reg === "string") reg = (await readBody(req)) as Record<string, unknown>;
    const redirectUris = Array.isArray((reg as any)?.redirect_uris) ? (reg as any).redirect_uris : [];
    sendJson(res, 201, {
      client_id: "ubeats-bo-mcp",
      client_id_issued_at: Math.floor(Date.now() / 1000),
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      redirect_uris: redirectUris,
    });
    return;
  }

  // ---- OAuth authorize: the user's own BO login + allowlist ----
  if (path === "/authorize") {
    if (!signingSecret()) {
      sendJson(res, 500, { error: "server_error", error_description: "UBEATS_BO_MCP_AUTH_TOKEN not set" });
      return;
    }
    if (method === "GET") {
      sendHtml(res, 200, authorizePage(url.searchParams));
      return;
    }
    if (method === "POST") {
      const form = await readForm(req);
      const params = new URLSearchParams();
      for (const k of OAUTH_PARAMS) if (form[k] !== undefined) params.set(k, form[k]);
      const redirectUri = form.redirect_uri ?? "";
      const codeChallenge = form.code_challenge ?? "";
      const email = (form.email ?? "").trim();
      const otp = (form.otp ?? "").replace(/\s+/g, "");
      if (!redirectUri || !redirectAllowed(redirectUri) || !codeChallenge || form.code_challenge_method !== "S256") {
        sendHtml(res, 400, authorizePage(params, { error: "Буруу хүсэлт (https redirect_uri ба PKCE S256 шаардлагатай).", email }));
        return;
      }
      if (allowlist().length === 0) {
        sendHtml(res, 503, authorizePage(params, { error: "Сервер дээр зөвшөөрөгдсөн имэйлийн жагсаалт (UBEATS_BO_ALLOWED_EMAILS) тохируулаагүй байна.", email }));
        return;
      }
      // Cheap pre-check on the typed email so disallowed users don't hit Keycloak.
      if (!emailAllowed(email)) {
        sendHtml(res, 403, authorizePage(params, { error: "Энэ имэйлд MCP-д хандах зөвшөөрөл олгогдоогүй байна.", email }));
        return;
      }
      if (otp && !/^\d{6,8}$/.test(otp)) {
        sendHtml(res, 400, authorizePage(params, { error: "OTP нь 6 оронтой тоо байна.", email, askOtp: true }));
        return;
      }
      let login: UserLogin;
      try {
        login = await keycloakUserLogin(email, form.password ?? "", otp);
      } catch (err) {
        const msg = err instanceof Error && err.message ? err.message : String(err);
        const isCred = err instanceof BOError && (err.body as any)?.error === "invalid_grant";
        sendHtml(res, 401, authorizePage(params, { error: msg, email, askOtp: isCred }));
        return;
      }
      // Re-check against the identity Keycloak actually verified.
      if (!emailAllowed(login.email)) {
        sendHtml(res, 403, authorizePage(params, { error: "Энэ имэйлд MCP-д хандах зөвшөөрөл олгогдоогүй байна.", email }));
        return;
      }
      const code = seal({
        t: "code",
        ru: redirectUri,
        cc: codeChallenge,
        em: login.email,
        rt: login.refreshToken,
        exp: Date.now() + CODE_TTL_MS,
      });
      const sep = redirectUri.includes("?") ? "&" : "?";
      let location = `${redirectUri}${sep}code=${encodeURIComponent(code)}`;
      if (form.state) location += `&state=${encodeURIComponent(form.state)}`;
      res.writeHead(302, { Location: location, "Cache-Control": "no-store" });
      res.end();
      return;
    }
  }

  // ---- OAuth token endpoint: authorization_code + refresh_token ----
  if (method === "POST" && path === "/token") {
    if (!signingSecret()) {
      sendJson(res, 500, { error: "server_error", error_description: "UBEATS_BO_MCP_AUTH_TOKEN not set" });
      return;
    }
    const form = await readForm(req);

    if (form.grant_type === "authorization_code") {
      const code = unseal(form.code, "code");
      if (!code) {
        sendJson(res, 400, { error: "invalid_grant", error_description: "code invalid or expired" });
        return;
      }
      if (form.redirect_uri && form.redirect_uri !== code.ru) {
        sendJson(res, 400, { error: "invalid_grant", error_description: "redirect_uri mismatch" });
        return;
      }
      if (!form.code_verifier || !pkceOk(form.code_verifier, String(code.cc))) {
        sendJson(res, 400, { error: "invalid_grant", error_description: "PKCE verification failed" });
        return;
      }
      if (!emailAllowed(String(code.em ?? ""))) {
        sendJson(res, 403, { error: "access_denied", error_description: "email is not allowed" });
        return;
      }
      sendJson(res, 200, mintTokens(String(code.em), String(code.rt)));
      return;
    }

    if (form.grant_type === "refresh_token") {
      const rt = unseal(form.refresh_token, "rt");
      if (!rt || !emailAllowed(String(rt.em ?? ""))) {
        sendJson(res, 400, { error: "invalid_grant", error_description: "refresh token invalid, expired or email no longer allowed" });
        return;
      }
      // Prove the user's Keycloak session is still alive before re-issuing —
      // force a real Keycloak round-trip, not the cached 5-minute access token.
      const client = userClient(String(rt.rt));
      try {
        await client.getToken(true);
      } catch (err) {
        if (err instanceof SessionExpiredError) {
          sendJson(res, 400, { error: "invalid_grant", error_description: "BO session expired — sign in again" });
        } else {
          sendJson(res, 503, { error: "temporarily_unavailable", error_description: err instanceof Error ? err.message : String(err) });
        }
        return;
      }
      sendJson(res, 200, mintTokens(String(rt.em), client.currentRefreshToken || String(rt.rt)));
      return;
    }

    sendJson(res, 400, { error: "unsupported_grant_type" });
    return;
  }

  // ---- Non-MCP GETs → 404 ----
  if (method === "GET") {
    sendJson(res, 404, { error: "Not found. POST to /mcp for the MCP endpoint." });
    return;
  }
  if (method !== "POST") {
    sendJson(res, 405, { jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed" }, id: null });
    return;
  }

  // ---- MCP endpoint (POST /mcp or /mcp/<token>) ----
  if (!signingSecret()) {
    sendJson(res, 500, {
      jsonrpc: "2.0",
      error: { code: -32001, message: "Server misconfigured: UBEATS_BO_MCP_AUTH_TOKEN not set." },
      id: null,
    });
    return;
  }
  const bearer = bearerToken(req);
  let client: UBEatsBOClient | null = null;
  const at = unseal(bearer, "at");
  if (at) {
    if (!emailAllowed(String(at.em ?? ""))) {
      sendUnauthorized(req, res, "Энэ имэйлийн MCP эрх цуцлагдсан байна.");
      return;
    }
    client = userClient(String(at.rt));
    // Fail at the HTTP layer (401 → Claude prompts to reconnect) rather than
    // inside every tool call when the user's BO session is gone.
    try {
      await client.getToken();
    } catch (err) {
      if (err instanceof SessionExpiredError) {
        sendUnauthorized(req, res, err.message);
        return;
      }
      // transient Keycloak trouble: let the tool calls surface it
    }
  } else if (tokenMatches(bearer) || tokenMatches(pathToken(url))) {
    client = getClient(); // break-glass: env service account
  }
  if (!client) {
    sendUnauthorized(req, res);
    return;
  }

  let body = (req as IncomingMessage & { body?: unknown }).body;
  if (typeof body === "string") {
    try {
      body = JSON.parse(body);
    } catch {
      body = undefined;
    }
  }
  if (body === undefined) body = await readBody(req);

  try {
    const mcp = createMcpServer(client);
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });
    res.on("close", () => {
      void transport.close();
      void mcp.close();
    });
    await mcp.connect(transport);
    await transport.handleRequest(req, res, body);
  } catch (err) {
    if (!res.headersSent) {
      sendJson(res, 500, {
        jsonrpc: "2.0",
        error: { code: -32603, message: err instanceof Error ? err.message : String(err) },
        id: null,
      });
    }
  }
}

// ===========================================================================
// stdio mode (local)
// ===========================================================================

async function startStdio(): Promise<void> {
  const server = createMcpServer(getClient());
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("ubeats-bo-mcp server running on stdio");
}

function isRunDirectly(): boolean {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return import.meta.url === pathToFileURL(entry).href;
  } catch {
    return false;
  }
}

if (isRunDirectly()) {
  startStdio().catch((err) => {
    console.error("Fatal error starting ubeats-bo-mcp:", err);
    process.exit(1);
  });
}
