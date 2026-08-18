#!/usr/bin/env node
/**
 * UBEats Backoffice MCP server — single self-contained entry point.
 *
 * Backend for office.ubeats.mn ("UBEats Backoffice V2"), API host
 * https://ubeats-bo-api.ubcabtech.com.
 *
 * Runs two ways from this one file:
 *   - HTTP mode  (Vercel): serves the MCP over Streamable HTTP at /mcp,
 *     guarded by a bearer token + OAuth 2.1 (PKCE).
 *   - stdio mode (local / Claude Desktop): when run directly.
 *
 * SELF-CONTAINED ON PURPOSE: no relative imports, so neither Vercel's bundler
 * nor Node's ESM loader has to resolve sibling ".ts"/".js" files.
 *
 * Auth (verified 2026-08-18 against a live office.ubeats.mn session):
 *   Keycloak SSO, issuer https://sso.ubcabtech.com/realms/ubcab-bo
 *   OIDC client (azp): "ubeats-bo"
 *   Token endpoint: {SSO_URL}/realms/{REALM}/protocol/openid-connect/token
 *   Access tokens live ~5 min; this server caches until ~30s before expiry and
 *   silently re-auths (refresh_token first, then password grant).
 *   Every API call sends Origin/Referer = https://office.ubeats.mn so the BO's
 *   allowed-origins check passes.
 *
 * Env:
 *   UBEATS_BO_USERNAME, UBEATS_BO_PASSWORD   password-grant creds (recommended)
 *   UBEATS_BO_REFRESH_TOKEN                  alternative to username/password
 *   UBEATS_BO_CLIENT_ID                      OIDC client (default ubeats-bo)
 *   UBEATS_BO_SSO_URL                        Keycloak base (default https://sso.ubcabtech.com)
 *   UBEATS_BO_REALM                          realm (default ubcab-bo)
 *   UBEATS_BO_API_URL                        API base (default https://ubeats-bo-api.ubcabtech.com)
 *   UBEATS_BO_ORIGIN                         Origin/Referer (default https://office.ubeats.mn)
 *   UBEATS_BO_MCP_AUTH_TOKEN                 required in HTTP mode (fails closed)
 *
 * UBEATS_USERNAME / UBEATS_PASSWORD are accepted as fallbacks so this server can
 * share the env already set up for ubcab-bo-mcp.
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { timingSafeEqual, createHmac, createHash } from "node:crypto";
import { pathToFileURL } from "node:url";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

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

interface RequestOptions {
  query?: Record<string, unknown>;
  body?: unknown;
  /** Override Accept-Language (default "mn"). */
  lang?: string;
}

interface AuthConfig {
  username: string;
  password: string;
  refreshToken: string;
  clientId: string;
  ssoUrl: string;
  realm: string;
  apiUrl: string;
  origin: string;
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
    // Prefer refresh_token (cheaper, avoids re-sending creds); fall back to password.
    if (this.refreshToken) {
      try {
        return await this.tokenRequest({
          grant_type: "refresh_token",
          refresh_token: this.refreshToken,
          client_id: this.clientId,
        });
      } catch (err) {
        if (!hasPassword) throw err; // nothing else to try
        // refresh expired/rotated — fall through to password grant
      }
    }
    if (hasPassword) {
      return this.tokenRequest({
        grant_type: "password",
        client_id: this.clientId,
        username: this.cfg.username,
        password: this.cfg.password,
        scope: "openid",
      });
    }
    throw new BOError(
      "No credentials. Set UBEATS_BO_USERNAME + UBEATS_BO_PASSWORD, or UBEATS_BO_REFRESH_TOKEN."
    );
  }

  private async tokenRequest(params: Record<string, string>): Promise<string> {
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
      throw new BOError(`Keycloak auth failed (HTTP ${res.status})`, res.status, body);
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

let cachedClient: UBEatsBOClient | null = null;
function getClient(): UBEatsBOClient {
  if (!cachedClient) {
    cachedClient = new UBEatsBOClient({
      username: process.env.UBEATS_BO_USERNAME ?? process.env.UBEATS_USERNAME ?? "",
      password: process.env.UBEATS_BO_PASSWORD ?? process.env.UBEATS_PASSWORD ?? "",
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

function createMcpServer(): McpServer {
  const server = new McpServer({ name: "ubeats-bo-mcp", version: "1.0.0" });
  const client = getClient();

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
// HTTP mode (Vercel) — bearer-guarded Streamable HTTP + OAuth 2.1 (PKCE)
// ===========================================================================

function tokenMatches(provided: string | null | undefined): boolean {
  const expected = process.env.UBEATS_BO_MCP_AUTH_TOKEN;
  if (!expected || !provided) return false; // fail closed
  const a = Buffer.from(provided);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

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
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

function sendHtml(res: ServerResponse, status: number, html: string): void {
  res.writeHead(status, { "Content-Type": "text/html; charset=utf-8" });
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

function hmac(data: string): string {
  return createHmac("sha256", process.env.UBEATS_BO_MCP_AUTH_TOKEN ?? "").update(data).digest("base64url");
}

function signPayload(obj: unknown): string {
  const p = Buffer.from(JSON.stringify(obj)).toString("base64url");
  return `${p}.${hmac(p)}`;
}

function verifySigned(token: string): Record<string, any> | null {
  const dot = token.lastIndexOf(".");
  if (dot < 0) return null;
  const p = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const expected = hmac(p);
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  try {
    const obj = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
    if (typeof obj.exp === "number" && Date.now() > obj.exp) return null;
    return obj;
  } catch {
    return null;
  }
}

function mintAuthCode(redirectUri: string, codeChallenge: string): string {
  return signPayload({ t: "code", ru: redirectUri, cc: codeChallenge, exp: Date.now() + 5 * 60 * 1000 });
}

function mintAccessToken(): string {
  return signPayload({ t: "at", sub: "ubcab-bo", exp: Date.now() + 30 * 24 * 60 * 60 * 1000 });
}

function isValidAccessToken(token: string | null | undefined): boolean {
  if (!token) return false;
  const obj = verifySigned(token);
  return !!obj && obj.t === "at";
}

function pkceOk(verifier: string, challenge: string): boolean {
  const h = createHash("sha256").update(verifier).digest("base64url");
  const a = Buffer.from(h);
  const b = Buffer.from(challenge);
  return a.length === b.length && timingSafeEqual(a, b);
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

function authorizePage(params: URLSearchParams, error?: string): string {
  const hidden = ["client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method", "scope", "response_type"]
    .map((k) => `<input type="hidden" name="${k}" value="${escapeHtml(params.get(k) ?? "")}">`)
    .join("\n");
  return `<!doctype html><html lang="mn"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>UBEats BO MCP — Нэвтрэх</title>
<style>body{font-family:ui-sans-serif,system-ui,-apple-system,sans-serif;max-width:380px;margin:5rem auto;padding:0 1.25rem;color:#1a1a1a}
h1{font-size:1.25rem}label{display:block;margin:1rem 0 .35rem;font-size:.9rem}
input[type=password]{width:100%;padding:.6rem;border:1px solid #ccc;border-radius:8px;font-size:1rem;box-sizing:border-box}
button{margin-top:1rem;width:100%;padding:.65rem;border:0;border-radius:8px;background:#1a1a1a;color:#fff;font-size:1rem;cursor:pointer}
.err{color:#b00020;font-size:.9rem;margin-top:.75rem}.muted{color:#666;font-size:.85rem;margin-top:1rem}</style></head>
<body><h1>UBEats BO MCP холболт</h1><p class="muted">UBEats Backoffice MCP сервер рүү холбогдохын тулд хандах түлхүүрээ оруулна уу.</p>
<form method="POST" action="/authorize">${hidden}
<label for="pw">Хандах түлхүүр (access token)</label>
<input id="pw" type="password" name="password" autocomplete="off" autofocus required>
${error ? `<div class="err">${escapeHtml(error)}</div>` : ""}
<button type="submit">Зөвшөөрөх</button></form></body></html>`;
}

export default async function handler(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
  const path = url.pathname;
  const method = req.method ?? "GET";

  if (method === "GET" && path === "/health") {
    sendJson(res, 200, { status: "ok", server: "ubeats-bo-mcp" });
    return;
  }

  // ---- OAuth discovery metadata ----
  if (method === "GET" && path === "/.well-known/oauth-protected-resource") {
    const base = baseUrl(req);
    sendJson(res, 200, { resource: `${base}/mcp`, authorization_servers: [base] });
    return;
  }
  if (
    method === "GET" &&
    (path === "/.well-known/oauth-authorization-server" || path === "/.well-known/openid-configuration")
  ) {
    const base = baseUrl(req);
    sendJson(res, 200, {
      issuer: base,
      authorization_endpoint: `${base}/authorize`,
      token_endpoint: `${base}/token`,
      registration_endpoint: `${base}/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
      scopes_supported: ["mcp"],
    });
    return;
  }

  // ---- OAuth dynamic client registration ----
  if (method === "POST" && path === "/register") {
    let reg = (req as IncomingMessage & { body?: unknown }).body as Record<string, unknown> | string | undefined;
    if (reg === undefined || typeof reg === "string") reg = (await readBody(req)) as Record<string, unknown>;
    const redirectUris = Array.isArray((reg as any)?.redirect_uris) ? (reg as any).redirect_uris : [];
    sendJson(res, 201, {
      client_id: "ubeats-bo-mcp",
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code"],
      response_types: ["code"],
      redirect_uris: redirectUris,
    });
    return;
  }

  // ---- OAuth authorize ----
  if (path === "/authorize") {
    if (!process.env.UBEATS_BO_MCP_AUTH_TOKEN) {
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
      for (const k of ["client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method", "scope", "response_type"]) {
        if (form[k] !== undefined) params.set(k, form[k]);
      }
      const redirectUri = form.redirect_uri ?? "";
      const codeChallenge = form.code_challenge ?? "";
      if (!redirectUri || !codeChallenge || form.code_challenge_method !== "S256") {
        sendHtml(res, 400, authorizePage(params, "Буруу хүсэлт (PKCE S256 шаардлагатай)."));
        return;
      }
      if (!tokenMatches(form.password)) {
        sendHtml(res, 401, authorizePage(params, "Хандах түлхүүр буруу байна."));
        return;
      }
      const code = mintAuthCode(redirectUri, codeChallenge);
      const sep = redirectUri.includes("?") ? "&" : "?";
      let location = `${redirectUri}${sep}code=${encodeURIComponent(code)}`;
      if (form.state) location += `&state=${encodeURIComponent(form.state)}`;
      res.writeHead(302, { Location: location });
      res.end();
      return;
    }
  }

  // ---- OAuth token exchange ----
  if (method === "POST" && path === "/token") {
    const form = await readForm(req);
    if (form.grant_type !== "authorization_code") {
      sendJson(res, 400, { error: "unsupported_grant_type" });
      return;
    }
    const decoded = form.code ? verifySigned(form.code) : null;
    if (!decoded || decoded.t !== "code") {
      sendJson(res, 400, { error: "invalid_grant" });
      return;
    }
    if (form.redirect_uri && form.redirect_uri !== decoded.ru) {
      sendJson(res, 400, { error: "invalid_grant", error_description: "redirect_uri mismatch" });
      return;
    }
    if (!form.code_verifier || !pkceOk(form.code_verifier, decoded.cc)) {
      sendJson(res, 400, { error: "invalid_grant", error_description: "PKCE verification failed" });
      return;
    }
    sendJson(res, 200, {
      access_token: mintAccessToken(),
      token_type: "Bearer",
      expires_in: 30 * 24 * 60 * 60,
      scope: "mcp",
    });
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
  if (!process.env.UBEATS_BO_MCP_AUTH_TOKEN) {
    sendJson(res, 500, {
      jsonrpc: "2.0",
      error: { code: -32001, message: "Server misconfigured: UBEATS_BO_MCP_AUTH_TOKEN not set." },
      id: null,
    });
    return;
  }
  const bearer = bearerToken(req);
  const authed = isValidAccessToken(bearer) || tokenMatches(bearer) || tokenMatches(pathToken(url));
  if (!authed) {
    res.writeHead(401, {
      "Content-Type": "application/json",
      "WWW-Authenticate": `Bearer resource_metadata="${baseUrl(req)}/.well-known/oauth-protected-resource"`,
    });
    res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32001, message: "Unauthorized" }, id: null }));
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
    const mcp = createMcpServer();
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
  const server = createMcpServer();
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
