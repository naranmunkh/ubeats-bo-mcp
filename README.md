# ubeats-bo-mcp

MCP server for the **UBEats Backoffice** (`office.ubeats.mn`, API host
`https://ubeats-bo-api.ubcabtech.com`). Built on the same pattern as
`ubcab-bo-mcp`: one self-contained `api/index.ts` that runs either over stdio
(local / Claude Desktop) or as a bearer-guarded Streamable HTTP endpoint on
Vercel.

## Auth — OTP (authenticator app) since 2026-10

The `ubcab-bo` realm now requires a 6-digit authenticator-app code at login.
A server can't produce a 30-second code, so **password grant no longer works**
(Keycloak answers `invalid_grant: Invalid user credentials`).

Production auth is an **offline refresh token** you mint once on your Mac:

```bash
npm run login
```

It asks for the 6-digit code (password is read from `.env` if present,
otherwise prompted without echo), requests `scope=openid offline_access`,
proves the token by refreshing it and calling the API, then writes
`UBEATS_BO_REFRESH_TOKEN` into `.env` and copies it to the clipboard. The token
is never printed.

Then in Vercel → `ubeats-bo-mcp` → Settings → Environment Variables:
set `UBEATS_BO_REFRESH_TOKEN` (Production + Preview), delete
`UBEATS_BO_PASSWORD`, and **Redeploy** (env changes need a new deployment).

The offline token lives until it goes unused for the realm's *Offline Session
Idle* (Keycloak default 30 days); every MCP call extends it. It is revoked by a
password change or an admin "sign out all sessions". When it dies the tools
return an error that says exactly this — rerun `npm run login`.

`npm run login:bo` does the same for the UBCab BO (`bo-mcp`, client
`ubcab-registration-bo`) and writes `UBCAB_BO_REFRESH_TOKEN` — paste that into
the **bo-mcp** Vercel project instead.

### Keycloak details

Verified 2026-08-18 against a live BO session:

| | |
|---|---|
| Issuer | `https://sso.ubcabtech.com/realms/ubcab-bo` |
| OIDC client (`azp`) | `ubeats-bo` |
| Token endpoint | `{SSO}/realms/{REALM}/protocol/openid-connect/token` |
| Origin/Referer sent | `https://office.ubeats.mn` |

Access tokens live ~5 minutes; the server caches until ~30s before expiry and
re-auths silently (refresh_token first, then password grant).

## Tools (21)

### Reports (8)

All seven report endpoints share one body shape:

```
POST /v1/api/reports/{report}/list
{ "filter": { "beginDate": "2026-08-17", "endDate": "2026-08-18", "city": "11" },
  "page": 1, "limit": 20 }
```

Three things that are easy to get wrong (all confirmed by live testing):

1. **`page` / `limit` are top-level, not inside `pagination`.** Sending
   `pagination: {page, limit}` is silently ignored and you get the default 20 rows.
2. **`endDate` is exclusive.** For a single day pass the *next* day.
   `beginDate === endDate` returns `996 "Begin date or end date is wrong!"`.
3. **Dates must be `YYYY-MM-DD`.** ISO datetimes or `"YYYY-MM-DD HH:mm:ss"` return 996.

Unknown `filter` keys are silently ignored — no error, no filtering. Always
sanity-check totals.

`filter.city` enum (Mongolian aimag/city codes, `11` = Улаанбаатар):
`11 21 22 23 41 42 43 44 45 46 48 61 62 63 64 65 67 81 82 83 84 85`

| Tool | Report |
|---|---|
| `ubeats_report_driver_revenue` | Жолоочийн цалин бодолт (+`driverRevenueDirectTransact` filter, confirmed working) |
| `ubeats_report_delivery` | Хүргэлтийн тайлан (returns `feeChargeTotal`, `couponTotal`, `grandTotal`) |
| `ubeats_report_financial` | Санхүүгийн тайлан (29 columns, +`includeCancelled`) |
| `ubeats_report_financial_short` | Санхүүгийн тайлан (хураангуй, 14 columns) |
| `ubeats_report_items` | Хоолны тайлан (item-level) |
| `ubeats_report_order_duration` | Мерчант захиалгын хугацаа |
| `ubeats_report_orders` | Захиалгын дэлгэрэнгүй тайлан |
| `ubeats_report_meta` | `GET /reports/{report}/meta?action=list` — column + filter definitions |

### Orders (6)

Cloud Kitchen and Merchant orders live in **separate** collections — a phone
number can have orders in both, so search both.

`ubeats_order_search` / `_get` / `_state_histories`,
`ubeats_merchant_order_search` / `_get` / `_state_histories`

### Catalog (6)

`ubeats_provider_search`, `ubeats_branch_search` (filters: `name`, `status`),
`ubeats_merchant_search`, `ubeats_kitchen_search`, `ubeats_menu_search`,
`ubeats_notification_search` (filters: `beginDate`, `endDate`, `sender`,
`senderRole`, `receiverPhoneNumber`)

### Escape hatch (1)

`ubeats_bo_request` — arbitrary method/path against the BO API, with auth and
headers handled. Use it to probe undocumented endpoints before adding a real tool.

## Local run

```bash
npm install
npm run typecheck
cp .env.example .env
npm run login
npm run test:login
npm run compile && npm start   # stdio MCP server
```

## Vercel deploy

Zero-config: `api/index.ts` is the function, `vercel.json` rewrites everything
to it. Three rules carried over from `ubcab-bo-mcp` (learned the hard way):

1. **No legacy `builds` + `routes`** in `vercel.json` on a git-imported project
   — every path 404s. Use `rewrites` only.
2. **No `build` script in package.json** — Vercel then looks for `public/` and
   the deploy fails. Local compile is `npm run compile`.
3. **No imports from `src/`** — esbuild's Node16 resolver won't map `.js` → `.ts`
   and you get a 500. Everything lives in the one file.

Deploy by pushing to `main` (git integration), not from the CLI.

Env vars to set in Vercel: `UBEATS_BO_REFRESH_TOKEN` (from `npm run login`),
`UBEATS_BO_MCP_AUTH_TOKEN` (`openssl rand -hex 32`).

Health check: `GET /health` → `{"status":"ok","server":"ubeats-bo-mcp"}`

## Known gaps

- `order-duration`'s `meta?action=list` returns `998 permission_denied` for some
  roles even though `/list` works. Read the columns off the response instead.
- `financial-report`'s `includeCancelled` maps to `filter.state`; the BO renders
  it as a checkbox but the backend effect was not confirmed live.
- `/v1/api/categories/list` returns `998` for the account tested.
- No `products`, `delivery-tariffs`, `delivery-zones`, `feedbacks`, or `lots`
  list route under `/v1/api/` — those BO screens use different paths.
