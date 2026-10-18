# ubeats-bo-mcp

MCP server for the **UBEats Backoffice** (`office.ubeats.mn`, API host
`https://ubeats-bo-api.ubcabtech.com`). Built on the same pattern as
`ubcab-bo-mcp`: one self-contained `api/index.ts` that runs either over stdio
(local / Claude Desktop) or as a bearer-guarded Streamable HTTP endpoint on
Vercel.

## Auth — every user signs in with their own BO account

When someone adds the connector in Claude and presses **Connect**, the server's
`/authorize` page asks for their **BO email + password** (and a 6-digit **OTP**
only if their account has an authenticator configured). The server sends those
once to Keycloak (direct grant, client `ubeats-bo`, `scope=openid
offline_access`), checks the email **Keycloak verified** against
`UBEATS_BO_ALLOWED_EMAILS`, and hands Claude a sealed token. From then on every
tool call runs **with that user's own BO permissions** — two people asking the
same question can get different answers, exactly as in office.ubeats.mn.

- **The password is never stored or logged** — it's used for that one Keycloak
  call. Only the user's Keycloak offline refresh token is kept, and only inside
  AES-256-GCM sealed tokens (codes, access, refresh) keyed off
  `UBEATS_BO_MCP_AUTH_TOKEN`. Rotating that secret logs everyone out.
- **Allowlist is fail-closed**: `UBEATS_BO_ALLOWED_EMAILS` takes full emails,
  `@ubcab.mn` (whole domain) or `*` (any BO user). Empty → nobody can connect.
  It's re-checked on every request, so removing an email cuts access at once.
- **How long a connection lasts**: Claude's access token is 12h and silently
  refreshed; each refresh does a real Keycloak round-trip. The connection lives
  as long as the user's Keycloak offline session (default: until 30 days
  unused; ended by a password change or "sign out all sessions"). When it ends,
  `/mcp` answers 401 and the tools say: *Settings → Connectors → UBEats BO →
  Disconnect → Connect*.
- **OTP**: office.ubeats.mn's own login doesn't ask for OTP, but Keycloak's
  direct-grant flow does for users who have an authenticator set up (e.g. for
  the UBCab BO). Leave the field empty first; if the login fails the page asks
  for the code.

Vercel env for this mode:

| Variable | |
|---|---|
| `UBEATS_BO_MCP_AUTH_TOKEN` | required — `openssl rand -hex 32` |
| `UBEATS_BO_ALLOWED_EMAILS` | required — e.g. `naranmunkh@ubcab.mn, someone@ubcab.mn` or `@ubcab.mn` |
| `UBEATS_BO_PASSWORD`, `UBEATS_BO_USERNAME` | **delete** — no longer used on Vercel |
| `UBEATS_BO_REFRESH_TOKEN` | optional — service account for the break-glass bearer only |

**Break-glass / stdio:** sending the raw `UBEATS_BO_MCP_AUTH_TOKEN` as the bearer
(or `/mcp/<token>`) skips the per-user login and uses the service account from
`UBEATS_BO_REFRESH_TOKEN` (mint it with `npm run login`). stdio mode always uses
the service account.

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

Env vars to set in Vercel: `UBEATS_BO_MCP_AUTH_TOKEN` and
`UBEATS_BO_ALLOWED_EMAILS` (see the Auth section).

Health check: `GET /health` → `{"status":"ok","server":"ubeats-bo-mcp"}`

## Known gaps

- `order-duration`'s `meta?action=list` returns `998 permission_denied` for some
  roles even though `/list` works. Read the columns off the response instead.
- `financial-report`'s `includeCancelled` maps to `filter.state`; the BO renders
  it as a checkbox but the backend effect was not confirmed live.
- `/v1/api/categories/list` returns `998` for the account tested.
- No `products`, `delivery-tariffs`, `delivery-zones`, `feedbacks`, or `lots`
  list route under `/v1/api/` — those BO screens use different paths.
