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
- **Same login path as office.ubeats.mn (no OTP)**: the server drives Keycloak's
  *browser* flow for the `ubeats-bo` client — GET the login page, POST the
  user's email + password to Keycloak's own form (with its cookies), capture
  the `302 https://office.ubeats.mn/?code=…`, and exchange the code with PKCE.
  For users without OTP in that flow this logs in with just email + password,
  exactly like office.ubeats.mn. (The realm's *direct grant* asks OTP from
  anyone with an authenticator configured — e.g. for the UBCab BO — which is
  why a plain password grant failed for them.)
- **OTP**: the OTP field is optional. A typed code always goes to the direct
  grant (password + `otp`), never to Keycloak's browser OTP form — codes are
  single-use, and one spent on a browser step that then dead-ended made the
  direct-grant fallback fail too (build `2026-10-18b`). If the browser flow
  reaches an OTP step without a code, the page asks for one.
  If the browser flow can't be driven (theme change, redirect URI rejected…),
  the server falls back to the direct grant and the error shows
  `[тех.: <build>; browser flow: <reason>]`.

Vercel env for this mode:

| Variable | |
|---|---|
| `UBEATS_BO_MCP_AUTH_TOKEN` | required — `openssl rand -hex 32` |
| `UBEATS_BO_ALLOWED_EMAILS` | required — e.g. `naranmunkh@ubcab.mn, someone@ubcab.mn` or `@ubcab.mn` |
| `UBEATS_BO_PASSWORD`, `UBEATS_BO_USERNAME` | **delete** — no longer used on Vercel |
| `UBCAB_BO_USERNAME`, `UBCAB_BO_PASSWORD`, `UBCAB_BO_TOTP_SECRET` | optional — service account, break-glass only (see below) |
| `UBEATS_BO_REFRESH_TOKEN` | optional — alternative service account, break-glass only |

### Service account (stdio and break-glass only)

Sending the raw `UBEATS_BO_MCP_AUTH_TOKEN` as the bearer (or `/mcp/<token>`)
skips the per-user login and uses one shared service account; stdio mode always
does. Connector users never touch it. Sources, in order:

1. `UBEATS_BO_REFRESH_TOKEN` — offline token for the `ubeats-bo` client, minted
   with `npm run login` (a BO token from ubcab-bo-mcp won't work: tokens are
   bound to the client that issued them).
2. **The BO login** — the same account and env names as `ubcab-bo-mcp`:
   `UBCAB_BO_USERNAME` + `UBCAB_BO_PASSWORD` + `UBCAB_BO_TOTP_SECRET` (the base32
   text under «Unable to scan?» in the authenticator setup; required since the
   realm enforced OTP on 2026-10-05). Every password grant sends a freshly
   generated `totp`. A code is single-use and the account is shared with
   ubcab-bo-mcp and the browser, so if another login spent the current code the
   server waits for the next 30 s step and retries once (~35 s cold login).
3. `UBEATS_BO_USERNAME` / `_PASSWORD` / `_TOTP_SECRET` — fallback when no BO login is set.

Check the TOTP generator offline with `npm run test:totp` (RFC 6238 vectors).

Once per-user login works for everyone, the shared password and TOTP secret are
only needed for break-glass — consider removing them from Vercel, since storing
a TOTP secret next to the password means that account's 2FA no longer protects it.

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
npm run test:totp
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

Deploy by pushing to `master` (git integration), not from the CLI.

Env vars to set in Vercel: `UBEATS_BO_MCP_AUTH_TOKEN` and
`UBEATS_BO_ALLOWED_EMAILS` (see the Auth section).

Health check: `GET /health` → `{"status":"ok","server":"ubeats-bo-mcp","build":"2026-10-18b per-user-browser-login",…}`
plus `allowlistConfigured`, `signingSecretConfigured`, `serviceAccountConfigured`.

### Is the latest build live?

- `/health` shows `build`. Missing, or older than the latest commit → an old
  deploy is serving. Vercel → Deployments: the top Production deployment must be
  the latest `master` commit ("Redeploy" on an old deployment rebuilds that old
  source).
- Every Keycloak auth error ends with a non-secret context, e.g.
  `[build 2026-10-18b per-user-browser-login, client=ubeats-bo, origin=https://office.ubeats.mn, grant=password, login=UBCAB_BO_*, totp=sent]`.
  `login=UBEATS_BO_* (fallback…)` → `UBCAB_BO_*` not set on that deployment (env
  changes need a new deploy); `totp=not configured` → `UBCAB_BO_TOTP_SECRET`
  missing; `totp=sent` with `invalid_grant` → wrong password or TOTP secret.

## Known gaps

- `order-duration`'s `meta?action=list` returns `998 permission_denied` for some
  roles even though `/list` works. Read the columns off the response instead.
- `financial-report`'s `includeCancelled` maps to `filter.state`; the BO renders
  it as a checkbox but the backend effect was not confirmed live.
- `/v1/api/categories/list` returns `998` for the account tested.
- No `products`, `delivery-tariffs`, `delivery-zones`, `feedbacks`, or `lots`
  list route under `/v1/api/` — those BO screens use different paths.
