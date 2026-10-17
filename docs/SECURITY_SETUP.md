# Security Setup (required before going live)

These settings are **required**. Without them the protected features stay off and return HTTP 503.
The example values in `.env.example` are rejected on purpose.

## 1. Generate secrets

Run this once per secret and paste each result into `.env`:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

| Variable | Used by | Purpose |
| --- | --- | --- |
| `ADMIN_API_TOKEN` | Payment API, admin panel, checkout portal, Gmail observer | Guards every `/api/v1/admin/*` route. Also signs the Gmail OAuth `state` and the checkout portal's internal requests. Never sent to browsers. |
| `OBSERVER_INGEST_TOKEN` | Payment API, Gmail/SMS observers | Guards bank-alert ingestion and every observer endpoint except health checks. |
| `ANDROID_ENROLLMENT_SECRET` | Payment API, admin panel | Needed to pair the Android SMS app. |
| `ADMIN_PANEL_USER` / `ADMIN_PANEL_PASSWORD` | Merchant admin panel | Login for the panel (HTTP Basic auth). Password must be 12+ characters. |

Also set your own UPI ID in the admin panel. In production, payments to the seeded placeholder
`merchant@upi` are refused.

## 2. What is protected

**Admin and operator access**
- `/api/v1/admin/*` needs `X-Admin-Token: <ADMIN_API_TOKEN>` (or `Authorization: Bearer <token>`). Admin routes never send CORS headers.
- Merchant-backend endpoints that return customer details (`/api/v1/orders/:orderId/cod`, `/api/v1/payments/:id/cod`, `/api/v1/devices/:id`, `/api/v1/devices/customer/:id`) need the admin token.
- `/api/v1/checkout/:id/simulate-observation` and auto-activation (`autoActivate`) are admin only.
- The merchant admin panel requires login, blocks cross-origin writes, cannot be framed, and locks an IP for 15 minutes after 10 failed logins.
- The control center and SMS observer listen on `127.0.0.1` only.

**Payment confirmation**
- Bank-alert ingestion (`/api/v1/pollers/events`, `/active-window`) needs `X-Observer-Token`. Test flags in the body only work for admin callers.
- The Gmail and SMS observers reject every request except `/health` (and Gmail's `/oauth/callback`) unless it carries the observer or admin token.
- The Gmail OAuth callback only accepts a signed, 15-minute `state`, so nobody can link their own inbox.
- Android pairing accepts only `ANDROID_ENROLLMENT_SECRET`; every device event must be HMAC-signed with a fresh timestamp. The app only reads notifications from known UPI/bank apps and only talks HTTPS.
- Counter confirmation cannot revive a cancelled, failed or expired session.

**Customers**
- OTPs come from a CSPRNG, are never logged, and are burned after 5 wrong attempts. OTP sending is limited per number (1 per 30 s, 5 per 10 min) and per IP.
- Login, registration and lookups are rate limited. `check-user` only returns masked details.
- A request may only act for the customer behind its own session token. A raw `customerId` is accepted from admins only.
- Passwords must be 8-128 characters and are hashed with PBKDF2-SHA512 (210,000 iterations).

**Input and output**
- `orderId`, method, currency, amount, `returnUrl` and metadata are validated on payment creation. Names are stripped of markup.
- The admin panel, checkout page, control center and demo store escape untrusted values. The checkout page rejects malformed payment IDs.
- The merchant SDK only trusts `postMessage` events from its own checkout iframe and only follows `http(s)` redirects.
- Request bodies are capped (1 MB API, 64 KB device events). Internal error details are hidden unless `YOUPI_DEBUG_ERRORS=1`.
- The Cloudflare tunnel setting accepts only a tunnel token; nothing is run through a shell.

**Supply chain**
- No prebuilt APK or JAR is shipped. Build the Android app from source (see `docs/ANDROID_MOBILE_APP.md`).
- The default merchant's webhook secret is random. A legacy public default is rotated automatically on start.

## 3. Rules for your own store or app

These come from the webhook contract and are easy to get wrong when copying code:

1. **Only fulfil orders from the signed webhook**, never from browser events or `?status=` URL parameters.
2. **Check the order belongs to you and the amount matches.** Anyone can create a payment on the public API with any `orderId`, amount and metadata. Look up the `orderId` in *your* database and compare `amountPaise` with what you expected.
3. **Check `method`.** `COD`, `CASH_COUNTER` and `CARD_COUNTER` successes are not prepaid UPI payments.
4. **Make processing idempotent** by `orderId` / `X-Gateway-Delivery-Id`.
5. **Verify the HMAC over the raw body** with a constant-time comparison.

The demo store (`apps/coin-wallet-store`) follows these rules: it only credits orders it created, at the amount it expected.

## 4. Behind a proxy

Requests arriving from `127.0.0.1` (for example via `cloudflared`) use `CF-Connecting-IP` / `X-Forwarded-For` as the client address for rate limiting. If a proxy on another host forwards traffic, set `TRUST_PROXY=1`.

## 5. Rotating secrets

Change the value in `.env` and restart all services. Re-pair Android phones after changing `ANDROID_ENROLLMENT_SECRET`. Changing `ADMIN_API_TOKEN` also invalidates pending Gmail OAuth flows.

## 6. Known limits

- Payment confirmation relies on bank SMS and email alerts. SMS sender IDs and email headers can be spoofed by determined attackers outside this system. Keep a manual review step for large orders.
- The WhatsApp OTP integration uses an unofficial protocol (`berryprotocol`) that may break or violate WhatsApp's terms.
- Rate limits are in memory and per process; run a single API process or add a shared store.

## 7. Running tests

`npm test` preloads `scripts/test-setup.js`, which provides test-only secrets. To run one file:

```bash
node --import ./scripts/test-setup.js --test path/to/file.test.js
```
