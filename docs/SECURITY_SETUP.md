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
| `ADMIN_API_TOKEN` | Payment API, merchant admin panel | Guards every `/api/v1/admin/*` route. The panel sends it server-side; it never reaches the browser. |
| `OBSERVER_INGEST_TOKEN` | Payment API, Gmail/SMS observers | Guards `/api/v1/pollers/events` and `/api/v1/pollers/active-window`. |
| `ANDROID_ENROLLMENT_SECRET` | Payment API, admin panel | Needed to pair the Android SMS app. |
| `ADMIN_PANEL_USER` / `ADMIN_PANEL_PASSWORD` | Merchant admin panel | Login for the panel (HTTP Basic auth). Password must be 12+ characters. |

## 2. What is protected

- **Admin API** (`/api/v1/admin/*`): needs `X-Admin-Token: <ADMIN_API_TOKEN>` (or `Authorization: Bearer <token>`).
- **Payment simulation** (`/api/v1/checkout/:id/simulate-observation`): admin token only.
- **Bank alert ingestion** (`/api/v1/pollers/events`, `/active-window`): `X-Observer-Token`. Test flags in the body are ignored unless the caller is an admin.
- **Android devices**: pairing accepts only `ANDROID_ENROLLMENT_SECRET`. Every SMS event must carry `X-Timestamp` and an HMAC `X-Signature`.
- **Merchant admin panel**: login required; cross-origin writes are blocked; 10 failed logins lock an IP for 15 minutes.
- **Control center** (process supervisor): listens on `127.0.0.1` only. Reach it through the admin panel.
- **Cloudflare tunnel**: only a tunnel token or `cloudflared tunnel run --token <TOKEN>` is accepted. Nothing is run through a shell.

## 3. Rotating secrets

Change the value in `.env` and restart all services. Re-pair Android phones after changing `ANDROID_ENROLLMENT_SECRET`.

## 4. Running tests

`npm test` preloads `scripts/test-setup.js`, which provides test-only secrets. To run one file:

```bash
node --import ./scripts/test-setup.js --test path/to/file.test.js
```
