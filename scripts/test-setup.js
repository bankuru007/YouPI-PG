/**
 * Test harness preload (node --import ./scripts/test-setup.js).
 *
 * The API now requires credentials for admin, observer and device-pairing routes.
 * The existing suites exercise those routes as a trusted operator, so this preload:
 *   1. sets strong test-only secrets in the environment, and
 *   2. attaches operator credentials to requests sent to localhost.
 *
 * Suites that check the lock-down itself set `globalThis.__YOUPI_TEST_NO_AUTH = true`
 * (or send the header `x-test-no-auth: 1`) to send requests exactly as written.
 */
import http from 'node:http';
import { syncBuiltinESMExports } from 'node:module';

const TEST_SECRETS = {
  ADMIN_API_TOKEN: 'test-admin-token-0123456789abcdef0123456789abcdef',
  OBSERVER_INGEST_TOKEN: 'test-observer-token-0123456789abcdef0123456789ab',
  ANDROID_ENROLLMENT_SECRET: 'test-enrollment-secret-0123456789abcdef01234567',
  ADMIN_PANEL_USER: 'test-admin',
  ADMIN_PANEL_PASSWORD: 'test-panel-password-123456',
  // Existing suites read the OTP from the API response and hit endpoints in tight loops.
  YOUPI_DEV_OTP: '1',
  YOUPI_RATE_LIMIT_DISABLED: '1'
};

for (const [key, value] of Object.entries(TEST_SECRETS)) {
  if (!process.env[key]) process.env[key] = value;
}

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);

function authHeaders() {
  const basic = Buffer.from(`${process.env.ADMIN_PANEL_USER}:${process.env.ADMIN_PANEL_PASSWORD}`).toString('base64');
  return {
    'x-admin-token': process.env.ADMIN_API_TOKEN,
    'x-observer-token': process.env.OBSERVER_INGEST_TOKEN,
    authorization: `Basic ${basic}`
  };
}

function shouldInject(hostname, hasOptOutHeader) {
  if (globalThis.__YOUPI_TEST_NO_AUTH || hasOptOutHeader) return false;
  return LOCAL_HOSTS.has(String(hostname || '').toLowerCase());
}

const originalRequest = http.request;
http.request = function patchedRequest(...args) {
  const req = originalRequest.apply(this, args);
  try {
    const optOut = Boolean(req.getHeader('x-test-no-auth'));
    if (optOut) req.removeHeader('x-test-no-auth');
    if (shouldInject(req.host, optOut)) {
      for (const [name, value] of Object.entries(authHeaders())) {
        if (!req.getHeader(name)) req.setHeader(name, value);
      }
    }
  } catch {}
  return req;
};
http.get = function patchedGet(...args) {
  const req = http.request(...args);
  req.end();
  return req;
};

const originalFetch = globalThis.fetch;
if (typeof originalFetch === 'function') {
  globalThis.fetch = async function patchedFetch(input, init = {}) {
    try {
      const url = new URL(typeof input === 'string' || input instanceof URL ? String(input) : input.url);
      const headers = new Headers(init.headers || (input instanceof Request ? input.headers : undefined));
      const optOut = headers.has('x-test-no-auth');
      headers.delete('x-test-no-auth');
      if (shouldInject(url.hostname, optOut)) {
        for (const [name, value] of Object.entries(authHeaders())) {
          if (!headers.has(name)) headers.set(name, value);
        }
      }
      return originalFetch(input, { ...init, headers });
    } catch {
      return originalFetch(input, init);
    }
  };
}

syncBuiltinESMExports();
