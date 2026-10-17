import { safeEqual, getStrongSecret } from '@youpi/common';

/**
 * Central access control for the Payment API.
 *
 * - /api/v1/admin/*                         -> admin token required
 * - /api/v1/checkout/:id/simulate-observation -> admin token required (dev tool that can mark payments paid)
 * - /api/v1/pollers/events, /active-window   -> observer token (or admin token) required
 * - /api/v1/admin/gmail/credentials          -> admin token, or observer token (used by the Gmail observer)
 *
 * Tokens are read from the environment on every request:
 *   ADMIN_API_TOKEN        (min 32 chars) used by the merchant admin panel proxy and operators
 *   OBSERVER_INGEST_TOKEN  (min 32 chars) used by the Gmail / SMS observer services
 *
 * Everything fails closed: if a token is not configured, the protected routes are disabled.
 */

function headerValue(req, name) {
  const v = req.headers?.[name];
  if (Array.isArray(v)) return v[0];
  return typeof v === 'string' ? v.trim() : '';
}

function bearerToken(req) {
  const auth = headerValue(req, 'authorization');
  return auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
}

/**
 * @param {import('node:http').IncomingMessage} req
 */
export function isAdminRequest(req) {
  const expected = getStrongSecret('ADMIN_API_TOKEN');
  if (!expected) return false;
  const supplied = headerValue(req, 'x-admin-token') || bearerToken(req);
  return Boolean(supplied) && safeEqual(supplied, expected);
}

/**
 * @param {import('node:http').IncomingMessage} req
 */
export function isObserverRequest(req) {
  const expected = getStrongSecret('OBSERVER_INGEST_TOKEN');
  const supplied = headerValue(req, 'x-observer-token');
  if (expected && supplied && safeEqual(supplied, expected)) return true;
  return isAdminRequest(req);
}

const OBSERVER_PATHS = new Set([
  '/api/v1/pollers/events',
  '/api/v1/pollers/active-window'
]);

const OBSERVER_ALLOWED_ADMIN_PATHS = new Set([
  '/api/v1/admin/gmail/credentials'
]);

const SIMULATE_OBSERVATION_RE = /^\/api\/v1\/checkout\/[^/]+\/simulate-observation$/;

function deny(res, status, error) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'WWW-Authenticate': 'Bearer'
  });
  res.end(JSON.stringify({ error }));
  return true;
}

/**
 * Returns the access level a path needs: 'admin', 'observer', 'admin-or-observer', or null (public).
 * @param {string} pathname
 */
export function requiredAccessFor(pathname) {
  if (OBSERVER_ALLOWED_ADMIN_PATHS.has(pathname)) return 'admin-or-observer';
  if (pathname === '/api/v1/admin' || pathname.startsWith('/api/v1/admin/')) return 'admin';
  if (SIMULATE_OBSERVATION_RE.test(pathname)) return 'admin';
  if (OBSERVER_PATHS.has(pathname)) return 'observer';
  return null;
}

/**
 * HttpServer guard. Returns true when the request was rejected (response already sent).
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {string} pathname
 */
export function accessGuard(req, res, pathname) {
  const level = requiredAccessFor(pathname);
  if (!level) return false;

  if (level === 'admin') {
    if (!getStrongSecret('ADMIN_API_TOKEN')) {
      return deny(res, 503, 'Admin API is disabled: set ADMIN_API_TOKEN (at least 32 random characters) in .env.');
    }
    return isAdminRequest(req) ? false : deny(res, 401, 'Unauthorized: valid admin token required.');
  }

  // observer or admin-or-observer
  if (!getStrongSecret('OBSERVER_INGEST_TOKEN') && !getStrongSecret('ADMIN_API_TOKEN')) {
    return deny(res, 503, 'Observer ingestion is disabled: set OBSERVER_INGEST_TOKEN (at least 32 random characters) in .env.');
  }
  return isObserverRequest(req) ? false : deny(res, 401, 'Unauthorized: valid observer token required.');
}
