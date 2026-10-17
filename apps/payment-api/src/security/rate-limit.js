import { clientIpFromRequest } from '@youpi/common';
/**
 * Small in-memory fixed-window rate limiter (single-process deployment).
 *
 * Set YOUPI_RATE_LIMIT_DISABLED=1 only for automated test runs.
 */

const buckets = new Map(); // key -> { count, resetAt }
let lastSweep = Date.now();

function sweep(now) {
  if (now - lastSweep < 60_000) return;
  lastSweep = now;
  for (const [key, bucket] of buckets) {
    if (bucket.resetAt <= now) buckets.delete(key);
  }
}

export function rateLimitDisabled() {
  return process.env.YOUPI_RATE_LIMIT_DISABLED === '1';
}

/**
 * Records one hit and reports whether the caller is over the limit.
 * @param {string} key
 * @param {number} limit max hits per window
 * @param {number} windowMs
 * @returns {{ limited: boolean, retryAfterSeconds: number, remaining: number }}
 */
export function hit(key, limit, windowMs) {
  const now = Date.now();
  sweep(now);
  if (rateLimitDisabled()) return { limited: false, retryAfterSeconds: 0, remaining: limit };

  let bucket = buckets.get(key);
  if (!bucket || bucket.resetAt <= now) {
    bucket = { count: 0, resetAt: now + windowMs };
    buckets.set(key, bucket);
  }
  bucket.count += 1;
  const limited = bucket.count > limit;
  return {
    limited,
    retryAfterSeconds: Math.max(1, Math.ceil((bucket.resetAt - now) / 1000)),
    remaining: Math.max(0, limit - bucket.count)
  };
}

/**
 * Clears a key (e.g. after a successful login).
 * @param {string} key
 */
export function reset(key) {
  buckets.delete(key);
}

/**
 * Client IP (proxy-aware). See clientIpFromRequest in @youpi/common.
 * @param {import('node:http').IncomingMessage} req
 */
export function clientIp(req) {
  return clientIpFromRequest(req);
}

/**
 * Applies several limits; writes a 429 response and returns true if any is exceeded.
 * @param {import('node:http').ServerResponse} res
 * @param {Array<{ key: string, limit: number, windowMs: number }>} rules
 */
export function enforce(res, rules) {
  for (const rule of rules) {
    const result = hit(rule.key, rule.limit, rule.windowMs);
    if (result.limited) {
      res.writeHead(429, {
        'Content-Type': 'application/json',
        'Retry-After': String(result.retryAfterSeconds),
        'Access-Control-Allow-Origin': '*'
      });
      res.end(JSON.stringify({ error: 'Too many requests. Please wait and try again.', retryAfterSeconds: result.retryAfterSeconds }));
      return true;
    }
  }
  return false;
}
