import crypto from 'node:crypto';

/**
 * Shared security helpers: shared-secret checks and safe Cloudflare tunnel launching.
 */

export const MIN_SECRET_LENGTH = 32;

// Placeholder values shipped in .env.example. A deployment using any of these is not secured.
const KNOWN_PLACEHOLDERS = new Set([
  'super_secret_jwt_key_change_in_production_min_32_chars',
  'android_pairing_enrollment_secret_key_32_chars',
  '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
  'AdminSecurePassword123!',
  'change_me_to_a_long_random_admin_api_token_value',
  'change_me_to_a_long_random_observer_token_value'
]);

/**
 * Constant-time string comparison.
 * @param {unknown} a
 * @param {unknown} b
 */
export function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) {
    // Still burn comparable time so length is not trivially observable.
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Returns a configured secret from the environment, or null when it is missing,
 * too short, or still set to a shipped placeholder value.
 * @param {string} name
 * @param {number} [minLength]
 */
export function getStrongSecret(name, minLength = MIN_SECRET_LENGTH) {
  const value = (process.env[name] || '').trim();
  if (value.length < minLength) return null;
  if (KNOWN_PLACEHOLDERS.has(value)) return null;
  return value;
}

/**
 * True when the value is a shipped placeholder (or empty).
 * @param {string|undefined|null} value
 */
export function isPlaceholderSecret(value) {
  const v = (value || '').trim();
  return !v || KNOWN_PLACEHOLDERS.has(v);
}

// Cloudflare tunnel tokens are base64/base64url strings.
const TUNNEL_TOKEN_RE = /^[A-Za-z0-9+/_=.-]{20,4096}$/;

/**
 * Extracts a Cloudflare tunnel token from either a bare token or a
 * `cloudflared ... tunnel run --token <TOKEN>` command. Anything else is rejected.
 * The original string is never passed to a shell.
 * @param {string} input
 * @returns {string} token
 */
export function parseCloudflareTunnelToken(input) {
  const raw = String(input || '').trim();
  if (!raw) {
    throw new Error('Cloudflare Tunnel command cannot be empty.');
  }

  if (TUNNEL_TOKEN_RE.test(raw)) {
    return raw;
  }

  // Shell metacharacters are never valid in a tunnel command.
  if (/[;&|`$<>(){}\\\n\r'"!*?]/.test(raw)) {
    throw new Error('Tunnel command contains characters that are not allowed. Paste the token or a plain "cloudflared tunnel run --token <TOKEN>" command.');
  }

  const parts = raw.split(/\s+/);
  const exe = parts[0].replace(/^.*[\\/]/, '').toLowerCase();
  if (exe !== 'cloudflared' && exe !== 'cloudflared.exe') {
    throw new Error('Only cloudflared tunnel commands are allowed.');
  }

  let token = null;
  for (let i = 1; i < parts.length; i++) {
    const p = parts[i];
    if (p === '--token' && parts[i + 1]) {
      token = parts[i + 1];
      break;
    }
    if (p.startsWith('--token=')) {
      token = p.slice('--token='.length);
      break;
    }
  }

  if (!token && parts.length >= 2) {
    const last = parts[parts.length - 1];
    // Also accept the dashboard form "cloudflared service install <TOKEN>"; we run it in the foreground instead.
    if (TUNNEL_TOKEN_RE.test(last) && (parts.includes('run') || parts.includes('install'))) {
      token = last;
    }
  }

  if (!token || !TUNNEL_TOKEN_RE.test(token)) {
    throw new Error('Could not find a valid tunnel token. Expected "cloudflared tunnel run --token <TOKEN>".');
  }

  return token;
}

/**
 * Builds the fixed executable + argument list used to run a tunnel. No shell is involved.
 * @param {string} input bare token or cloudflared command
 * @returns {{ executable: string, args: string[], token: string, display: string }}
 */
export function buildCloudflaredInvocation(input) {
  const token = parseCloudflareTunnelToken(input);
  const executable = (process.env.CLOUDFLARED_PATH || '').trim() || 'cloudflared';
  const args = ['tunnel', '--no-autoupdate', 'run', '--token', token];
  return {
    executable,
    args,
    token,
    display: `${executable} tunnel --no-autoupdate run --token ${redactToken(token)}`
  };
}

/**
 * @param {string} token
 */
export function redactToken(token) {
  const t = String(token || '');
  if (t.length <= 8) return '****';
  return `${t.slice(0, 4)}…${t.slice(-4)}`;
}

/**
 * Headers internal observer services attach when calling the Payment API.
 * @returns {Record<string, string>}
 */
export function observerAuthHeaders() {
  const token = (process.env.OBSERVER_INGEST_TOKEN || '').trim();
  return token ? { 'X-Observer-Token': token } : {};
}

/**
 * Token the checkout portal uses for server-side state fetches. Derived from ADMIN_API_TOKEN,
 * so no extra secret is needed; returns null when the admin token is not configured.
 * @returns {string|null}
 */
export function internalRenderToken() {
  const admin = getStrongSecret('ADMIN_API_TOKEN');
  if (!admin) return null;
  return crypto.createHmac('sha256', admin).update('youpi-internal-render-v1').digest('hex');
}

/**
 * Client IP for rate limiting and logging.
 * When the TCP peer is loopback the request came through a local proxy (cloudflared or one of
 * our own proxies), so CF-Connecting-IP / X-Forwarded-For identify the client. For any other
 * peer those headers are trusted only when TRUST_PROXY=1.
 * @param {import('node:http').IncomingMessage} req
 */
export function clientIpFromRequest(req) {
  const peer = req.socket?.remoteAddress || 'unknown';
  const isLoopback = peer === '127.0.0.1' || peer === '::1' || peer === '::ffff:127.0.0.1';
  if (isLoopback || process.env.TRUST_PROXY === '1') {
    const cf = req.headers['cf-connecting-ip'];
    if (typeof cf === 'string' && cf.trim()) return cf.trim();
    const xff = req.headers['x-forwarded-for'];
    if (typeof xff === 'string' && xff.trim()) return xff.split(',')[0].trim();
  }
  return peer;
}

/**
 * Headers an internal proxy should send upstream so the API sees the real client address
 * and cannot be fooled by client-supplied forwarding headers.
 * @param {import('node:http').IncomingMessage} req
 */
export function proxyForwardingHeaders(req) {
  return { 'x-forwarded-for': clientIpFromRequest(req), 'cf-connecting-ip': clientIpFromRequest(req) };
}

/**
 * True when a request to an internal service (Gmail / SMS observer) carries the observer or
 * admin token. Used to lock down everything except health checks and the OAuth callback.
 * @param {import('node:http').IncomingMessage} req
 */
export function isTrustedServiceRequest(req) {
  const observer = getStrongSecret('OBSERVER_INGEST_TOKEN');
  const admin = getStrongSecret('ADMIN_API_TOKEN');
  const suppliedObserver = String(req.headers['x-observer-token'] || '');
  const suppliedAdmin = String(req.headers['x-admin-token'] || '');
  return Boolean(
    (observer && suppliedObserver && safeEqual(suppliedObserver, observer)) ||
    (admin && suppliedAdmin && safeEqual(suppliedAdmin, admin))
  );
}

const OAUTH_STATE_TTL_MS = 15 * 60 * 1000;

/**
 * Signed, expiring OAuth `state` value (CSRF protection for the Gmail OAuth flow).
 * Both the Payment API and the Gmail observer can create/verify it using ADMIN_API_TOKEN.
 * @returns {string|null}
 */
export function createOAuthState() {
  const key = getStrongSecret('ADMIN_API_TOKEN');
  if (!key) return null;
  const payload = Buffer.from(JSON.stringify({
    n: crypto.randomBytes(16).toString('hex'),
    exp: Date.now() + OAUTH_STATE_TTL_MS
  })).toString('base64url');
  const sig = crypto.createHmac('sha256', key).update(`oauth-state:${payload}`).digest('base64url');
  return `${payload}.${sig}`;
}

/**
 * @param {string|null|undefined} state
 * @returns {boolean}
 */
export function verifyOAuthState(state) {
  const key = getStrongSecret('ADMIN_API_TOKEN');
  if (!key || typeof state !== 'string' || state.length > 512) return false;
  const [payload, sig] = state.split('.');
  if (!payload || !sig) return false;
  const expected = crypto.createHmac('sha256', key).update(`oauth-state:${payload}`).digest('base64url');
  if (!safeEqual(sig, expected)) return false;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    return typeof data.exp === 'number' && data.exp > Date.now();
  } catch {
    return false;
  }
}

/**
 * Minimal HTML escaping for server-rendered strings.
 * @param {unknown} value
 */
export function escapeHtmlText(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
