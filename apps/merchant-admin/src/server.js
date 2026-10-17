import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getDatabase, MerchantRepository, SupportTicketRepository } from '@youpi/db';
import { getStrongSecret, safeEqual, isPlaceholderSecret } from '@youpi/common';

// ---------------------------------------------------------------------------
// SECURITY: the merchant admin panel is protected with HTTP Basic auth and
// talks to the Payment API's admin routes using a server-side ADMIN_API_TOKEN.
// ---------------------------------------------------------------------------
const MIN_PANEL_PASSWORD_LENGTH = 12;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const MAX_FAILED_LOGINS = 10;
const failedLogins = new Map(); // ip -> { count, firstAt }

function getPanelCredentials() {
  const user = (process.env.ADMIN_PANEL_USER || process.env.INITIAL_ADMIN_EMAIL || '').trim();
  const password = process.env.ADMIN_PANEL_PASSWORD || process.env.INITIAL_ADMIN_PASSWORD || '';
  if (!user || password.length < MIN_PANEL_PASSWORD_LENGTH || isPlaceholderSecret(password)) return null;
  return { user, password };
}

function clientIp(req) {
  return req.socket?.remoteAddress || 'unknown';
}

function isLockedOut(ip) {
  const entry = failedLogins.get(ip);
  if (!entry) return false;
  if (Date.now() - entry.firstAt > LOGIN_WINDOW_MS) {
    failedLogins.delete(ip);
    return false;
  }
  return entry.count >= MAX_FAILED_LOGINS;
}

function recordFailure(ip) {
  const entry = failedLogins.get(ip);
  if (!entry || Date.now() - entry.firstAt > LOGIN_WINDOW_MS) {
    failedLogins.set(ip, { count: 1, firstAt: Date.now() });
  } else {
    entry.count += 1;
  }
}

/**
 * Returns true when the request is authenticated. Otherwise writes the response and returns false.
 */
export function checkPanelAuth(req, res) {
  const creds = getPanelCredentials();
  if (!creds) {
    res.writeHead(503, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Merchant admin is disabled: set ADMIN_PANEL_USER and ADMIN_PANEL_PASSWORD (12+ characters, not the example value) in .env.');
    return false;
  }

  const ip = clientIp(req);
  if (isLockedOut(ip)) {
    res.writeHead(429, { 'Content-Type': 'text/plain; charset=utf-8', 'Retry-After': '900' });
    res.end('Too many failed login attempts. Try again later.');
    return false;
  }

  const header = req.headers.authorization || '';
  if (header.startsWith('Basic ')) {
    let decoded = '';
    try {
      decoded = Buffer.from(header.slice(6).trim(), 'base64').toString('utf8');
    } catch {}
    const sep = decoded.indexOf(':');
    if (sep > 0) {
      const user = decoded.slice(0, sep);
      const password = decoded.slice(sep + 1);
      const userOk = safeEqual(user, creds.user);
      const passOk = safeEqual(password, creds.password);
      if (userOk && passOk) {
        failedLogins.delete(ip);
        return true;
      }
    }
    recordFailure(ip);
  }

  res.writeHead(401, {
    'Content-Type': 'text/plain; charset=utf-8',
    'WWW-Authenticate': 'Basic realm="YOUPI Merchant Admin", charset="UTF-8"'
  });
  res.end('Authentication required.');
  return false;
}

function isSameOrigin(req) {
  const origin = req.headers.origin || '';
  const referer = req.headers.referer || '';
  const source = origin || referer;
  if (!source) {
    // Non-browser clients (curl, scripts) send neither header; they still need valid credentials.
    return true;
  }
  let sourceHost;
  try {
    sourceHost = new URL(source).host.toLowerCase();
  } catch {
    return false;
  }
  const allowed = new Set(
    [req.headers.host, req.headers['x-forwarded-host']]
      .filter(Boolean)
      .map(h => String(h).split(',')[0].trim().toLowerCase())
  );
  return allowed.has(sourceHost);
}

function stripAuthHeaders(headers) {
  const copy = { ...headers };
  delete copy.authorization;
  delete copy['x-admin-token'];
  delete copy['x-observer-token'];
  delete copy.cookie;
  return copy;
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// In production, reliably ensure environment variables from .env are loaded if not already provided
if (!process.env.BASE_PAYMENT_API_URL && typeof process.loadEnvFile === 'function') {
  try {
    const rootEnv = path.resolve(__dirname, '../../../.env');
    if (fs.existsSync(rootEnv)) {
      process.loadEnvFile(rootEnv);
    }
  } catch {}
}

export class AdminServer {
  /**
   * @param {{
   *   db?: import('@youpi/db').Database,
   *   apiBaseUrl?: string
   * }} options
   */
  constructor(options = {}) {
    this.db = options.db || getDatabase();
    this.apiBaseUrl = options.apiBaseUrl || process.env.BASE_PAYMENT_API_URL || 'http://localhost:6100';
    this.merchantRepo = new MerchantRepository(this.db);
    this.ticketRepo = new SupportTicketRepository(this.db);
    this.htmlTemplatePath = path.join(__dirname, 'views', 'admin.html');
    this.template = fs.readFileSync(this.htmlTemplatePath, 'utf8');
  }

  renderHtml() {
    try {
      this.template = fs.readFileSync(this.htmlTemplatePath, 'utf8');
    } catch {}

    let html = this.template;
    // Always use empty string '' so client fetch calls hit the merchant admin's own /api proxy!
    // This completely eliminates CORS errors, tunnel downtime 530s, and cross-origin failures.
    const clientApiBase = '';
    html = html.replaceAll('{{API_BASE_URL}}', clientApiBase);
    html = html.replaceAll('{{ANDROID_ENROLLMENT_SECRET}}', getStrongSecret('ANDROID_ENROLLMENT_SECRET') || '');
    return html;
  }

  createServer() {
    return http.createServer(async (req, res) => {
      const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
      const pathname = url.pathname;

      if (req.method === 'OPTIONS') {
        res.writeHead(204, {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization'
        });
        res.end();
        return;
      }

      // Health
      if (pathname === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'UP', service: 'merchant-admin' }));
        return;
      }

      // Public APK download (the companion app is not secret; phones fetch it during setup)
      const isPublicApk = pathname === '/youpi-sms-gateway.apk';

      // SECURITY: everything else on the admin panel requires login.
      if (!isPublicApk && !checkPanelAuth(req, res)) {
        return;
      }

      // SECURITY (CSRF): browsers attach Basic credentials to cross-site form posts,
      // so state-changing requests must come from this same origin.
      if (!['GET', 'HEAD'].includes(req.method) && !isSameOrigin(req)) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Cross-origin request blocked.' }));
        return;
      }

      // Admin Tickets API: GET /api/admin/tickets
      if (pathname === '/api/admin/tickets') {
        const merchants = this.merchantRepo.findAll();
        const mId = merchants[0]?.id || '00000000-0000-0000-0000-000000000001';
        const tickets = this.ticketRepo.findTicketsByMerchant(mId);

        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        });
        res.end(JSON.stringify(tickets));
        return;
      }

      // Merged Control Center Supervisor Proxy: /api/services/* and /api/logs/stream -> Control Center on port 8090
      if (pathname.startsWith('/api/services') || pathname === '/api/logs/stream') {
        const ccPort = Number(process.env.CONTROL_CENTER_PORT || 8090);
        const proxyReq = http.request({
          hostname: '127.0.0.1',
          port: ccPort,
          path: req.url,
          method: req.method,
          headers: {
            ...stripAuthHeaders(req.headers),
            host: `localhost:${ccPort}`
          }
        }, (proxyRes) => {
          res.writeHead(proxyRes.statusCode, proxyRes.headers);
          proxyRes.pipe(res);
        });

        proxyReq.on('error', (err) => {
          if (!res.headersSent) {
            res.writeHead(502, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Control center supervisor unavailable', details: err.message }));
          }
        });

        req.on('data', chunk => proxyReq.write(chunk));
        req.on('end', () => proxyReq.end());
        return;
      }

      // Transparent API Proxy: /api/* -> Payment Core REST API
      if (pathname.startsWith('/api/')) {
        const targetPort = Number(process.env.PAYMENT_API_PORT || 6100);
        const defaultMerchant = this.merchantRepo.getDefault ? this.merchantRepo.getDefault() : (this.merchantRepo.findById('00000000-0000-0000-0000-000000000001') || this.merchantRepo.findAll()[0]);
        const defaultMerchantId = defaultMerchant?.id || '00000000-0000-0000-0000-000000000001';
        const proxyReq = http.request({
          hostname: '127.0.0.1',
          port: targetPort,
          path: req.url,
          method: req.method,
          headers: {
            ...stripAuthHeaders(req.headers),
            // Server-side admin credential; never exposed to the browser.
            ...(getStrongSecret('ADMIN_API_TOKEN') ? { 'x-admin-token': getStrongSecret('ADMIN_API_TOKEN') } : {}),
            'x-merchant-id': req.headers['x-merchant-id'] || defaultMerchantId,
            host: `localhost:${targetPort}`,
            'x-forwarded-host': req.headers.host || '',
            'x-forwarded-proto': req.headers['x-forwarded-proto'] || 'http'
          }
        }, (proxyRes) => {
          res.writeHead(proxyRes.statusCode, proxyRes.headers);
          proxyRes.pipe(res);
        });

        proxyReq.on('error', (err) => {
          if (!res.headersSent) {
            res.writeHead(502, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Gateway API unavailable', details: err.message }));
          }
        });

        req.pipe(proxyReq);
        return;
      }

      // Download Android Companion APK
      if (pathname === '/youpi-sms-gateway.apk' || pathname === '/api/v1/admin/sms-gateway/download-apk') {
        const apkCandidates = [
          path.resolve(__dirname, '../public/youpi-sms-gateway.apk'),
          path.resolve(__dirname, '../../payment-api/public/youpi-sms-gateway.apk'),
          path.resolve(__dirname, '../../android-observer-app/youpi-sms-gateway.apk')
        ];
        let apkPath = null;
        for (const p of apkCandidates) {
          if (fs.existsSync(p)) {
            apkPath = p;
            break;
          }
        }
        if (apkPath) {
          const stat = fs.statSync(apkPath);
          res.writeHead(200, {
            'Content-Type': 'application/vnd.android.package-archive',
            'Content-Disposition': 'attachment; filename="youpi-sms-gateway.apk"',
            'Content-Length': stat.size,
            'Access-Control-Allow-Origin': '*'
          });
          const stream = fs.createReadStream(apkPath);
          stream.pipe(res);
          return;
        }
      }

      // Dashboard View: GET / or GET /admin
      if (pathname === '/' || pathname === '/admin') {
        const html = this.renderHtml();
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'no-cache'
        });
        res.end(html);
        return;
      }

      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Admin Route Not Found');
    });
  }
}
