import http from 'node:http';
import { URL } from 'node:url';

const ALLOWED_HEADERS = 'Content-Type, Authorization, Idempotency-Key, X-Device-Id, X-Device-Token, X-Timestamp, X-Signature, X-Customer-Token';
const MAX_BODY_BYTES = 1024 * 1024; // 1 MB

const NO_CORS_PATH_RE = /^\/api\/v1\/(admin(\/|$)|pollers\/(events|active-window)$|devices\/customer\/|devices\/(?!register$|verify$)[^/]+$|orders\/[^/]+\/cod$|payments\/[^/]+\/cod$)/;

function httpError(statusCode, message) {
  const err = new Error(message);
  err.statusCode = statusCode;
  return err;
}

/**
 * Reads the raw request body with a size cap. Rejects with a 413 error when too large.
 * @param {import('node:http').IncomingMessage} req
 * @param {number} [limit]
 * @returns {Promise<string>}
 */
export function readBody(req, limit = MAX_BODY_BYTES) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let done = false;
    req.on('data', chunk => {
      if (done) return;
      size += chunk.length;
      if (size > limit) {
        done = true;
        reject(httpError(413, 'Payload Too Large'));
        req.resume();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (done) return;
      done = true;
      resolve(Buffer.concat(chunks).toString('utf8'));
    });
    req.on('error', err => {
      if (done) return;
      done = true;
      reject(err);
    });
  });
}

function corsOriginFor(req, pathname) {
  if (NO_CORS_PATH_RE.test(pathname)) return null;
  const configured = (process.env.CORS_ALLOWED_ORIGINS || '').split(',').map(o => o.trim()).filter(Boolean);
  if (configured.length === 0) return '*';
  const origin = req.headers.origin;
  return origin && configured.includes(origin) ? origin : null;
}

/**
 * Rewrites Access-Control-Allow-Origin on every response for this request.
 */
function applyCorsPolicy(req, res, pathname) {
  const allowOrigin = corsOriginFor(req, pathname);
  const originalWriteHead = res.writeHead.bind(res);
  res.writeHead = (statusCode, ...rest) => {
    for (const arg of rest) {
      if (arg && typeof arg === 'object' && !Array.isArray(arg)) {
        for (const key of Object.keys(arg)) {
          if (key.toLowerCase() === 'access-control-allow-origin') delete arg[key];
        }
      }
    }
    res.removeHeader('Access-Control-Allow-Origin');
    if (allowOrigin) {
      res.setHeader('Access-Control-Allow-Origin', allowOrigin);
      if (allowOrigin !== '*') res.setHeader('Vary', 'Origin');
    }
    return originalWriteHead(statusCode, ...rest);
  };
}

/**
 * Lightweight, high-performance HTTP router and server with native SSE and CORS.
 */
export class HttpServer {
  constructor() {
    this.routes = [];
    this.sseClients = new Map(); // sessionId -> Set of res objects
    this.guards = [];
  }

  /**
   * Registers a guard that runs before routing. A guard returns true when it has
   * already rejected the request (and written the response).
   * @param {(req: any, res: any, pathname: string, method: string) => boolean} guard
   */
  use(guard) {
    this.guards.push(guard);
  }

  /**
   * Registers a route.
   * @param {'GET'|'POST'|'PUT'|'DELETE'} method
   * @param {string} pattern E.g. "/api/v1/checkout/:id/state"
   * @param {(req: any, res: any, params: Record<string, string>) => void} handler
   */
  register(method, pattern, handler) {
    const paramNames = [];
    const regexPattern = pattern.replace(/:([a-zA-Z0-9_]+)/g, (_, name) => {
      paramNames.push(name);
      return '([^/]+)';
    });

    this.routes.push({
      method: method.toUpperCase(),
      regex: new RegExp(`^${regexPattern}$`),
      paramNames,
      handler
    });
  }

  get(pattern, handler) {
    this.register('GET', pattern, handler);
  }

  post(pattern, handler) {
    this.register('POST', pattern, handler);
  }

  delete(pattern, handler) {
    this.register('DELETE', pattern, handler);
  }

  /**
   * Dispatches SSE event to all connected clients listening on a specific topic/key.
   * @param {string} topic
   * @param {string} event
   * @param {any} data
   */
  broadcastSse(topic, event, data) {
    const clients = this.sseClients.get(topic);
    if (!clients || clients.size === 0) return;

    const safeJson = (obj) => JSON.stringify(obj, (k, v) => typeof v === 'bigint' ? v.toString() : v);
    const namedPayload = `event: ${event}\ndata: ${safeJson(data)}\n\n`;
    const defaultPayload = `data: ${safeJson({ type: event, ...data, event })}\n\n`;
    const combinedPayload = namedPayload + defaultPayload;
    for (const res of clients) {
      try {
        res.write(combinedPayload);
      } catch {
        clients.delete(res);
      }
    }
  }

  /**
   * Sets up SSE connection for a client response.
   * @param {string} topic
   * @param {http.ServerResponse} res
   */
  initSse(topic, res) {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': '*'
    });

    res.write('event: connected\ndata: {"status":"connected"}\n\n');

    if (!this.sseClients.has(topic)) {
      this.sseClients.set(topic, new Set());
    }
    const set = this.sseClients.get(topic);
    set.add(res);

    // Keepalive ping every 15s
    const pingInterval = setInterval(() => {
      try {
        res.write(': keepalive\n\n');
      } catch {
        clearInterval(pingInterval);
      }
    }, 15000);

    res.on('close', () => {
      clearInterval(pingInterval);
      set.delete(res);
      if (set.size === 0) {
        this.sseClients.delete(topic);
      }
    });
  }

  /**
   * Helper to send JSON responses with standard headers.
   */
  static json(res, statusCode, data) {
    const jsonStr = JSON.stringify(data, (key, value) =>
      typeof value === 'bigint' ? value.toString() : value
    );
    if (res.headersSent) {
      try { res.end(); } catch {}
      return;
    }
    res.writeHead(statusCode, {
      'Content-Type': 'application/json',
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'no-store',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': ALLOWED_HEADERS
    });
    res.end(jsonStr);
  }

  /**
   * Parses JSON body from request (max 1 MB).
   */
  static async parseBody(req) {
    return readBody(req).then(body => {
      if (!body.trim()) return {};
      try {
        return JSON.parse(body);
      } catch {
        throw httpError(400, 'Malformed JSON body');
      }
    });
  }

  /**
   * Creates native HTTP server.
   */
  createServer() {
    return http.createServer(async (req, res) => {
      try {
        await this.dispatch(req, res);
      } catch (err) {
        console.error('Unhandled request error:', err);
        if (!res.headersSent) {
          HttpServer.json(res, 500, { error: 'Internal Server Error' });
        } else {
          try { res.end(); } catch {}
        }
      }
    });
  }

  async dispatch(req, res) {
    let parsedUrl;
    try {
      parsedUrl = new URL(req.url, 'http://localhost');
    } catch {
      HttpServer.json(res, 400, { error: 'Bad request URL' });
      return;
    }
    const pathname = parsedUrl.pathname;
    const method = req.method.toUpperCase();

    // SECURITY: CORS is decided once per request. Admin, observer and device-admin routes
    // never get CORS headers; public routes follow CORS_ALLOWED_ORIGINS (default "*").
    applyCorsPolicy(req, res, pathname);

    // Handle CORS preflight
    if (method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': ALLOWED_HEADERS,
        'Access-Control-Max-Age': '600'
      });
      res.end();
      return;
    }

    for (const guard of this.guards) {
      try {
        if (guard(req, res, pathname, method)) return;
      } catch (err) {
        console.error(`Guard Error [${method} ${pathname}]:`, err);
        HttpServer.json(res, 500, { error: 'Internal Server Error' });
        return;
      }
    }

    for (const route of this.routes) {
      if (route.method === method) {
        const match = pathname.match(route.regex);
        if (match) {
          const params = {};
          route.paramNames.forEach((name, index) => {
            params[name] = match[index + 1];
          });

          req.query = Object.fromEntries(parsedUrl.searchParams.entries());

          try {
            await route.handler(req, res, params);
          } catch (err) {
            const status = Number(err?.statusCode) || 500;
            if (status >= 500) {
              console.error(`Route Error [${method} ${pathname}]:`, err);
            }
            // SECURITY: never leak internal error details (SQL, stack, paths) to clients.
            const message = status < 500 ? err.message : (process.env.YOUPI_DEBUG_ERRORS === '1' ? err.message : 'Internal Server Error');
            HttpServer.json(res, status, { error: message });
          }
          return;
        }
      }
    }

    // Not found
    HttpServer.json(res, 404, { error: 'Route not found' });
  }
}
