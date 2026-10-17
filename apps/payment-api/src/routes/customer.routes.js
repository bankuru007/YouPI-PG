import crypto from 'node:crypto';
import { HttpServer } from '../server.js';
import { normalizeEmail, normalizeMobile, isValidEmail, isValidMobile, isValidPassword, safeEqual } from '@youpi/common';
import { enforce, clientIp, reset as resetRateLimit } from '../security/rate-limit.js';

// Per-IP limits are generous because many mobile users share one IP (carrier NAT);
// the per-number and per-account limits are the main brute-force controls.
const MINUTE = 60 * 1000;
const OTP_TTL_MS = 5 * MINUTE;
const MAX_OTP_ATTEMPTS = 5;

// Names are shown in the admin panel; strip markup and control characters.
function cleanName(value) {
  return String(value || '').replace(/[\u0000-\u001f\u007f<>"'`]/g, '').trim().slice(0, 80);
}

function maskMobile(mobile) {
  const m = String(mobile || '');
  return m.length >= 4 ? `******${m.slice(-4)}` : '****';
}

function maskName(name) {
  const n = String(name || '').trim();
  if (!n) return '';
  return n.split(/\s+/).map(part => `${part[0]}${'*'.repeat(Math.max(1, Math.min(part.length - 1, 4)))}`).join(' ');
}

function maskEmail(email) {
  const e = String(email || '');
  const at = e.indexOf('@');
  if (at < 1) return '';
  return `${e[0]}***${e.slice(at)}`;
}

/**
 * Dev-only OTP echo. Requires an explicit opt-in and is never enabled in production.
 */
function exposeDevOtp() {
  return process.env.YOUPI_DEV_OTP === '1' && process.env.NODE_ENV !== 'production';
}

/**
 * Registers gateway-owned customer identity and session routes.
 * @param {HttpServer} server
 * @param {{
 *   customerRepo: import('@youpi/db').CustomerRepository,
 *   customerSessionRepo: import('@youpi/db').CustomerSessionRepository,
 *   sessionRepo: import('@youpi/db').PaymentSessionRepository,
 *   auditRepo: import('@youpi/db').AuditLogRepository
 * }} ctx
 */
export function registerCustomerRoutes(server, ctx) {
  // Helper to extract session token from Authorization header or Cookie
  function extractSessionToken(req) {
    const authHeader = req.headers['authorization'] || '';
    if (authHeader.startsWith('Bearer ')) {
      return authHeader.slice(7).trim();
    }
    const cookieHeader = req.headers['cookie'] || '';
    const match = cookieHeader.match(/youpi_session=([^;]+)/);
    if (match) {
      return match[1].trim();
    }
    return null;
  }

  // Helper to set session cookie header
  function isHttpsRequest(req) {
    const proto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
    return proto === 'https' || Boolean(req.socket?.encrypted);
  }

  function buildSessionCookie(token, maxAgeSeconds = 30 * 24 * 3600, req = null) {
    const secure = req && isHttpsRequest(req) ? '; Secure' : '';
    return `youpi_session=${token}; Path=/; Max-Age=${maxAgeSeconds}; HttpOnly; SameSite=Lax${secure}`;
  }

  // Pending signup challenges cache: mobileNumber -> { otpCode, expiresAt, name, email }
  const pendingOtpChallenges = new Map();
  // Wrong OTP attempts per mobile for the currently issued code
  const otpFailures = new Map();

  function recordOtpFailure(mobile) {
    const count = (otpFailures.get(mobile) || 0) + 1;
    otpFailures.set(mobile, count);
    if (count >= MAX_OTP_ATTEMPTS) {
      // Burn the code: the customer must request a new one.
      pendingOtpChallenges.delete(mobile);
      try { ctx.customerRepo.setOtp(mobile, null, null); } catch {}
      otpFailures.delete(mobile);
      return true;
    }
    return false;
  }

  // Helper to get Berry Service
  function getBerry() {
    return ctx.whatsappBerryService || null;
  }

  // 1. POST /api/v1/customer/check-user
  // Check whether a customer exists by mobile number
  server.post('/api/v1/customer/check-user', async (req, res) => {
    const ip = clientIp(req);
    if (enforce(res, [{ key: `check-user:ip:${ip}`, limit: 60, windowMs: 10 * MINUTE }])) return;
    const body = await HttpServer.parseBody(req).catch(() => ({}));
    const rawMobile = body.mobileNumber || body.phoneNumber || body.mobile || body.phone;

    if (!rawMobile) {
      HttpServer.json(res, 400, { error: 'Mobile number is required.' });
      return;
    }

    const cleanMobile = normalizeMobile(rawMobile);
    if (!cleanMobile || !isValidMobile(cleanMobile)) {
      HttpServer.json(res, 400, { error: 'Please enter a valid 10-digit mobile number.' });
      return;
    }

    const existingUser = ctx.customerRepo.findByMobile(cleanMobile);

    HttpServer.json(res, 200, {
      success: true,
      exists: Boolean(existingUser),
      mobileNumber: cleanMobile,
      // Only masked details: this endpoint is unauthenticated.
      customer: existingUser ? {
        name: maskName(existingUser.name),
        email: maskEmail(existingUser.email),
        mobileNumber: maskMobile(existingUser.mobileNumber)
      } : null
    });
  });

  // 2. POST /api/v1/customer/send-otp
  // Dispatches 6-digit verification code to customer's WhatsApp via Berry Protocol
  server.post('/api/v1/customer/send-otp', async (req, res) => {
    const ip = clientIp(req);
    if (enforce(res, [{ key: `send-otp:ip:${ip}`, limit: 30, windowMs: 10 * MINUTE }])) return;
    const body = await HttpServer.parseBody(req).catch(() => ({}));
    const rawMobile = body.mobileNumber || body.phoneNumber || body.mobile || body.phone;
    const name = cleanName(body.name || body.fullName || '');
    const email = normalizeEmail(body.email);
    const isNewUser = Boolean(body.isNewUser);

    if (!rawMobile) {
      HttpServer.json(res, 400, { error: 'Mobile number is required.' });
      return;
    }

    const cleanMobile = normalizeMobile(rawMobile);
    if (!cleanMobile || !isValidMobile(cleanMobile)) {
      HttpServer.json(res, 400, { error: 'Please enter a valid 10-digit mobile number.' });
      return;
    }

    // Per-number limits stop OTP flooding of one customer: one code per 30s, five per 10 minutes.
    if (enforce(res, [
      { key: `send-otp:cooldown:${cleanMobile}`, limit: 1, windowMs: 30 * 1000 },
      { key: `send-otp:mobile:${cleanMobile}`, limit: 5, windowMs: 10 * MINUTE }
    ])) return;

    const existingUser = ctx.customerRepo.findByMobile(cleanMobile);

    // If new user signing up, validate name and email
    if (!existingUser && isNewUser) {
      if (!name) {
        HttpServer.json(res, 400, { error: 'Full name is required for registration.' });
        return;
      }
      if (!email || !isValidEmail(email)) {
        HttpServer.json(res, 400, { error: 'A valid email address is required for registration.' });
        return;
      }
      // Check unique email
      const existingByEmail = ctx.customerRepo.findByEmail(email);
      if (existingByEmail) {
        HttpServer.json(res, 409, { error: 'An account with this email address already exists. Please log in.' });
        return;
      }
    }

    // Generate 6-digit OTP from a CSPRNG
    const otpCode = String(crypto.randomInt(100000, 1000000));
    const expiresAt = new Date(Date.now() + OTP_TTL_MS).toISOString();
    otpFailures.delete(cleanMobile);

    if (existingUser) {
      ctx.customerRepo.setOtp(cleanMobile, otpCode, expiresAt);
    } else {
      pendingOtpChallenges.set(cleanMobile, {
        otpCode,
        expiresAt,
        name: name || `Customer ${cleanMobile.slice(-4)}`,
        email: email || `${cleanMobile}@customer.youpi.local`
      });
    }

    // Dispatch via WhatsApp Berry Protocol
    const berry = getBerry();
    let dispatchResult = { success: true, delivered: false, simulated: true };
    const displayName = existingUser?.name || name || '';

    if (berry) {
      try {
        dispatchResult = await berry.sendOtp(cleanMobile, otpCode, displayName);
      } catch (err) {
        console.warn(`[CustomerAuth] WhatsApp dispatch notice: ${err.message}`);
      }
    } else {
      console.log(`[CustomerAuth] Berry service not loaded. OTP not delivered for ${maskMobile(cleanMobile)}.`);
    }

    // Never log OTP codes.
    console.log(`[CustomerAuth] OTP issued for ${maskMobile(cleanMobile)} (expires in 5 mins)`);

    HttpServer.json(res, 200, {
      success: true,
      message: 'OTP sent to your WhatsApp number.',
      mobileNumber: cleanMobile,
      expiresInSeconds: 300,
      devOtp: exposeDevOtp() ? otpCode : undefined,
      dispatch: dispatchResult
    });
  });

  // 3. POST /api/v1/customer/verify-otp
  // Verifies 6-digit WhatsApp OTP, registers new user if needed, and logs them in
  server.post('/api/v1/customer/verify-otp', async (req, res) => {
    const ip = clientIp(req);
    if (enforce(res, [{ key: `verify-otp:ip:${ip}`, limit: 60, windowMs: 10 * MINUTE }])) return;
    const body = await HttpServer.parseBody(req).catch(() => ({}));
    const rawMobile = body.mobileNumber || body.phoneNumber || body.mobile || body.phone;
    const otp = String(body.otp || body.code || '').trim();

    if (!rawMobile || !otp) {
      HttpServer.json(res, 400, { error: 'Mobile number and 6-digit OTP code are required.' });
      return;
    }
    if (!/^\d{6}$/.test(otp)) {
      HttpServer.json(res, 400, { error: 'Invalid verification code. Please check and try again.' });
      return;
    }

    const cleanMobile = normalizeMobile(rawMobile);
    if (!cleanMobile) {
      HttpServer.json(res, 400, { error: 'Invalid mobile number.' });
      return;
    }

    let customer = ctx.customerRepo.findByMobile(cleanMobile);

    if (customer) {
      // Existing User Verification
      const verified = ctx.customerRepo.verifyOtp(cleanMobile, otp);
      if (!verified) {
        const burned = recordOtpFailure(cleanMobile);
        HttpServer.json(res, 400, {
          error: burned
            ? 'Too many wrong attempts. Please request a new OTP.'
            : 'Invalid or expired verification code. Please request a new OTP.'
        });
        return;
      }
      otpFailures.delete(cleanMobile);
      customer = verified;
    } else {
      // New User Registration Verification
      const pending = pendingOtpChallenges.get(cleanMobile);
      if (!pending) {
        HttpServer.json(res, 400, { error: 'No active OTP request found. Please request a new OTP.' });
        return;
      }
      if (new Date() > new Date(pending.expiresAt)) {
        pendingOtpChallenges.delete(cleanMobile);
        HttpServer.json(res, 400, { error: 'Verification code has expired. Please request a new OTP.' });
        return;
      }
      if (!safeEqual(pending.otpCode, otp)) {
        const burned = recordOtpFailure(cleanMobile);
        HttpServer.json(res, 400, {
          error: burned
            ? 'Too many wrong attempts. Please request a new OTP.'
            : 'Invalid verification code. Please check and try again.'
        });
        return;
      }
      otpFailures.delete(cleanMobile);
      if (new Date() > new Date(pending.expiresAt)) {
        pendingOtpChallenges.delete(cleanMobile);
        HttpServer.json(res, 400, { error: 'Verification code has expired. Please request a new OTP.' });
        return;
      }

      // Create new customer account in DB
      const resolvedName = cleanName(body.name || body.fullName || pending.name) || `Customer ${cleanMobile.slice(-4)}`;
      const resolvedEmail = normalizeEmail(body.email || pending.email) || `${cleanMobile}@customer.youpi.local`;

      try {
        customer = ctx.customerRepo.create({
          name: resolvedName,
          email: resolvedEmail,
          mobileNumber: cleanMobile,
          isPhoneVerified: true
        });
      } catch (err) {
        HttpServer.json(res, 400, { error: err.message });
        return;
      }

      pendingOtpChallenges.delete(cleanMobile);
    }

    // Server-side Ban Enforcement (Section 3)
    if (customer.status === 'BANNED') {
      HttpServer.json(res, 403, {
        error: 'ACCESS BLOCKED',
        message: 'Your account has been temporarily blocked because suspicious payment activity was detected. Our team will review the activity before access can be restored.',
        isBanned: true
      });
      return;
    }

    // Issue server-authoritative session
    const ipAddress = req.socket?.remoteAddress || null;
    const userAgent = req.headers['user-agent'] || null;
    const session = ctx.customerSessionRepo.create({
      customerId: customer.id,
      ipAddress,
      userAgent
    });

    res.setHeader('Set-Cookie', buildSessionCookie(session.token, undefined, req));

    if (ctx.auditRepo) {
      ctx.auditRepo.log({
        entityType: 'CUSTOMER',
        entityId: customer.id,
        action: 'CUSTOMER_WHATSAPP_OTP_LOGGED_IN',
        actorType: 'CUSTOMER',
        actorId: customer.id,
        details: { mobileNumber: customer.mobileNumber, email: customer.email }
      });
    }

    HttpServer.json(res, 200, {
      success: true,
      token: session.token,
      customerId: customer.id,
      phoneNumber: customer.mobileNumber,
      fullName: customer.name,
      customer: {
        id: customer.id,
        name: customer.name,
        email: customer.email,
        mobileNumber: customer.mobileNumber,
        status: customer.status,
        lastLoginAt: customer.lastLoginAt
      }
    });
  });

  // POST /api/v1/customer/register (Gateway-owned Sign Up)
  // Input: exactly name, email, mobileNumber, password
  server.post('/api/v1/customer/register', async (req, res) => {
    const ip = clientIp(req);
    if (enforce(res, [{ key: `register:ip:${ip}`, limit: 20, windowMs: 60 * MINUTE }])) return;
    const body = await HttpServer.parseBody(req);
    const { name, email, mobileNumber, password } = body;

    // Backward-compatibility field fallback if legacy fields are sent
    const resolvedName = cleanName(name || body.fullName || '');
    const resolvedMobile = normalizeMobile(mobileNumber || body.phoneNumber);
    let resolvedEmail = normalizeEmail(email);
    if (!resolvedEmail && resolvedMobile) {
      resolvedEmail = `${resolvedMobile}@customer.youpi.local`;
    }
    const resolvedPassword = password;

    if (!resolvedName) {
      HttpServer.json(res, 400, { error: 'Name is required.' });
      return;
    }
    if (!resolvedEmail || !isValidEmail(resolvedEmail)) {
      HttpServer.json(res, 400, { error: 'A valid email address is required.' });
      return;
    }
    if (!resolvedMobile || !isValidMobile(resolvedMobile)) {
      HttpServer.json(res, 400, { error: 'A valid 10-digit mobile number is required.' });
      return;
    }
    if (!isValidPassword(resolvedPassword)) {
      HttpServer.json(res, 400, { error: 'Password must be 8 to 128 characters long.' });
      return;
    }

    // Check unique email
    const existingByEmail = ctx.customerRepo.findByEmail(resolvedEmail);
    if (existingByEmail) {
      HttpServer.json(res, 409, { error: 'An account with this email address already exists.' });
      return;
    }

    // Check unique mobile
    const existingByMobile = ctx.customerRepo.findByMobile(resolvedMobile);
    if (existingByMobile) {
      HttpServer.json(res, 409, { error: 'An account with this mobile number already exists.' });
      return;
    }

    let customer;
    try {
      customer = ctx.customerRepo.create({
        name: resolvedName,
        email: resolvedEmail,
        mobileNumber: resolvedMobile,
        password: resolvedPassword
      });
    } catch (err) {
      HttpServer.json(res, 400, { error: err.message });
      return;
    }

    // Create authenticated server-authoritative session
    const ipAddress = req.socket?.remoteAddress || null;
    const userAgent = req.headers['user-agent'] || null;
    const session = ctx.customerSessionRepo.create({
      customerId: customer.id,
      ipAddress,
      userAgent
    });

    res.setHeader('Set-Cookie', buildSessionCookie(session.token, undefined, req));

    if (ctx.auditRepo) {
      ctx.auditRepo.log({
        entityType: 'CUSTOMER',
        entityId: customer.id,
        action: 'CUSTOMER_REGISTERED',
        actorType: 'CUSTOMER',
        actorId: customer.id,
        details: { email: customer.email, mobileNumber: customer.mobileNumber }
      });
    }

    HttpServer.json(res, 201, {
      success: true,
      token: session.token,
      customerId: customer.id,
      phoneNumber: customer.mobileNumber,
      fullName: customer.name,
      customer: {
        id: customer.id,
        name: customer.name,
        email: customer.email,
        mobileNumber: customer.mobileNumber,
        status: customer.status,
        createdAt: customer.createdAt
      }
    });
  });

  // POST /api/v1/customer/login (Gateway-owned Sign In)
  // Input: identifier (email or mobile) + password
  server.post('/api/v1/customer/login', async (req, res) => {
    const ip = clientIp(req);
    if (enforce(res, [{ key: `login:ip:${ip}`, limit: 30, windowMs: 15 * MINUTE }])) return;
    const body = await HttpServer.parseBody(req);
    const identifier = (body.identifier || body.email || body.mobileNumber || body.phoneNumber || '').trim();
    const password = body.password;

    if (!identifier || !password) {
      HttpServer.json(res, 400, { error: 'Email/mobile number and password are required.' });
      return;
    }

    const identifierKey = `login:id:${identifier.toLowerCase()}`;
    if (enforce(res, [{ key: identifierKey, limit: 10, windowMs: 15 * MINUTE }])) return;

    const verified = ctx.customerRepo.verifyCredentials(identifier, password);
    if (verified) resetRateLimit(identifierKey);
    if (!verified) {
      HttpServer.json(res, 401, { error: 'Invalid credentials. Please check your email/mobile and password.' });
      return;
    }

    // Server-side Ban Enforcement (Section 3)
    if (verified.status === 'BANNED') {
      HttpServer.json(res, 403, {
        error: 'ACCESS BLOCKED',
        message: 'Your account has been temporarily blocked because suspicious payment activity was detected. Our team will review the activity before access can be restored.',
        isBanned: true
      });
      return;
    }

    // Create session
    const ipAddress = req.socket?.remoteAddress || null;
    const userAgent = req.headers['user-agent'] || null;
    const session = ctx.customerSessionRepo.create({
      customerId: verified.id,
      ipAddress,
      userAgent
    });

    res.setHeader('Set-Cookie', buildSessionCookie(session.token, undefined, req));

    if (ctx.auditRepo) {
      ctx.auditRepo.log({
        entityType: 'CUSTOMER',
        entityId: verified.id,
        action: 'CUSTOMER_LOGGED_IN',
        actorType: 'CUSTOMER',
        actorId: verified.id,
        details: { identifier }
      });
    }

    HttpServer.json(res, 200, {
      success: true,
      token: session.token,
      customerId: verified.id,
      phoneNumber: verified.mobileNumber,
      fullName: verified.name,
      customer: {
        id: verified.id,
        name: verified.name,
        email: verified.email,
        mobileNumber: verified.mobileNumber,
        status: verified.status,
        lastLoginAt: verified.lastLoginAt
      }
    });
  });

  // GET /api/v1/customer/me (Verify active session & return profile)
  server.get('/api/v1/customer/me', async (req, res) => {
    const token = extractSessionToken(req);
    if (!token) {
      HttpServer.json(res, 401, { error: 'No active session token provided.' });
      return;
    }

    const authContext = ctx.customerSessionRepo.findByToken(token);
    if (!authContext) {
      HttpServer.json(res, 401, { error: 'Session expired or invalid.' });
      return;
    }

    const { customer, session } = authContext;
    HttpServer.json(res, 200, {
      authenticated: true,
      customer: {
        id: customer.id,
        name: customer.name,
        email: customer.email,
        mobileNumber: customer.mobileNumber,
        status: customer.status,
        lastLoginAt: customer.lastLoginAt
      },
      session: {
        id: session.id,
        expiresAt: session.expiresAt
      }
    });
  });

  // POST /api/v1/customer/logout (Revoke active session token)
  server.post('/api/v1/customer/logout', async (req, res) => {
    const body = await HttpServer.parseBody(req).catch(() => ({}));
    const token = extractSessionToken(req) || body.token;

    if (token) {
      ctx.customerSessionRepo.revokeToken(token);
    }

    res.setHeader('Set-Cookie', 'youpi_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax');
    HttpServer.json(res, 200, { success: true, message: 'Logged out successfully.' });
  });

  // POST /api/v1/customer/switch-account (Validates target saved account token)
  server.post('/api/v1/customer/switch-account', async (req, res) => {
    const body = await HttpServer.parseBody(req);
    const targetToken = body.token || body.sessionToken;

    if (!targetToken) {
      HttpServer.json(res, 400, { error: 'Target account session token is required.' });
      return;
    }

    const authContext = ctx.customerSessionRepo.findByToken(targetToken);
    if (!authContext) {
      HttpServer.json(res, 401, { error: 'Target account session has expired. Please log in again.' });
      return;
    }

    res.setHeader('Set-Cookie', buildSessionCookie(authContext.session.token, undefined, req));

    HttpServer.json(res, 200, {
      success: true,
      token: authContext.session.token,
      customer: {
        id: authContext.customer.id,
        name: authContext.customer.name,
        email: authContext.customer.email,
        mobileNumber: authContext.customer.mobileNumber
      }
    });
  });

  // Decommissioned Customer Endpoints (HTTP 404)
  server.get('/api/v1/customer/payments', async (req, res) => {
    HttpServer.json(res, 404, { error: 'Feature not available' });
  });

  server.post('/api/v1/customer/tickets', async (req, res) => {
    HttpServer.json(res, 404, { error: 'Feature not available' });
  });

  server.get('/api/v1/customer/tickets/:id/messages', async (req, res) => {
    HttpServer.json(res, 404, { error: 'Feature not available' });
  });

  server.post('/api/v1/customer/tickets/:id/messages', async (req, res) => {
    HttpServer.json(res, 404, { error: 'Feature not available' });
  });

  server.get('/api/v1/customer/tickets/:id/stream', async (req, res) => {
    HttpServer.json(res, 404, { error: 'Feature not available' });
  });
}
