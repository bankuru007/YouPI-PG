/**
 * Regression tests for the second hardening pass:
 *  - customer OTP brute force, user enumeration, password policy
 *  - payment input validation, autoActivate and customer binding restrictions
 *  - CORS, error leakage, merchant-backend endpoints, device verification
 *  - observer services (Gmail / SMS) locked down, OAuth state, reflected XSS
 *  - checkout page template escaping
 *  - rate limiting
 *
 * Requests are sent WITHOUT harness credentials unless a test adds them explicitly.
 */
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { Database } from '@youpi/db';
import { createOAuthState, verifyOAuthState } from '@youpi/common';
import { startServer as startPaymentApi } from '../index.js';
import { startGmailObserver } from '../../../gmail-observer/src/index.js';
import { startSmsObserver } from '../../../sms-observer/src/index.js';
import { startCheckoutServer } from '../../../checkout-portal/src/index.js';
import { startCoinWalletStore } from '../../../coin-wallet-store/src/index.js';

const ADMIN_TOKEN = 'hardening-test-admin-token-0123456789abcdef01234567';
const OBSERVER_TOKEN = 'hardening-test-observer-token-0123456789abcdef0123';
const ADMIN = { 'X-Admin-Token': ADMIN_TOKEN };

function request(baseUrl, urlPath, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlPath, baseUrl);
    const req = http.request(url, { method, headers: { 'Content-Type': 'application/json', ...headers } }, res => {
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => {
        let parsed;
        try { parsed = JSON.parse(data); } catch { parsed = data; }
        resolve({ status: res.statusCode, body: parsed, headers: res.headers, text: data });
      });
    });
    req.on('error', reject);
    if (body !== undefined) req.write(typeof body === 'string' ? body : JSON.stringify(body));
    req.end();
  });
}

describe('Security hardening (second pass)', () => {
  let api, apiUrl, gmail, gmailUrl, sms, smsUrl, checkout, checkoutUrl, store, storeUrl, db;
  const savedEnv = {};
  const ENV_KEYS = ['ADMIN_API_TOKEN', 'OBSERVER_INGEST_TOKEN', 'PAYMENT_API_PORT', 'YOUPI_DEV_OTP', 'YOUPI_RATE_LIMIT_DISABLED', 'CORS_ALLOWED_ORIGINS'];

  before(async () => {
    for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
    process.env.ADMIN_API_TOKEN = ADMIN_TOKEN;
    process.env.OBSERVER_INGEST_TOKEN = OBSERVER_TOKEN;
    process.env.YOUPI_DEV_OTP = '1';
    process.env.YOUPI_RATE_LIMIT_DISABLED = '1';
    delete process.env.CORS_ALLOWED_ORIGINS;
    globalThis.__YOUPI_TEST_NO_AUTH = true;

    db = new Database({ inMemory: true });
    api = await startPaymentApi(6187, db);
    apiUrl = `http://localhost:${api.port}`;
    process.env.PAYMENT_API_PORT = String(api.port);
    gmail = await startGmailObserver(6188, { apiBaseUrl: apiUrl });
    gmailUrl = `http://localhost:${gmail.port}`;
    sms = await startSmsObserver(6189, { apiBaseUrl: apiUrl });
    smsUrl = `http://127.0.0.1:${sms.port}`;
    checkout = await startCheckoutServer(6190, { apiBaseUrl: apiUrl });
    checkoutUrl = `http://localhost:${checkout.port}`;
    store = await startCoinWalletStore(6191, { gatewayApiUrl: apiUrl, webhookSecret: 'store-test-secret' });
    storeUrl = `http://localhost:${store.port}`;
  });

  after(async () => {
    globalThis.__YOUPI_TEST_NO_AUTH = false;
    for (const s of [store, checkout, sms, gmail, api]) {
      try { await s.close(); } catch {}
    }
    db.close();
    for (const [k, v] of Object.entries(savedEnv)) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
  });

  // ------------------------------------------------------------- customers
  test('check-user does not leak customer identity', async () => {
    const send = await request(apiUrl, '/api/v1/customer/send-otp', {
      method: 'POST', body: { mobileNumber: '9811122233', isNewUser: true, name: 'Asha Verma', email: 'asha@example.com' }
    });
    assert.equal(send.status, 200);
    const verify = await request(apiUrl, '/api/v1/customer/verify-otp', {
      method: 'POST', body: { mobileNumber: '9811122233', otp: send.body.devOtp }
    });
    assert.equal(verify.status, 200);

    const res = await request(apiUrl, '/api/v1/customer/check-user', { method: 'POST', body: { mobileNumber: '9811122233' } });
    assert.equal(res.status, 200);
    assert.equal(res.body.exists, true);
    assert.equal(res.body.customer.id, undefined);
    assert.notEqual(res.body.customer.name, 'Asha Verma');
    assert.notEqual(res.body.customer.email, 'asha@example.com');
  });

  test('OTP is burned after 5 wrong attempts', async () => {
    const send = await request(apiUrl, '/api/v1/customer/send-otp', {
      method: 'POST', body: { mobileNumber: '9822233344', isNewUser: true, name: 'Ravi K', email: 'ravi@example.com' }
    });
    const realOtp = send.body.devOtp;
    assert.match(realOtp, /^\d{6}$/);
    const wrong = realOtp === '000000' ? '111111' : '000000';
    for (let i = 0; i < 5; i++) {
      const r = await request(apiUrl, '/api/v1/customer/verify-otp', { method: 'POST', body: { mobileNumber: '9822233344', otp: wrong } });
      assert.equal(r.status, 400);
    }
    const late = await request(apiUrl, '/api/v1/customer/verify-otp', { method: 'POST', body: { mobileNumber: '9822233344', otp: realOtp } });
    assert.equal(late.status, 400, 'the real code must stop working after too many failures');
  });

  test('devOtp is not exposed without the explicit dev flag', async () => {
    process.env.YOUPI_DEV_OTP = '';
    try {
      const send = await request(apiUrl, '/api/v1/customer/send-otp', {
        method: 'POST', body: { mobileNumber: '9833344455', isNewUser: true, name: 'Meera S', email: 'meera@example.com' }
      });
      assert.equal(send.status, 200);
      assert.equal(send.body.devOtp, undefined);
    } finally {
      process.env.YOUPI_DEV_OTP = '1';
    }
  });

  test('weak passwords are rejected at registration', async () => {
    const res = await request(apiUrl, '/api/v1/customer/register', {
      method: 'POST', body: { name: 'Test', email: 'weak@example.com', mobileNumber: '9844455566', password: 'abc123' }
    });
    assert.equal(res.status, 400);
  });

  // ------------------------------------------------------------- payments
  test('payment creation rejects unsafe input', async () => {
    const xss = await request(apiUrl, '/api/v1/payments', { method: 'POST', body: { orderId: '<img src=x onerror=alert(1)>', amount: '10.00' } });
    assert.equal(xss.status, 400);
    const badMethod = await request(apiUrl, '/api/v1/payments', { method: 'POST', body: { orderId: 'ORD-M1', amount: '10.00', method: 'FREE' } });
    assert.equal(badMethod.status, 400);
    const badReturn = await request(apiUrl, '/api/v1/payments', { method: 'POST', body: { orderId: 'ORD-R1', amount: '10.00', returnUrl: 'javascript:alert(1)' } });
    assert.equal(badReturn.status, 400);
    const huge = await request(apiUrl, '/api/v1/payments', { method: 'POST', body: { orderId: 'ORD-H1', amount: '99999999.00' } });
    assert.equal(huge.status, 400);
  });

  test('public callers cannot auto-activate a UPI slot or bind someone else\'s customer', async () => {
    const res = await request(apiUrl, '/api/v1/payments', { method: 'POST', body: { orderId: 'ORD-AUTO-1', amount: '15.00', autoActivate: true } });
    assert.equal(res.status, 201);
    assert.equal(res.body.status, 'INITIATED');

    const spoof = await request(apiUrl, '/api/v1/payments', {
      method: 'POST', body: { orderId: 'ORD-CUST-1', amount: '15.00', customerId: '00000000-0000-0000-0000-000000000002' }
    });
    assert.equal(spoof.status, 403);

    const bind = await request(apiUrl, `/api/v1/checkout/${res.body.paymentId}/bind-customer`, {
      method: 'POST', body: { customerId: '00000000-0000-0000-0000-000000000002' }
    });
    assert.equal(bind.status, 401);
  });

  test('merchant-backend COD endpoints require the admin token', async () => {
    const created = await request(apiUrl, '/api/v1/payments', { method: 'POST', headers: ADMIN, body: { orderId: 'ORD-COD-PII', amount: '20.00' } });
    const byOrder = await request(apiUrl, '/api/v1/orders/ORD-COD-PII/cod');
    assert.equal(byOrder.status, 401);
    const byId = await request(apiUrl, `/api/v1/payments/${created.body.paymentId}/cod`);
    assert.equal(byId.status, 401);
    const ok = await request(apiUrl, '/api/v1/orders/ORD-COD-PII/cod', { headers: ADMIN });
    assert.equal(ok.status, 200);
  });

  test('device verify requires a credential and hides customerId otherwise', async () => {
    const reg = await request(apiUrl, '/api/v1/devices/register', { method: 'POST', body: { publicKey: 'hardening-device-key', signals: {} } });
    assert.ok(reg.body.deviceId);
    const bare = await request(apiUrl, '/api/v1/devices/verify', { method: 'POST', body: { deviceId: reg.body.deviceId } });
    assert.equal(bare.status, 401);
    assert.equal(bare.body.customerId, undefined);
    const again = await request(apiUrl, '/api/v1/devices/register', { method: 'POST', body: { publicKey: 'hardening-device-key', signals: {} } });
    assert.equal(again.body.deviceToken, null, 'device token is only issued once');
    const read = await request(apiUrl, `/api/v1/devices/${reg.body.deviceId}`);
    assert.equal(read.status, 401);
  });

  // ------------------------------------------------------------- transport
  test('admin routes never send CORS headers; errors do not leak internals', async () => {
    const adminRes = await request(apiUrl, '/api/v1/admin/queue', { headers: { ...ADMIN, Origin: 'https://evil.example' } });
    assert.equal(adminRes.status, 200);
    assert.equal(adminRes.headers['access-control-allow-origin'], undefined);

    const publicRes = await request(apiUrl, '/api/v1/checkout/server-health');
    assert.equal(publicRes.headers['access-control-allow-origin'], '*');

    const malformed = await request(apiUrl, '/api/v1/payments', { method: 'POST', body: '{not json' });
    assert.equal(malformed.status, 400);

    const notFound = await request(apiUrl, '/api/v1/nope/<script>');
    assert.equal(notFound.status, 404);
    assert.ok(!String(notFound.text).includes('<script>'));
  });

  test('oversized bodies are rejected with 413', async () => {
    const big = JSON.stringify({ orderId: 'BIG', amount: '1.00', pad: 'x'.repeat(1100 * 1024) });
    const res = await request(apiUrl, '/api/v1/payments', { method: 'POST', body: big });
    assert.equal(res.status, 413);
  });

  test('rate limits apply to OTP sending', async () => {
    process.env.YOUPI_RATE_LIMIT_DISABLED = '';
    try {
      const body = { mobileNumber: '9855566677', isNewUser: true, name: 'Limit Test', email: 'limit@example.com' };
      const first = await request(apiUrl, '/api/v1/customer/send-otp', { method: 'POST', body });
      assert.equal(first.status, 200);
      const second = await request(apiUrl, '/api/v1/customer/send-otp', { method: 'POST', body });
      assert.equal(second.status, 429, 'second OTP within 30 seconds is throttled');
    } finally {
      process.env.YOUPI_RATE_LIMIT_DISABLED = '1';
    }
  });

  // ------------------------------------------------------------- observers
  test('Gmail observer only exposes health and the OAuth callback', async () => {
    const health = await request(gmailUrl, '/health');
    assert.equal(health.status, 200);
    const inject = await request(gmailUrl, '/process-email', {
      method: 'POST', body: { from: 'alerts@hdfcbank.bank.in', subject: 'Credit', body: 'Rs 10.00 credited UPI Ref 512345678999' }
    });
    assert.equal(inject.status, 401);
    for (const p of ['/api/sweep', '/stop', '/api/browser/launch-login']) {
      const r = await request(gmailUrl, p, { method: 'POST', body: {} });
      assert.equal(r.status, 401, `${p} must be locked`);
    }
    const url = await request(gmailUrl, '/oauth/url');
    assert.equal(url.status, 401);
  });

  test('Gmail OAuth callback requires a valid signed state and escapes errors', async () => {
    const noState = await request(gmailUrl, '/oauth/callback?code=attacker-code');
    assert.equal(noState.status, 400);
    assert.ok(noState.text.includes('Invalid or expired OAuth state'));

    const xss = await request(gmailUrl, '/oauth/callback?error=%3Cscript%3Ealert(1)%3C/script%3E');
    assert.ok(!xss.text.includes('<script>'));

    const state = createOAuthState();
    assert.equal(verifyOAuthState(state), true);
    assert.equal(verifyOAuthState(state.replace(/.$/, c => (c === 'A' ? 'B' : 'A'))), false);
    assert.equal(verifyOAuthState('forged.value'), false);
  });

  test('SMS observer rejects injected SMS without a token', async () => {
    const res = await request(smsUrl, '/process-sms', { method: 'POST', body: { sender: 'HDFCBK', text: 'Rs 10 credited Ref 512345678998' } });
    assert.equal(res.status, 401);
    const ok = await request(smsUrl, '/health');
    assert.equal(ok.status, 200);
  });

  // ------------------------------------------------------------- pages
  test('checkout page rejects malformed payment IDs and escapes template values', async () => {
    const bad = await request(checkoutUrl, '/checkout/%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E');
    assert.equal(bad.status, 404);

    const created = await request(apiUrl, '/api/v1/payments', { method: 'POST', headers: ADMIN, body: { orderId: 'ORD-PAGE-1', amount: '12.00' } });
    const page = await request(checkoutUrl, `/checkout/${created.body.paymentId}`);
    assert.equal(page.status, 200);
    assert.ok(page.text.includes('ORD-PAGE-1'));
  });

  test('demo store result pages escape reflected parameters', async () => {
    const res = await request(storeUrl, `/order-failed?order_id=${encodeURIComponent('<script>alert(1)</script>')}&reason=${encodeURIComponent('"><img src=x onerror=alert(2)>')}`);
    assert.equal(res.status, 200);
    assert.ok(!res.text.includes('<script>alert(1)</script>'));
    assert.ok(!res.text.includes('<img src=x'));
  });
});
