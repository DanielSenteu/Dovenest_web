// Tests for request-guard.js — the honeypot → rate-limit → CSRF seam.
// The two stateful checks are injected, so the guard's logic (order, the
// honeypot fake-success, the rate-limit skip) is fully deterministic here.
//
// Run with: npm test

const test = require('node:test');
const assert = require('node:assert/strict');
const { createRequestGuard } = require('../server/request-guard.js');

const req = (ip = '1.2.3.4') => ({ socket: { remoteAddress: ip } });
const pass = () => true;
const fail = () => false;

test('a clean request passes and returns the resolved ip', () => {
  const guard = createRequestGuard({ checkRateLimit: pass, validateCsrfToken: pass });
  const r = guard(req(), { csrf_token: 'ok' });
  assert.deepEqual(r, { ok: true, ip: '1.2.3.4' });
});

test('a filled honeypot returns a fake success — and never reveals detection', () => {
  // checks that WOULD fail are never consulted once the trap is hit
  let csrfCalled = false;
  const guard = createRequestGuard({ checkRateLimit: fail, validateCsrfToken: () => { csrfCalled = true; return false; } });
  const r = guard(req(), { website: 'spam', csrf_token: 'whatever' }, { honeypotBody: () => ({ success: true, ref: 'FAKE-1' }) });
  assert.equal(r.ok, false);
  assert.equal(r.honeypot, true);
  assert.equal(r.status, 200);
  assert.deepEqual(r.body, { success: true, ref: 'FAKE-1' });
  assert.equal(csrfCalled, false, 'honeypot short-circuits before CSRF');
});

test('honeypot is checked before rate-limit (order matters)', () => {
  let rateCalled = false;
  const guard = createRequestGuard({ checkRateLimit: () => { rateCalled = true; return true; }, validateCsrfToken: pass });
  guard(req(), { website: 'x', csrf_token: 'ok' });
  assert.equal(rateCalled, false, 'rate-limit not consulted on a honeypot hit');
});

test('a rate-limited request is rejected with 429 before CSRF runs', () => {
  let csrfCalled = false;
  const guard = createRequestGuard({ checkRateLimit: fail, validateCsrfToken: () => { csrfCalled = true; return true; } });
  const r = guard(req(), { csrf_token: 'ok' });
  assert.equal(r.ok, false);
  assert.equal(r.status, 429);
  assert.match(r.body.error, /Too many requests/);
  assert.equal(csrfCalled, false, 'rate-limit short-circuits before CSRF');
});

test('rateLimit:false skips the rate-limit step entirely (group registration)', () => {
  let rateCalled = false;
  const guard = createRequestGuard({ checkRateLimit: () => { rateCalled = true; return false; }, validateCsrfToken: pass });
  const r = guard(req(), { csrf_token: 'ok' }, { rateLimit: false });
  assert.equal(r.ok, true);
  assert.equal(rateCalled, false, 'rate-limit never called when disabled');
});

test('an invalid CSRF token yields 403 with the given message', () => {
  const guard = createRequestGuard({ checkRateLimit: pass, validateCsrfToken: fail });
  const r = guard(req(), { csrf_token: 'bad' }, { csrfMessage: 'Invalid session. Please refresh and try again.' });
  assert.equal(r.ok, false);
  assert.equal(r.status, 403);
  assert.equal(r.body.error, 'Invalid session. Please refresh and try again.');
});

test('missing socket falls back to "unknown" ip', () => {
  const guard = createRequestGuard({ checkRateLimit: pass, validateCsrfToken: pass });
  const r = guard({}, { csrf_token: 'ok' });
  assert.equal(r.ip, 'unknown');
});
