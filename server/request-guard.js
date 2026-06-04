// ─────────────────────────────────────────────────────────────────────────────
// request-guard.js — the shared security preamble for every POST handler.
//
// Collapses the three-step preamble — honeypot → rate-limit → CSRF — into one
// seam, so the canonical check ORDER lives in exactly one place instead of being
// re-typed in every route. The two stateful checks (rate-limit, CSRF) are
// injected, so the guard's logic is testable with fakes — no real clock, no
// shared rate-limit map.
//
// guard(req, body, opts) returns:
//   { ok: true, ip }                          → caller proceeds; ip is resolved
//   { ok: false, status, body, honeypot? }    → caller sends `body` with `status`
//                                                and returns; `honeypot` is set on
//                                                a trap hit so the caller can log.
//
// opts:
//   rateLimit    — false to skip the rate-limit step (e.g. group registration)
//   honeypotBody — () => object : the fake-success body returned on a trap hit
//                  (bots must not learn they were caught), evaluated lazily
//   csrfMessage  — the error string sent on an invalid/expired CSRF token
// ─────────────────────────────────────────────────────────────────────────────

function createRequestGuard({ checkRateLimit, validateCsrfToken }) {
  return function guard(req, body, opts = {}) {
    const {
      rateLimit = true,
      honeypotBody = () => ({ success: true }),
      csrfMessage = 'Invalid or expired session. Please refresh the page and try again.',
    } = opts;

    const ip = (req.socket && req.socket.remoteAddress) || 'unknown';

    // 1. Honeypot — a hidden field only bots fill. Return a fake success so the
    //    bot can't tell it was caught.
    if (body.website && String(body.website).trim().length > 0) {
      return { ok: false, honeypot: true, status: 200, body: honeypotBody() };
    }

    // 2. Rate limit (skipped when opts.rateLimit === false)
    if (rateLimit && !checkRateLimit(ip)) {
      return { ok: false, status: 429, body: { error: 'Too many requests. Please try again later.' } };
    }

    // 3. CSRF
    if (!validateCsrfToken(body.csrf_token)) {
      return { ok: false, status: 403, body: { error: csrfMessage } };
    }

    return { ok: true, ip };
  };
}

module.exports = { createRequestGuard };
