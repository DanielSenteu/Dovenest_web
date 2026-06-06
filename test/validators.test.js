// Tests for validators.js — the deepened form-validation module.
// The interface is the test surface: feed a payload, assert the returned
// error list. A pinned `now` makes every age-band check deterministic.
//
// Run with: npm test

const test = require('node:test');
const assert = require('node:assert/strict');
const V = require('../server/validators.js');

const NOW = new Date('2026-06-03T12:00:00Z'); // pinned clock for age math
const png = 'data:image/png;base64,xxx';
const hasErr = (errors, needle) => errors.some(e => e.includes(needle));

// ── Last Expense ─────────────────────────────────────────────────────────────
function validLe(extra = {}) {
  return {
    application_type: 'individual', underwriter: 'heritage', cover_scope: 'extended',
    cover_option: 1, full_name: 'Test User', date_of_birth: '1990-01-01', gender: 'M',
    national_id: '12345678', kra_pin: 'A123456789Z', email: 'a@b.com', mobile: '+254712345678',
    town: 'Nairobi', occupation: 'Engineer', terms_accepted: true,
    documents: { principal_national_id: png, principal_kra_pin: png, signature: png },
    ...extra,
  };
}

test('LE: a complete, valid individual application has no errors', () => {
  assert.deepEqual(V.validateLePayload(validLe(), NOW), []);
});

test('LE: a biological parent dependent passes; a non-attested one is rejected', () => {
  const ok = validLe({ dependents: [{ relationship: 'mother', full_name: 'Mum', date_of_birth: '1960-01-01', is_biological: true }] });
  assert.deepEqual(V.validateLePayload(ok, NOW), []);

  const bad = validLe({ dependents: [{ relationship: 'mother', full_name: 'Mum', date_of_birth: '1960-01-01' }] });
  assert.ok(hasErr(V.validateLePayload(bad, NOW), 'only biological parents'));
});

test('LE: principal outside the 18–65 age band is rejected (deterministic via pinned now)', () => {
  const tooOld = validLe({ date_of_birth: '1950-01-01' }); // age 76 at NOW
  assert.ok(hasErr(V.validateLePayload(tooOld, NOW), 'Principal member must be aged 18–65'));
});

test('LE: individuals must use Liberty Life; missing docs are caught', () => {
  assert.ok(hasErr(V.validateLePayload(validLe({ underwriter: 'absa' }), NOW), 'Liberty Life'));
  assert.ok(hasErr(V.validateLePayload(validLe({ documents: {} }), NOW), 'principal_national_id'));
});

// ── Flying Doctor ────────────────────────────────────────────────────────────
function validFd(extra = {}) {
  return {
    plan: 'silver', full_name: 'Prop', phone: '+254712345678', email: 'a@b.com',
    members: [{ full_name: 'Self', date_of_birth: '1985-01-01', id_passport: '12345678', relation: 'self' }],
    documents: { signature: png }, terms_accepted: true, ...extra,
  };
}

test('FD: valid payload passes; a parent member needs biological attestation', () => {
  assert.deepEqual(V.validateFdPayload(validFd(), NOW), []);
  const parent = validFd({ members: [{ full_name: 'Mum', date_of_birth: '1960-01-01', id_passport: '87654321', relation: 'parent' }] });
  assert.ok(hasErr(V.validateFdPayload(parent, NOW), 'only biological parents'));
});

test('FD: missing signature is rejected', () => {
  assert.ok(hasErr(V.validateFdPayload(validFd({ documents: {} }), NOW), 'signature'));
});

// ── Travel ───────────────────────────────────────────────────────────────────
function validTravel(extra = {}) {
  return {
    destination: 'UK', departure_date: '2026-07-01', return_date: '2026-07-10',
    purpose: 'leisure', cover_type: 'premier_worldwide', payment_method: 'mpesa',
    full_name: 'Prop', date_of_birth: '1985-01-01', occupation: 'Eng', town: 'Nairobi',
    email: 'a@b.com', phone: '+254712345678', beneficiary_name: 'Ben', beneficiary_relation: 'spouse',
    travellers: [{ full_name: 'Self', date_of_birth: '1985-01-01', id_passport: '12345678', relation: 'self' }],
    documents: { signature: png }, terms_accepted: true, ...extra,
  };
}

test('Travel: valid payload passes; a past departure date is rejected (pinned now)', () => {
  assert.deepEqual(V.validateTravelQuotePayload(validTravel(), NOW), []);
  const past = validTravel({ departure_date: '2026-06-01', return_date: '2026-06-10' }); // before NOW
  assert.ok(hasErr(V.validateTravelQuotePayload(past, NOW), 'departure_date must be today or future'));
});

test('Travel: a parent traveller needs biological attestation', () => {
  const parent = validTravel({ travellers: [{ full_name: 'Mum', date_of_birth: '1960-01-01', id_passport: '87654321', relation: 'parent' }] });
  assert.ok(hasErr(V.validateTravelQuotePayload(parent, NOW), 'only biological parents'));
});

// ── Motor ────────────────────────────────────────────────────────────────────
function validMotor(extra = {}) {
  return {
    policy_type: 'personal', first_name: 'A', last_name: 'B', experience_years: 5,
    date_of_birth: '1990-01-01', email: 'a@b.com', phone: '+254712345678',
    vehicle_category: 'PRIVATE CAR', terms_accepted: true, ...extra,
  };
}

test('Motor: valid payload passes; an under-16 driver is rejected (pinned now)', () => {
  assert.deepEqual(V.validateMotorQuotePayload(validMotor(), NOW), []);
  const kid = validMotor({ date_of_birth: '2015-01-01' }); // age ~11 at NOW
  assert.ok(hasErr(V.validateMotorQuotePayload(kid, NOW), 'Minimum age is 16'));
});

// ── Contact ──────────────────────────────────────────────────────────────────
test('Contact: product must match the source page; general needs a message', () => {
  const mismatch = { kind: 'product_inquiry', source_page: 'motor-insurance.html', full_name: 'A B', email: 'a@b.com', phone: '+254712345678', country: 'Kenya', product: 'travel' };
  assert.ok(hasErr(V.validateContactPayload(mismatch), 'does not match the source page'));

  const general = { kind: 'general', source_page: 'contact.html', full_name: 'A B', email: 'a@b.com' };
  assert.ok(hasErr(V.validateContactPayload(general), 'Message is required'));
});

// ── Determinism guarantee ────────────────────────────────────────────────────
test('age math is driven by the injected clock, not the wall clock', () => {
  // Same payload, two different "today"s → different age-band outcome.
  const le = validLe({ date_of_birth: '1990-01-01' });
  assert.deepEqual(V.validateLePayload(le, new Date('2026-06-03')), []);          // age 36 → ok
  assert.ok(hasErr(V.validateLePayload(le, new Date('2070-01-01')), 'aged 18–65')); // age 80 → rejected
});

// ── Terms & Conditions ───────────────────────────────────────────────────────
test('every quote form rejects a submission that did not accept the Terms & Conditions', () => {
  const drop = (obj) => { const c = { ...obj }; delete c.terms_accepted; return c; };
  assert.ok(hasErr(V.validateLePayload(drop(validLe()), NOW), 'Terms & Conditions'));
  assert.ok(hasErr(V.validateFdPayload(drop(validFd()), NOW), 'Terms & Conditions'));
  assert.ok(hasErr(V.validateTravelQuotePayload(drop(validTravel()), NOW), 'Terms & Conditions'));
  assert.ok(hasErr(V.validateMotorQuotePayload(drop(validMotor()), NOW), 'Terms & Conditions'));
  // A literal `false` (unticked box forwarded by a tampering client) is also rejected.
  assert.ok(hasErr(V.validateMotorQuotePayload({ ...validMotor(), terms_accepted: false }, NOW), 'Terms & Conditions'));
});
