// Tests for the shared underwriter registry — the single source of truth for
// Last Expense pricing, eligibility and benefit tiers (used by both the browser
// quote form and the server's authoritative re-check). Pure logic, no I/O.
//
// Run with: npm test   (uses Node's built-in test runner, no dependencies)

const test = require('node:test');
const assert = require('node:assert/strict');
const LE = require('../public/last-expense-underwriters.js');

test('get() returns a profile for a known underwriter and null otherwise', () => {
  assert.equal(LE.get('heritage').id, 'heritage');
  assert.equal(LE.get('heritage').label, 'Liberty Life'); // renamed from "Liberty | Heritage"
  assert.equal(LE.get('nope'), null);
});

test('listFor() reflects availability: individual = Liberty Life only, group = all three', () => {
  const individual = LE.listFor('individual').map(u => u.id).sort();
  const group = LE.listFor('group').map(u => u.id).sort();
  assert.deepEqual(individual, ['heritage']);
  assert.deepEqual(group, ['absa', 'capex', 'heritage']);
});

test('coverAmount() maps a 1-based cover option to the benefit tier', () => {
  assert.equal(LE.coverAmount('heritage', 1), 50000);
  assert.equal(LE.coverAmount('heritage', 10), 500000);
  assert.equal(LE.coverAmount('heritage', 11), null); // out of range
});

test('allowedDependents() gates relationships by cover type', () => {
  assert.deepEqual(LE.allowedDependents('heritage', 'member'), []);
  assert.deepEqual(LE.allowedDependents('heritage', 'nuclear'), ['spouse', 'child']);
  assert.ok(LE.allowedDependents('heritage', 'extended').includes('mother'));
  assert.ok(LE.allowedDependents('heritage', 'extended').includes('sibling'));
  // single-cover-type underwriter falls back to its only type
  assert.ok(LE.allowedDependents('absa').includes('spouse'));
});

test('computePremium() — Liberty Life (modular) member/nuclear', () => {
  assert.deepEqual(
    LE.computePremium('heritage', { coverType: 'member', coverOption: 1, dependents: [] }),
    { base: 680, extras: 0, total: 680 }
  );
  assert.deepEqual(
    LE.computePremium('heritage', { coverType: 'nuclear', coverOption: 1, dependents: [] }),
    { base: 1130, extras: 0, total: 1130 }
  );
});

test('computePremium() — Liberty Life extended charges perParent for each parent', () => {
  const oneParent = LE.computePremium('heritage', {
    coverType: 'extended', coverOption: 1,
    dependents: [{ relationship: 'mother' }],
  });
  // extended base uses the nuclear column (1130) + 1 * perParent[0] (1365)
  assert.deepEqual(oneParent, { base: 1130, extras: 1365, total: 2495 });

  const twoParents = LE.computePremium('heritage', {
    coverType: 'extended', coverOption: 1,
    dependents: [{ relationship: 'mother' }, { relationship: 'father' }],
  });
  assert.equal(twoParents.extras, 2 * 1365);
  assert.equal(twoParents.total, 1130 + 2 * 1365);
});

test('computePremium() — extra children beyond the included 6, plus siblings, cost perParent', () => {
  const deps = [];
  for (let i = 0; i < 8; i++) deps.push({ relationship: 'child' }); // 2 beyond the 6 cap
  deps.push({ relationship: 'sibling' });                            // +1 sibling
  const r = LE.computePremium('heritage', { coverType: 'extended', coverOption: 1, dependents: deps });
  // 2 extra children + 1 sibling = 3 * perParent[0] (1365)
  assert.equal(r.extras, 3 * 1365);
});

test('computePremium() — ABSA (base_addon) adds for extra and 25–29-year-old children', () => {
  // Build children DOBs relative to a fixed "today" via an injected age function
  const ages = { young: '2015-01-01', adult2529: '1999-01-01' };
  const ageFn = (dob) => (dob === ages.adult2529 ? 27 : 8);

  // 5 young children: 4 included, 1 extra at extra_child[0] (250)
  const five = LE.computePremium('absa', {
    coverType: 'family', coverOption: 1,
    dependents: Array.from({ length: 5 }, () => ({ relationship: 'child', date_of_birth: ages.young })),
  }, ageFn);
  assert.equal(five.base, 5000);
  assert.equal(five.extras, 250);

  // A 25–29 child is charged the child_25_29 rate (300) regardless of position
  const older = LE.computePremium('absa', {
    coverType: 'family', coverOption: 1,
    dependents: [{ relationship: 'child', date_of_birth: ages.adult2529 }],
  }, ageFn);
  assert.equal(older.extras, 300);
});

test('computePremium() — invalid underwriter or out-of-range option returns null', () => {
  assert.equal(LE.computePremium('nope', { coverType: 'member', coverOption: 1 }), null);
  assert.equal(LE.computePremium('heritage', { coverType: 'member', coverOption: 0 }), null);
  assert.equal(LE.computePremium('heritage', { coverType: 'member', coverOption: 99 }), null);
  assert.equal(LE.computePremium('heritage', { coverType: 'bogus', coverOption: 1 }), null);
});
