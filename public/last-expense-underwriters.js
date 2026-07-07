/* ============================================================================
 * DoveNest — Last Expense Underwriter Registry  (single source of truth)
 * ----------------------------------------------------------------------------
 * Loaded by BOTH the browser (last-expense-quote.html) and the Node server
 * (server/server.js), so the quote UI, client-side pricing, and server-side
 * validation / premium re-computation can never drift apart.
 *
 * To add or change an underwriter, edit ONLY this file.
 *
 * Concepts
 *   • benefitTiers  — the sum-assured options (KES). Index 0..n maps to the
 *                     stored `cover_option` (1-based) and `cover_amount`.
 *   • coverTypes    — WHO is covered: 'member' | 'nuclear' | 'extended'.
 *                     Stored as `cover_scope`. Drives which dependents the
 *                     form allows and (for modular underwriters) the price.
 *   • pricing.model — 'modular'  : member / nuclear / extended-bundle tables,
 *                                   plus perAdditional for siblings & extra
 *                                   children (Liberty Life)
 *                     'base_addon': one family base + extra-child / 25-29 child
 *                                   add-ons (ABSA, Capex — unchanged legacy)
 * ========================================================================== */
(function (root, factory) {
  const api = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = api; // Node
  else root.LE_UNDERWRITERS = api;                                           // Browser
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // ──────────────────────────────────────────────────────────────────────
  // Underwriter profiles
  // ──────────────────────────────────────────────────────────────────────
  const UNDERWRITERS = {

    /* ===== Liberty Life — Family Protector Plan =========================== */
    heritage: {
      id: 'heritage',
      label: 'Liberty Life',
      legalName: 'Liberty Life Assurance Kenya Ltd',
      availableFor: ['individual', 'group'],
      benefitTiers: [50000, 70000, 100000, 150000, 200000, 250000, 300000, 350000, 400000, 500000],
      coverTypes: ['member', 'nuclear', 'extended'],
      pricing: {
        model: 'modular',
        // index-aligned with benefitTiers
        member:    [680,  952,  1345, 2018, 2660, 3325, 3955, 4614, 5215, 6450],
        nuclear:   [1130, 1582, 2240, 3360, 4440, 5550, 6590, 7688, 8695, 10755],
        // Extended family = flat bundle (nuclear family + up to 4 parents/in-laws)
        // regardless of how many parents are actually added — revised Liberty
        // rate card (Jul 2026), KES 76.4 per 1,000 sum assured.
        extended:  [3820, 5348, 7640, 11460, 15280, 19100, 22920, 26740, 30560, 38200],
        perParent: [1365, 1911, 2700, 4050, 5350, 6688, 7940, 9263, 10475, 12960], // per extra child / sibling only
      },
      // Revised rate card (Jul 2026): children & parents covered at 50% of the
      // main member across all tiers (up to 250,000 on option 10) — no 200k cap.
      childBenefit: { pct: 0.5, cap: null, under10Cap: 100000 },
      minPremium: 50000,            // per policy
      ages: {
        principal:     { min: 18, max: 65 },
        spouse:        { min: 18, max: 65 },
        child:         { minDays: 14, max: 21, studentMax: 25 },
        parent:        { min: 18, max: 75 },
        parent_in_law: { min: 18, max: 75 },
        sibling:       { min: 0,  max: 21, studentMax: 25 },
      },
      limits: { spouse: 1, children: 6, parents: 2, parents_in_law: 2, siblings: 6 },
      waiting: { natural: '3 months', accidental: 'none' },
      claimsPerYear: 4,
      features: [
        'No HIV/AIDS exclusion',
        'No suicide exclusion (after waiting period)',
        'Political Violence & Terrorism extension at no extra cost',
        'Payout within 48 working hours',
        'Up to 4 claims per family per year',
      ],
      notes: 'Children and parents are covered at 50% of the main member benefit (KES 100,000 maximum for children under 10). A minimum total premium of KES 50,000 applies to group schemes.',
    },

    /* ===== ABSA Life Assurance — legacy, unchanged ======================== */
    absa: {
      id: 'absa',
      label: 'ABSA Life Assurance',
      legalName: 'ABSA Life Assurance Kenya Ltd',
      availableFor: ['group'],
      benefitTiers: [50000, 100000, 150000, 200000, 300000, 400000, 500000],
      coverTypes: ['family'],       // single family product — no cover-type selector
      pricing: {
        model: 'base_addon',
        base:        [5000, 7000, 9000, 13200, 14100, 18500, 24000],
        extra_child: [250,  500,  500,  1000,  1000,  1000,  1000],   // 5th child onward
        child_25_29: [300,  500,  750,  1200,  1800,  2800,  4000],
        includedChildren: 4,
      },
      childBenefit: null,
      minPremium: null,
      ages: {
        principal: { min: 18, max: 69 },
        spouse:    { min: 18, max: 69 },
        child:     { min: 0, max: 29, extendedMin: 25 }, // 25-29 allowed (ABSA only)
        parent:        { min: 31, max: 85 },
        parent_in_law: { min: 31, max: 85 },
      },
      limits: { spouse: 1, children: 99, parents: 1, parents_in_law: 1 },
      waiting: { natural: '1 month nuclear / 3 months parents', accidental: 'none' },
      claimsPerYear: 5,
      features: [
        'Up to 5 claims per family/year',
        'Payout within 48 working hours',
        'Complimentary grief counseling',
        'Children aged 25–29 covered',
      ],
      notes: '',
    },

    /* ===== Capex Life Assurance — legacy, unchanged ======================= */
    capex: {
      id: 'capex',
      label: 'Capex Life Assurance',
      legalName: 'Capex Life Assurance',
      availableFor: ['group'],
      benefitTiers: [50000, 100000, 150000, 200000, 300000, 400000, 500000],
      coverTypes: ['family'],
      pricing: {
        model: 'base_addon',
        base:        [2200, 4400, 6500, 8700, 12900, 17000, 21200],
        extra_child: [100,  200,  300,  400,  600,   800,   1000],
        child_25_29: null,
        includedChildren: 4,
      },
      childBenefit: null,
      minPremium: null,
      ages: {
        principal: { min: 18, max: 69 },
        spouse:    { min: 18, max: 69 },
        child:     { min: 0, max: 24 },                  // 25-29 NOT available
        parent:        { min: 31, max: 85 },
        parent_in_law: { min: 31, max: 85 },
      },
      limits: { spouse: 1, children: 99, parents: 1, parents_in_law: 1 },
      waiting: { natural: '1 month nuclear / 3 months parents', accidental: 'none' },
      claimsPerYear: 3,
      features: [
        'Up to 3 claims per family/year',
        'Payout within 2 business days',
        'Grief counseling not included',
        'Children 25–29 not available',
      ],
      notes: '',
    },
  };

  // Cover-type → which dependent relationships are allowed
  const COVER_TYPE_DEPENDENTS = {
    member:   [],
    nuclear:  ['spouse', 'child'],
    extended: ['spouse', 'child', 'mother', 'father', 'mother_in_law', 'father_in_law', 'sibling'],
    family:   ['spouse', 'child', 'mother', 'father', 'mother_in_law', 'father_in_law'], // legacy ABSA/Capex
  };

  const COVER_TYPE_LABELS = {
    member:   'Principal only',
    nuclear:  'Nuclear family',
    extended: 'Extended family',
    family:   'Family',
  };

  const COVER_TYPE_DESCRIPTIONS = {
    member:   'Cover for the principal member only.',
    nuclear:  'Principal member, spouse, and up to 6 children.',
    extended: 'Nuclear family plus parents and parents-in-law (and dependent siblings).',
  };

  // ──────────────────────────────────────────────────────────────────────
  // Helpers (shared by client + server)
  // ──────────────────────────────────────────────────────────────────────
  const PARENT_RELS = ['mother', 'father', 'mother_in_law', 'father_in_law'];

  function get(uwId) { return UNDERWRITERS[uwId] || null; }

  function listFor(applicationType) {
    return Object.values(UNDERWRITERS).filter(u => u.availableFor.includes(applicationType));
  }

  function tierIndex(uwId, coverOption) { return Number(coverOption) - 1; }

  function coverAmount(uwId, coverOption) {
    const u = get(uwId); if (!u) return null;
    const t = u.benefitTiers[Number(coverOption) - 1];
    return (t === undefined) ? null : t;
  }

  // Which dependent relationships a given (underwriter, coverType) allows
  function allowedDependents(uwId, coverType) {
    const u = get(uwId); if (!u) return [];
    const ct = coverType || (u.coverTypes.length === 1 ? u.coverTypes[0] : null);
    return COVER_TYPE_DEPENDENTS[ct] || [];
  }

  /**
   * Canonical premium computation — used by both client (live ticker) and
   * server (authoritative re-check). Returns { base, extras, total } or null.
   *
   * @param {string} uwId
   * @param {object} opts  { coverType, coverOption, dependents:[{relationship,date_of_birth}] }
   * @param {function} [ageFn]  dob -> age in years (defaults to internal)
   */
  function computePremium(uwId, opts, ageFn) {
    const u = get(uwId); if (!u) return null;
    const idx = Number(opts.coverOption) - 1;
    if (idx < 0 || idx >= u.benefitTiers.length) return null;
    const deps = Array.isArray(opts.dependents) ? opts.dependents : [];
    const age = ageFn || _ageYears;

    if (u.pricing.model === 'modular') {
      const coverType = opts.coverType;
      let base = 0;
      if (coverType === 'member')   base = u.pricing.member[idx];
      else if (coverType === 'nuclear')  base = u.pricing.nuclear[idx];
      // Extended is a flat bundle: parents / parents-in-law (up to 4) are
      // included in the base — no per-parent charge.
      else if (coverType === 'extended') base = u.pricing.extended[idx];
      else return null;

      let extras = 0;
      if (coverType === 'nuclear' || coverType === 'extended') {
        // Children beyond the 6 included, plus any dependent siblings, at perParent
        const childCount = deps.filter(d => d.relationship === 'child').length;
        const extraChildren = Math.max(0, childCount - u.limits.children);
        const siblingCount = deps.filter(d => d.relationship === 'sibling').length;
        extras += (extraChildren + siblingCount) * u.pricing.perParent[idx];
      }

      // NOTE: minPremium is a GROUP-SCHEME minimum (total of all members), NOT a
      // per-member floor — so it is intentionally NOT applied to a single quote here.
      return { base, extras, total: base + extras };
    }

    if (u.pricing.model === 'base_addon') {
      const p = u.pricing;
      const base = p.base[idx];
      let extras = 0;
      const children = deps.filter(d => d.relationship === 'child');
      children.forEach((c, i) => {
        const a = c.date_of_birth ? age(c.date_of_birth) : 0;
        if (a >= 25 && a <= 29 && p.child_25_29) extras += p.child_25_29[idx];
        else if (i >= (p.includedChildren || 4)) extras += p.extra_child[idx];
      });
      return { base, extras, total: base + extras };
    }

    return null;
  }

  function _ageYears(dob) {
    const d = new Date(dob), now = new Date();
    let a = now.getFullYear() - d.getFullYear();
    const m = now.getMonth() - d.getMonth();
    if (m < 0 || (m === 0 && now.getDate() < d.getDate())) a--;
    return a;
  }

  return {
    UNDERWRITERS,
    COVER_TYPE_DEPENDENTS,
    COVER_TYPE_LABELS,
    COVER_TYPE_DESCRIPTIONS,
    PARENT_RELS,
    get,
    listFor,
    tierIndex,
    coverAmount,
    allowedDependents,
    computePremium,
  };
});
