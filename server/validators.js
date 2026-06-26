// ─────────────────────────────────────────────────────────────────────────────
// validators.js — pure, server-side field validation for every self-hosted form.
//
// Deep module: a small interface (one `validate<Form>(payload) -> string[]` per
// form) hides all the field rules. Callers — the route handlers in
// server/server.js AND the test suite — cross the same seam. No HTTP, no CSRF,
// no Supabase needed to exercise validation.
//
// Date-dependent validators accept an optional `now` (a Date) so age-band checks
// are deterministic under test. It defaults to the real clock, so production
// behaviour is unchanged. The interface is the test surface.
//
// Pricing/eligibility facts come from the underwriter registry (ADR-0002).
// ─────────────────────────────────────────────────────────────────────────────

const LE = require('../public/last-expense-underwriters.js');

// Whole years between `dob` and `now` (defaults to the real clock).
function ageYears(dob, now = new Date()) {
  const d = new Date(dob);
  let age = now.getFullYear() - d.getFullYear();
  const m = now.getMonth() - d.getMonth();
  if (m < 0 || (m === 0 && now.getDate() < d.getDate())) age--;
  return age;
}

// Every public quote form requires explicit agreement to the Terms & Conditions.
// The client gates submission on a checkbox; the server enforces it as the final
// authority (never trust the client alone).
function pushTermsError(body, errors) {
  if (body.terms_accepted !== true)
    errors.push('You must accept the Terms & Conditions to continue.');
}

// ── Shared constants ─────────────────────────────────────────────────────────
const VALID_POLICY_TYPES = ['personal', 'business'];
const VALID_VEHICLE_CATEGORIES = [
  'PRIVATE CAR',
  'MOTOR COMMERCIAL',
  'PRIVATE MOTOR CYCLE',
  'INSTITUTIONAL VEHICLES',
  'PETROLEUM TANKERS',
];

// Which page is allowed to submit which product (defense in depth for hidden fields)
const PAGE_PRODUCT_MAP = {
  'motor-insurance.html':        'motor',
  'health-insurance.html':       'health',
  'education-insurance.html':    'education',
  'diaspora-insurance.html':     'diaspora',
  'general-insurance.html':      'general',
  'life-pension-products.html':  'life_pension',
  'travel-insurance.html':       'travel',
  'flying-doctors.html':         'flying_doctors',
};
const VALID_PRODUCTS = new Set([
  'motor', 'health', 'group_last_expense', 'life_pension', 'education',
  'diaspora', 'general', 'travel', 'flying_doctors', 'other',
]);

// Products a client could pick when leaving a review (kept for phase 2 — the
// `product` column stays nullable; the live form no longer collects it).
const VALID_REVIEW_PRODUCTS = new Set([
  'motor', 'health', 'life_assurance', 'domestic', 'business',
  'pensions', 'education', 'diaspora', 'last_expense', 'general',
]);

// Controlled headline options — the reviewer picks one from a dropdown.
// 'other' is the escape hatch: it requires the reviewer to write their own
// review text instead (enforced below). Edit the wording freely; keep this set
// in sync with the <option> values in public/review.html.
const REVIEW_HEADLINES = [
  'Excellent, professional service',
  'Clear guidance throughout',
  'Fast, reliable support',
  'Helpful claims guidance',
  'Smooth renewals and documentation',
  'Clear explanation of cover options',
  'Responsive, friendly team',
  'Trusted advisory partner',
  'Good value and advice',
  'Satisfied overall',
  'Okay, but could improve',
  'Issue not fully resolved',
];
const VALID_REVIEW_HEADLINES = new Set(REVIEW_HEADLINES);

// ── Client review / endorsement ──────────────────────────────────────────────
// Public, link-shareable form. No Terms gate (that's for quote forms); the
// publish gate here is `consent_to_publish`. Name, email and phone are required
// so staff can verify the reviewer is a genuine client. The written review is
// optional UNLESS the reviewer chooses the "Other" headline, in which case they
// must write their own words.
function validateReviewPayload(body) {
  const errors = [];
  const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

  // Client type
  if (!['individual', 'business'].includes(body.type))
    errors.push('type must be "individual" or "business"');

  // Names
  if (!body.first_name || String(body.first_name).trim().length < 1)
    errors.push('first_name is required');
  else if (String(body.first_name).trim().length > 60)
    errors.push('first_name is too long');
  if (!body.last_name || String(body.last_name).trim().length < 1)
    errors.push('last_name is required');
  else if (String(body.last_name).trim().length > 60)
    errors.push('last_name is too long');

  // Email + phone — both required (verification channel)
  if (!body.email || !EMAIL_RE.test(String(body.email).trim().toLowerCase()))
    errors.push('A valid email address is required');
  if (!body.phone || !/^\+\d{9,15}$/.test(String(body.phone).trim()))
    errors.push('A valid phone number is required (e.g. +254712345678)');

  // Star rating
  const rating = Number(body.rating);
  if (!Number.isInteger(rating) || rating < 1 || rating > 5)
    errors.push('Please select a star rating from 1 to 5');

  // Headline — required, from the controlled list or the 'other' escape hatch
  const isOther = body.headline === 'other';
  if (!body.headline || !(isOther || VALID_REVIEW_HEADLINES.has(body.headline)))
    errors.push('Please choose a headline');

  // Written review — optional, BUT required when the reviewer picked "Other"
  const textLen = body.review_text ? String(body.review_text).trim().length : 0;
  if (isOther && textLen < 10)
    errors.push('Please write your review (at least a sentence) when you choose "Other"');
  else if (textLen > 0 && textLen < 10)
    errors.push('Your review is a little short — add a bit more, or leave it blank');
  if (textLen > 2000)
    errors.push('Your review is too long (max 2000 characters)');

  // Consent — nothing is published without it
  if (body.consent_to_publish !== true)
    errors.push('Please tick the box to consent to publishing your review');

  // Business reviewers must name their organisation
  if (body.type === 'business') {
    if (!body.company_name || String(body.company_name).trim().length < 2)
      errors.push('Organisation name is required for business reviews');
  }

  return errors;
}

// ── Motor quote ──────────────────────────────────────────────────────────────
function validateMotorQuotePayload(body, now = new Date()) {
  const errors = [];
  pushTermsError(body, errors);

  // 1. Policy type
  if (!body.policy_type || !VALID_POLICY_TYPES.includes(body.policy_type)) {
    errors.push('policy_type must be "personal" or "business"');
  }

  // 2. First name
  if (!body.first_name || typeof body.first_name !== 'string' || body.first_name.trim().length < 1) {
    errors.push('first_name is required');
  } else if (body.first_name.trim().length > 100) {
    errors.push('first_name is too long');
  }

  // 3. Last name
  if (!body.last_name || typeof body.last_name !== 'string' || body.last_name.trim().length < 1) {
    errors.push('last_name is required');
  } else if (body.last_name.trim().length > 100) {
    errors.push('last_name is too long');
  }

  // 4. Experience years — must be a non-negative integer between 0 and 70
  const expRaw = body.experience_years;
  const exp    = Number(expRaw);
  if (
    expRaw === null || expRaw === undefined || expRaw === '' ||
    !Number.isInteger(exp) || exp < 0 || exp > 70
  ) {
    errors.push('experience_years must be a whole number between 0 and 70');
  }

  // 5. Date of birth — must be YYYY-MM-DD, in the past, age 16–100
  if (!body.date_of_birth || typeof body.date_of_birth !== 'string') {
    errors.push('date_of_birth is required');
  } else if (!/^\d{4}-\d{2}-\d{2}$/.test(body.date_of_birth)) {
    errors.push('date_of_birth must be in YYYY-MM-DD format');
  } else {
    const dob = new Date(body.date_of_birth);
    if (isNaN(dob.getTime())) {
      errors.push('date_of_birth is not a valid date');
    } else {
      const ageMs  = now - dob;
      const ageYrs = ageMs / (1000 * 60 * 60 * 24 * 365.25);
      if (dob >= now)  errors.push('date_of_birth must be in the past');
      if (ageYrs < 16) errors.push('Minimum age is 16 years');
      if (ageYrs > 100) errors.push('Please verify your date of birth');
    }
  }

  // 6. Email
  if (!body.email || typeof body.email !== 'string') {
    errors.push('email is required');
  } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(body.email.trim().toLowerCase())) {
    errors.push('A valid email address is required');
  }

  // 7. Phone — must normalize to +XXXXXXXXX (9–15 digits after +)
  if (!body.phone || typeof body.phone !== 'string') {
    errors.push('phone is required');
  } else if (!/^\+\d{9,15}$/.test(body.phone.trim())) {
    errors.push('A valid phone number is required (e.g. +254712345678)');
  }

  // 8. Vehicle category
  if (!body.vehicle_category || !VALID_VEHICLE_CATEGORIES.includes(body.vehicle_category)) {
    errors.push('vehicle_category must be one of: ' + VALID_VEHICLE_CATEGORIES.join(', '));
  }

  return errors;
}

// ── Contact / product inquiry ────────────────────────────────────────────────
function validateContactPayload(body) {
  const errors = [];
  pushTermsError(body, errors);
  const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

  if (!['general', 'product_inquiry'].includes(body.kind))
    errors.push('kind must be "general" or "product_inquiry"');
  if (!body.source_page || String(body.source_page).trim().length < 4)
    errors.push('source_page is required');

  if (!body.full_name || String(body.full_name).trim().length < 2)
    errors.push('Name is required');
  if (!body.email || !EMAIL_RE.test(String(body.email).trim().toLowerCase()))
    errors.push('A valid email is required');

  if (body.kind === 'product_inquiry') {
    if (!body.phone || !/^\+\d{9,15}$/.test(String(body.phone).trim()))
      errors.push('A valid phone number is required');
    if (!body.country || String(body.country).trim().length < 2)
      errors.push('Country is required');
    if (!body.product || !VALID_PRODUCTS.has(body.product))
      errors.push('Invalid product');
    // Cross-check: the page's expected product must match what was sent
    const expected = PAGE_PRODUCT_MAP[body.source_page];
    if (expected && expected !== body.product)
      errors.push('Product does not match the source page');
  } else {
    // general (contact.html)
    if (!body.message || String(body.message).trim().length < 2)
      errors.push('Message is required');
    if (body.phone && !/^\+\d{9,15}$/.test(String(body.phone).trim()))
      errors.push('Phone number is invalid');
    if (body.product && !VALID_PRODUCTS.has(body.product))
      errors.push('Invalid product');
  }
  return errors;
}

// ── Travel quote ─────────────────────────────────────────────────────────────
function validateTravelQuotePayload(body, now = new Date()) {
  const errors = [];
  pushTermsError(body, errors);
  const VALID_PURPOSES = ['leisure', 'business', 'study', 'pilgrimage', 'employment'];
  const VALID_COVERS   = ['premier_worldwide', 'europe_schengen', 'inbound', 'incountry'];
  const VALID_PAYMENTS = ['mpesa', 'bank_transfer', 'cheque'];

  // Origin (optional but validated if provided)
  if (body.origin && String(body.origin).trim().length > 120)
    errors.push('origin must be 120 chars or fewer');

  // Destination
  if (!body.destination || String(body.destination).trim().length < 1 || String(body.destination).trim().length > 120)
    errors.push('destination is required (max 120 chars)');

  // Dates
  if (!body.departure_date || !/^\d{4}-\d{2}-\d{2}$/.test(body.departure_date))
    errors.push('departure_date must be YYYY-MM-DD');
  else {
    const dep = new Date(body.departure_date);
    const today = new Date(now.getTime()); today.setHours(0, 0, 0, 0);
    if (dep < today) errors.push('departure_date must be today or future');
  }

  if (!body.return_date || !/^\d{4}-\d{2}-\d{2}$/.test(body.return_date))
    errors.push('return_date must be YYYY-MM-DD');
  else if (body.departure_date && body.return_date <= body.departure_date)
    errors.push('return_date must be after departure_date');

  // Travellers
  if (!Array.isArray(body.travellers) || body.travellers.length < 1)
    errors.push('At least 1 traveller is required');
  else if (body.travellers.length > 15)
    errors.push('Maximum 15 travellers');
  else {
    body.travellers.forEach((t, i) => {
      const p = `Traveller ${i + 1}`;
      if (!t.full_name || String(t.full_name).trim().length < 2) errors.push(`${p}: full_name is required`);
      if (!t.date_of_birth || !/^\d{4}-\d{2}-\d{2}$/.test(t.date_of_birth)) errors.push(`${p}: date_of_birth is required (YYYY-MM-DD)`);
      else {
        const age = ageYears(t.date_of_birth, now);
        if (age < 0 || age > 99) errors.push(`${p}: invalid age`);
      }
      if (t.id_passport && String(t.id_passport).trim().length > 0 && String(t.id_passport).trim().length < 5)
        errors.push(`${p}: ID/passport number must be at least 5 characters`);
      // Only biological parents are eligible — the applicant must attest this
      if (t.relation === 'parent' && t.is_biological !== true)
        errors.push(`${p}: only biological parents can be covered — please confirm the biological relationship.`);
    });
  }

  // Purpose, cover, payment
  if (!VALID_PURPOSES.includes(body.purpose)) errors.push('purpose must be one of: ' + VALID_PURPOSES.join(', '));
  if (!VALID_COVERS.includes(body.cover_type)) errors.push('cover_type must be one of: ' + VALID_COVERS.join(', '));
  if (!VALID_PAYMENTS.includes(body.payment_method)) errors.push('payment_method must be one of: ' + VALID_PAYMENTS.join(', '));

  // Proposer
  if (!body.full_name || String(body.full_name).trim().length < 2) errors.push('full_name is required');
  if (!body.date_of_birth || !/^\d{4}-\d{2}-\d{2}$/.test(body.date_of_birth)) errors.push('proposer date_of_birth is required');
  if (!body.occupation || String(body.occupation).trim().length < 2) errors.push('occupation is required');
  if (!body.town || String(body.town).trim().length < 2) errors.push('town is required');
  if (!body.email || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(String(body.email).trim().toLowerCase()))
    errors.push('A valid email address is required');
  if (!body.phone || !/^\+\d{9,15}$/.test(String(body.phone).trim()))
    errors.push('A valid phone number is required (e.g. +254712345678)');

  // KRA PIN format (optional but validate if provided)
  if (body.kra_pin && String(body.kra_pin).trim().length > 0) {
    if (!/^[A-Z]\d{9}[A-Z]$/.test(String(body.kra_pin).trim().toUpperCase()))
      errors.push('kra_pin must match format A123456789Z');
  }

  // Proposer National ID / Passport (optional but ≥5 chars if entered)
  if (body.national_id && String(body.national_id).trim().length > 0 && String(body.national_id).trim().length < 5)
    errors.push('National ID must be at least 5 characters');
  if (body.passport_no && String(body.passport_no).trim().length > 0 && String(body.passport_no).trim().length < 5)
    errors.push('Passport number must be at least 5 characters');

  // Beneficiary
  if (!body.beneficiary_name || String(body.beneficiary_name).trim().length < 2) errors.push('beneficiary_name is required');
  if (!body.beneficiary_relation || String(body.beneficiary_relation).trim().length < 2) errors.push('beneficiary_relation is required');
  if (body.beneficiary_id && String(body.beneficiary_id).trim().length > 0 && String(body.beneficiary_id).trim().length < 5)
    errors.push('Beneficiary ID must be at least 5 characters');

  // Signature
  if (!body.documents || !body.documents.signature)
    errors.push('Signed declaration (signature) is required');

  return errors;
}

// ── Flying Doctor ────────────────────────────────────────────────────────────
function validateFdPayload(body, now = new Date()) {
  const errors = [];
  pushTermsError(body, errors);
  const VALID_PLANS = ['scholar', 'bronze', 'silver', 'gold', 'platinum', 'diamond'];

  if (!VALID_PLANS.includes(body.plan)) errors.push('plan must be one of: ' + VALID_PLANS.join(', '));

  // Members
  if (!Array.isArray(body.members) || body.members.length < 1)
    errors.push('At least 1 member is required');
  else if (body.members.length > 15)
    errors.push('Maximum 15 members');
  else {
    body.members.forEach((m, i) => {
      const p = `Member ${i + 1}`;
      if (!m.full_name || String(m.full_name).trim().length < 2) errors.push(`${p}: full_name is required`);
      if (!m.date_of_birth || !/^\d{4}-\d{2}-\d{2}$/.test(m.date_of_birth)) errors.push(`${p}: date_of_birth is required (YYYY-MM-DD)`);
      else {
        const age = ageYears(m.date_of_birth, now);
        if (age < 0 || age > 99) errors.push(`${p}: invalid age`);
      }
      if (!m.id_passport || String(m.id_passport).trim().length < 5) errors.push(`${p}: ID/passport/birth cert number must be at least 5 characters`);
      // Only biological parents are eligible — the applicant must attest this
      if (m.relation === 'parent' && m.is_biological !== true)
        errors.push(`${p}: only biological parents can be covered — please confirm the biological relationship.`);
    });
  }

  // Contact
  if (!body.full_name || String(body.full_name).trim().length < 2) errors.push('full_name is required');
  if (!body.email || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(String(body.email).trim().toLowerCase()))
    errors.push('A valid email address is required');
  if (!body.phone || !/^\+\d{9,15}$/.test(String(body.phone).trim()))
    errors.push('A valid phone number is required (e.g. +254712345678)');

  // Signature
  if (!body.documents || !body.documents.signature)
    errors.push('Signed declaration (signature) is required');

  return errors;
}

// ── Last Expense ─────────────────────────────────────────────────────────────
// Age band for a dependent relationship, read from an underwriter profile.
function serverDepBand(uw, rel) {
  const ag = uw.ages;
  if (rel === 'spouse' && ag.spouse) return { min: ag.spouse.min, max: ag.spouse.max, label: ag.spouse.min + '–' + ag.spouse.max };
  if ((rel === 'mother' || rel === 'father') && ag.parent) return { min: ag.parent.min, max: ag.parent.max, label: ag.parent.min + '–' + ag.parent.max };
  if ((rel === 'mother_in_law' || rel === 'father_in_law') && ag.parent_in_law) return { min: ag.parent_in_law.min, max: ag.parent_in_law.max, label: ag.parent_in_law.min + '–' + ag.parent_in_law.max };
  if (rel === 'child' && ag.child) { const mx = ag.child.studentMax || ag.child.max; return { min: 0, max: mx, label: 'up to ' + mx }; }
  if (rel === 'sibling' && ag.sibling) { const mx = ag.sibling.studentMax || ag.sibling.max; return { min: 0, max: mx, label: 'up to ' + mx }; }
  return null;
}

function validateLePayload(body, now = new Date()) {
  const errors = [];
  pushTermsError(body, errors);

  if (!['individual', 'group'].includes(body.application_type))
    errors.push('application_type must be "individual" or "group"');

  if (body.application_type === 'group' && !body.group_code)
    errors.push('group_code is required for group applications');

  // Individual / family cover is Liberty Life only
  if (body.application_type === 'individual' && body.underwriter !== 'heritage')
    errors.push('Individual/family applications must use the Liberty Life plan');

  const uw = LE.get(body.underwriter);
  if (!uw) { errors.push('Invalid underwriter'); return errors; }
  if (!uw.availableFor.includes(body.application_type))
    errors.push(`${uw.label} is not available for ${body.application_type} cover`);

  // Cover type (only where the underwriter offers a choice)
  let coverType;
  if (uw.coverTypes.length > 1) {
    if (!uw.coverTypes.includes(body.cover_scope))
      errors.push('cover_scope must be one of: ' + uw.coverTypes.join(', '));
    coverType = body.cover_scope;
  } else {
    coverType = uw.coverTypes[0];
  }

  // Benefit-tier option — valid range depends on the underwriter
  const optCount = uw.benefitTiers.length;
  const optNum = Number(body.cover_option);
  if (!(optNum >= 1 && optNum <= optCount))
    errors.push(`cover_option must be 1–${optCount}`);

  // Principal
  if (!body.full_name || String(body.full_name).trim().length < 2)
    errors.push('full_name is required');

  if (!body.date_of_birth || !/^\d{4}-\d{2}-\d{2}$/.test(body.date_of_birth))
    errors.push('date_of_birth must be YYYY-MM-DD');
  else {
    const age = ageYears(body.date_of_birth, now);
    const pa = uw.ages.principal;
    if (age < pa.min || age > pa.max) errors.push(`Principal member must be aged ${pa.min}–${pa.max}`);
  }

  if (!['M', 'F'].includes(body.gender))
    errors.push('gender must be M or F');

  if (!body.national_id || String(body.national_id).trim().length < 5)
    errors.push('National ID must be at least 5 characters');

  if (!body.kra_pin || !/^[A-Z]\d{9}[A-Z]$/.test(String(body.kra_pin).trim().toUpperCase()))
    errors.push('kra_pin must match format A123456789Z');

  if (!body.email || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(String(body.email).trim().toLowerCase()))
    errors.push('A valid email address is required');

  if (!body.mobile || !/^\+\d{9,15}$/.test(String(body.mobile).trim()))
    errors.push('mobile must be a valid phone number (e.g. +254712345678)');

  if (!body.town || String(body.town).trim().length < 2)
    errors.push('town is required');

  if (!body.occupation || String(body.occupation).trim().length < 2)
    errors.push('occupation is required');

  // Dependents — relationships allowed by cover type, counts & ages from profile
  if (body.dependents && Array.isArray(body.dependents)) {
    const allowed = LE.allowedDependents(body.underwriter, coverType);

    if (uw.limits.spouse != null && body.dependents.filter(d => d.relationship === 'spouse').length > uw.limits.spouse)
      errors.push(`Maximum ${uw.limits.spouse} spouse allowed`);
    ['mother', 'father', 'mother_in_law', 'father_in_law'].forEach(rel => {
      if (body.dependents.filter(d => d.relationship === rel).length > 1)
        errors.push(`Maximum 1 ${rel.replace(/_/g, ' ')} allowed`);
    });

    const PARENT_RELS = ['mother', 'father', 'mother_in_law', 'father_in_law'];
    body.dependents.forEach((dep, i) => {
      const prefix = `Dependent ${i + 1} (${dep.relationship})`;
      if (!allowed.includes(dep.relationship))
        errors.push(`${prefix}: not allowed for ${coverType} cover`);
      // Only biological parents are eligible — the applicant must attest this
      if (PARENT_RELS.includes(dep.relationship) && dep.is_biological !== true)
        errors.push(`${prefix}: only biological parents can be covered — please confirm the biological relationship.`);
      if (!dep.full_name || String(dep.full_name).trim().length < 2)
        errors.push(`${prefix}: full_name is required`);
      if (dep.id_number && String(dep.id_number).trim().length > 0 && String(dep.id_number).trim().length < 5)
        errors.push(`${prefix}: ID/passport number must be at least 5 characters`);
      if (!dep.date_of_birth || !/^\d{4}-\d{2}-\d{2}$/.test(dep.date_of_birth))
        errors.push(`${prefix}: date_of_birth is required (YYYY-MM-DD)`);
      else {
        const age = ageYears(dep.date_of_birth, now);
        const band = serverDepBand(uw, dep.relationship);
        if (band && (age < band.min || age > band.max))
          errors.push(`${prefix}: must be aged ${band.label}`);
      }
    });
  }

  // Documents — mandatory principal docs + signature
  if (!body.documents || !body.documents.principal_national_id)
    errors.push('National ID document (principal_national_id) is required');
  if (!body.documents || !body.documents.principal_kra_pin)
    errors.push('KRA PIN document (principal_kra_pin) is required');
  if (!body.documents || !body.documents.signature)
    errors.push('Signed declaration (signature) is required');

  return errors;
}

module.exports = {
  ageYears,
  serverDepBand,
  validateReviewPayload,
  validateMotorQuotePayload,
  validateContactPayload,
  validateTravelQuotePayload,
  validateFdPayload,
  validateLePayload,
  // constants exported for reuse/tests
  VALID_POLICY_TYPES,
  VALID_VEHICLE_CATEGORIES,
  VALID_PRODUCTS,
  VALID_REVIEW_PRODUCTS,
  VALID_REVIEW_HEADLINES,
  REVIEW_HEADLINES,
  PAGE_PRODUCT_MAP,
};
