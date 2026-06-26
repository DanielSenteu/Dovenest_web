// ─────────────────────────────────────────────────────────────────────────────
// email.js — transactional emails via Resend.
//
// Every form sends two emails (fire-and-forget — a failure never blocks the
// submission, it's just logged):
//   • a confirmation to the CLIENT (per-form summary), and
//   • a notification to the DoveNest inbox.
//
// Config via .env:
//   RESEND_API_KEY   required to actually send (absent → logs + skips)
//   EMAIL_FROM       default: "DoveNest Insurance <info@dovenest.morsensolutions.com>"
//   DOVENEST_INBOX   default: info@dovenestinsurance.com,senteudaniel3@gmail.com
//                    (comma-separated — every internal notification goes to all)
// ─────────────────────────────────────────────────────────────────────────────

const https = require('https');

// Read config lazily so it works regardless of when .env is loaded.
const FROM_DEFAULT  = 'DoveNest Insurance <info@dovenest.morsensolutions.com>';
const INBOX_DEFAULT = 'info@dovenestinsurance.com,senteudaniel3@gmail.com';
// Returns an array of recipients — send() accepts arrays directly.
const inbox = () => (process.env.DOVENEST_INBOX || INBOX_DEFAULT)
  .split(',').map(s => s.trim()).filter(Boolean);

// ── Low-level send ───────────────────────────────────────────────────────────
function send({ to, subject, html, attachments }) {
  return new Promise((resolve, reject) => {
    const key  = process.env.RESEND_API_KEY;
    const from = process.env.EMAIL_FROM || FROM_DEFAULT;
    if (!key) {
      console.warn('[email] RESEND_API_KEY not set — skipped:', subject);
      return resolve({ skipped: true });
    }
    const body = { from, to: Array.isArray(to) ? to : [to], subject, html };
    if (attachments && attachments.length) body.attachments = attachments;
    const payload = JSON.stringify(body);
    const req = https.request({
      hostname: 'api.resend.com', path: '/emails', method: 'POST',
      headers: { 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
    }, res => {
      let d = ''; res.on('data', c => d += c);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) resolve(JSON.parse(d || '{}'));
        else reject(new Error(`Resend ${res.statusCode}: ${d}`));
      });
    });
    req.on('error', reject); req.write(payload); req.end();
  });
}

function fire(promise, label) {
  Promise.resolve(promise)
    .then(r => { if (!(r && r.skipped)) console.log(`[email] sent: ${label}`); })
    .catch(e => console.error(`[email] FAILED ${label}: ${e.message}`));
}

// ── Presentation helpers ─────────────────────────────────────────────────────
function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function shell(bodyHtml, preheader = '') {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;background:#f4f6f9;font-family:Arial,Helvetica,sans-serif;color:#1a2b3c;">
<span style="display:none;max-height:0;overflow:hidden;opacity:0;">${esc(preheader)}</span>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f6f9;padding:24px 12px;">
 <tr><td align="center">
  <table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 2px 12px rgba(8,55,95,0.08);">
   <tr><td style="background:#08375f;padding:20px 28px;">
     <span style="color:#ffffff;font-size:18px;font-weight:bold;letter-spacing:0.3px;">DoveNest Insurance</span>
     <span style="display:inline-block;width:38px;height:3px;background:#52B44B;border-radius:2px;margin-left:10px;"></span>
   </td></tr>
   <tr><td style="padding:30px 28px;">${bodyHtml}</td></tr>
   <tr><td style="padding:18px 28px;background:#f7f9fb;border-top:1px solid #eef2f6;color:#8497a6;font-size:12px;line-height:1.7;">
     DoveNest Insurance Brokers Ltd &middot; 4th Floor, Uganda House, Kenyatta Avenue, Nairobi<br>
     +254 726 001122 &middot; info@dovenestinsurance.com &middot; Regulated by the IRA<br>
     This is an automated message — please do not reply to this email.
   </td></tr>
  </table>
 </td></tr>
</table></body></html>`;
}

function h1(text)   { return `<h1 style="margin:0 0 12px;font-size:22px;color:#08375f;">${esc(text)}</h1>`; }
function p(text)    { return `<p style="margin:0 0 14px;font-size:15px;line-height:1.65;color:#3a4d5e;">${text}</p>`; }
function signoff()  { return p('Warm regards,<br><strong style="color:#08375f;">The DoveNest Insurance Team</strong>'); }

function refBadge(ref) {
  return `<div style="background:#eef6ff;border:1px solid #d3e6f7;border-radius:8px;padding:10px 16px;margin:0 0 18px;display:inline-block;">
    <span style="color:#5a7080;font-size:12px;text-transform:uppercase;letter-spacing:0.5px;">Reference</span>
    <span style="color:#08375f;font-size:16px;font-weight:bold;letter-spacing:0.5px;margin-left:8px;">${esc(ref)}</span></div>`;
}

function codeBox(code) {
  return `<div style="background:#08375f;border-radius:12px;padding:22px;text-align:center;margin:6px 0 20px;">
    <div style="color:#9fc3e3;font-size:12px;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px;">Your group code</div>
    <div style="color:#ffffff;font-size:30px;font-weight:bold;letter-spacing:3px;">${esc(code)}</div></div>`;
}

function kv(rows) {
  const trs = rows.filter(r => r && r[1] != null && r[1] !== '').map(([k, v]) =>
    `<tr>
       <td style="padding:8px 0;color:#7a8a99;font-size:13px;width:44%;vertical-align:top;">${esc(k)}</td>
       <td style="padding:8px 0;color:#1a2b3c;font-size:14px;font-weight:600;">${esc(String(v))}</td>
     </tr>`).join('');
  return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-top:1px solid #eef2f6;margin:6px 0 18px;">${trs}</table>`;
}

// ── Label maps ───────────────────────────────────────────────────────────────
const PRODUCT_LABELS = {
  motor: 'Motor Insurance', health: 'Health Insurance', education: 'Education Insurance',
  diaspora: 'Diaspora Insurance', general: 'General Insurance', life_pension: 'Life & Pension Products',
  travel: 'Travel Insurance', flying_doctors: 'Amref Flying Doctors',
  group_last_expense: 'Group Last Expense', other: 'Other',
};
const UW_LABELS = { heritage: 'Liberty Life', absa: 'ABSA Life', capex: 'Capex Life' };
const COVER_LABELS = { member: 'Principal only', nuclear: 'Nuclear family', extended: 'Extended family', family: 'Family' };
const POLICY_LABELS = { personal: 'Personal', business: 'Business' };
const ksh = n => (n == null ? null : 'Ksh ' + Number(n).toLocaleString());
const pageLabel = sp => (sp ? String(sp).replace(/\.html$/, '').replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase()) : null);

// PDF receipt → Resend attachment array (or undefined).
const pdfAtt = (b64, name) => (b64 ? [{ filename: name || 'DoveNest-receipt.pdf', content: b64 }] : undefined);

// ── Per-form notifications ───────────────────────────────────────────────────
function notifyMotor(q, pdfB64, pdfName) {
  const att = pdfAtt(pdfB64, pdfName);
  const name = [q.first_name, q.last_name].filter(Boolean).join(' ').trim();
  fire(send({
    to: q.email, attachments: att,
    subject: `We've received your motor quote request — ${q.ref}`,
    html: shell(
      h1('Your motor quote request is in') +
      p(`Hi ${esc(q.first_name || 'there')}, thanks for your motor insurance enquiry. Our team is preparing your quote and will be in touch shortly.`) +
      refBadge(q.ref) +
      kv([['Cover type', POLICY_LABELS[q.policy_type] || q.policy_type], ['Vehicle category', q.vehicle_category]]) +
      p('We typically respond within one business day.') + signoff(),
      'We received your motor quote request.'),
  }), `motor client ${q.ref}`);
  fire(send({
    to: inbox(),
    subject: `New motor quote — ${name || q.email} (${q.ref})`,
    html: shell(h1('New motor quote request') + kv([
      ['Reference', q.ref], ['Name', name], ['Email', q.email], ['Phone', q.phone],
      ['Date of birth', q.date_of_birth], ['Driving experience', q.experience_years != null ? `${q.experience_years} yrs` : null],
      ['Policy type', POLICY_LABELS[q.policy_type] || q.policy_type], ['Vehicle category', q.vehicle_category],
    ])),
  }), `motor internal ${q.ref}`);
}

function notifyTravel(b, pdfB64, pdfName) {
  const att = pdfAtt(pdfB64, pdfName);
  fire(send({
    to: b.email, attachments: att,
    subject: `Your travel insurance application — ${b.ref}`,
    html: shell(
      h1('Your travel insurance application is in') +
      p(`Hi ${esc(b.full_name || 'there')}, thanks for your application. Our team will review it and get back to you shortly.`) +
      refBadge(b.ref) +
      kv([['Destination', b.destination], ['Departure', b.departure_date], ['Return', b.return_date],
          ['Cover type', b.cover_type], ['Travellers', (b.travellers || []).length || null]]) +
      signoff(),
      'We received your travel insurance application.'),
  }), `travel client ${b.ref}`);
  fire(send({
    to: inbox(),
    subject: `New travel application — ${b.full_name || b.email} (${b.ref})`,
    html: shell(h1('New travel insurance application') + kv([
      ['Reference', b.ref], ['Proposer', b.full_name], ['Email', b.email], ['Phone', b.phone],
      ['Destination', b.destination], ['Dates', `${b.departure_date} → ${b.return_date}`],
      ['Purpose', b.purpose], ['Cover type', b.cover_type], ['Payment', b.payment_method],
      ['Travellers', (b.travellers || []).length || null],
      ['Beneficiary', b.beneficiary_name ? `${b.beneficiary_name} (${b.beneficiary_relation || '—'})` : null],
    ])),
  }), `travel internal ${b.ref}`);
}

function notifyFlyingDoctor(b, pdfB64, pdfName) {
  const att = pdfAtt(pdfB64, pdfName);
  fire(send({
    to: b.email, attachments: att,
    subject: `Your Amref Flying Doctors application — ${b.ref}`,
    html: shell(
      h1('Your Amref Flying Doctors application is in') +
      p(`Hi ${esc(b.full_name || 'there')}, thanks for your application. We'll review it and be in touch shortly.`) +
      refBadge(b.ref) +
      kv([['Plan', b.plan ? b.plan[0].toUpperCase() + b.plan.slice(1) : null], ['Members', (b.members || []).length || null]]) +
      signoff(),
      'We received your Amref Flying Doctors application.'),
  }), `flying-doctor client ${b.ref}`);
  fire(send({
    to: inbox(),
    subject: `New flying-doctor application — ${b.full_name || b.email} (${b.ref})`,
    html: shell(h1('New Amref Flying Doctors application') + kv([
      ['Reference', b.ref], ['Applicant', b.full_name], ['Email', b.email], ['Phone', b.phone],
      ['Plan', b.plan], ['Members', (b.members || []).length || null], ['Payment ref', b.payment_ref],
    ])),
  }), `flying-doctor internal ${b.ref}`);
}

function notifyLastExpense(r, pdfB64, pdfName) {
  const att = pdfAtt(pdfB64, pdfName);
  const pr = r.principal || {};
  const isGroup = r.application_type === 'group';
  fire(send({
    to: pr.email, attachments: att,
    subject: `Your Last Expense application — ${r.ref}`,
    html: shell(
      h1('Your Last Expense application is in') +
      p(`Hi ${esc((pr.full_name || '').split(' ')[0] || 'there')}, thanks for your application. Our team will review it and confirm your cover shortly.`) +
      refBadge(r.ref) +
      kv([
        ['Underwriter', UW_LABELS[r.underwriter] || r.underwriter],
        ['Cover', COVER_LABELS[r.cover_scope] || r.cover_scope],
        ['Sum assured', ksh(r.cover_amount)],
        ['Annual premium', ksh(r.total_premium)],
        isGroup ? ['Group', r.group_name] : null,
        isGroup ? ['Group code', r.group_code] : null,
      ]) + signoff(),
      'We received your Last Expense application.'),
  }), `last-expense client ${r.ref}`);
  fire(send({
    to: inbox(),
    subject: `New last-expense ${r.application_type} — ${pr.full_name || pr.email} (${r.ref})`,
    html: shell(h1('New Last Expense application') + kv([
      ['Reference', r.ref], ['Type', r.application_type],
      isGroup ? ['Group', `${r.group_name || '—'} (${r.group_code || '—'})`] : null,
      ['Underwriter', UW_LABELS[r.underwriter] || r.underwriter],
      ['Cover', COVER_LABELS[r.cover_scope] || r.cover_scope], ['Sum assured', ksh(r.cover_amount)],
      ['Annual premium', ksh(r.total_premium)],
      ['Principal', pr.full_name], ['Email', pr.email], ['Mobile', pr.mobile],
      ['Dependents', (r.dependents || []).length || 0],
    ])),
  }), `last-expense internal ${r.ref}`);
}

function notifyGroupRegistered(grp, pdfB64, pdfName) {
  const att = pdfAtt(pdfB64, pdfName);
  const to = grp.contact_email || grp.group_email;
  fire(send({
    to, attachments: att,
    subject: `Your group is registered — code ${grp.group_code}`,
    html: shell(
      h1('Your group is registered 🎉') +
      p(`Hi ${esc((grp.contact_person || '').split(' ')[0] || 'there')}, your group <strong>${esc(grp.group_name)}</strong> has been registered for Last Expense cover.`) +
      codeBox(grp.group_code) +
      p('<strong>Share this code with your members.</strong> Each member uses it to apply for cover under the group — a minimum of 10 principal members is needed to activate the scheme.') +
      kv([['Group name', grp.group_name], ['Type', grp.group_type], ['Underwriter', UW_LABELS[grp.underwriter] || grp.underwriter]]) +
      signoff(),
      `Your group code is ${grp.group_code}.`),
  }), `group-register client ${grp.group_code}`);
  fire(send({
    to: inbox(),
    subject: `New group registered — ${grp.group_name} (${grp.group_code})`,
    html: shell(h1('New group registered') + kv([
      ['Group code', grp.group_code], ['Group name', grp.group_name], ['Type', grp.group_type],
      ['Underwriter', UW_LABELS[grp.underwriter] || grp.underwriter],
      ['Contact person', grp.contact_person], ['Contact email', grp.contact_email],
      ['Contact phone', grp.contact_phone], ['Additional contacts', (grp.additional_contacts || []).length || 0],
    ])),
  }), `group-register internal ${grp.group_code}`);
}

function notifyContact(r) {
  const isInquiry = r.kind === 'product_inquiry';
  const productLabel = r.product ? (PRODUCT_LABELS[r.product] || r.product) : null;
  const fromPage = pageLabel(r.source_page);
  fire(send({
    to: r.email,
    subject: isInquiry ? `We received your enquiry${productLabel ? ' about ' + productLabel : ''} — ${r.ref}`
                       : `We received your message — ${r.ref}`,
    html: shell(
      h1(isInquiry ? 'Thanks for your enquiry' : 'We received your message') +
      p(`Hi ${esc((r.full_name || '').split(' ')[0] || 'there')}, thanks for getting in touch with DoveNest. ${isInquiry ? 'A DoveNest advisor will get back to you shortly.' : "We've received your message and will get back to you shortly."}`) +
      refBadge(r.ref) +
      kv([
        ['Enquiry type', isInquiry ? 'Product enquiry' : 'General enquiry'],
        ['Product', productLabel],
        ['From page', fromPage],
        ['Country', r.country],
        ['Your message', r.message],
      ]) +
      p("We aim to respond within one business day. If it's urgent, call us on +254 726 001122.") +
      signoff(),
      'We received your message and will get back to you shortly.'),
  }), `contact client ${r.ref}`);
  fire(send({
    to: inbox(),
    subject: `New ${isInquiry ? 'product enquiry' : 'contact message'}${productLabel ? ' — ' + productLabel : ''} (${r.ref})`,
    html: shell(h1(isInquiry ? 'New product enquiry' : 'New contact message') + kv([
      ['Reference', r.ref], ['Type', isInquiry ? 'Product enquiry' : 'General'],
      ['Product', productLabel], ['From page', fromPage],
      ['Name', r.full_name], ['Email', r.email], ['Phone', r.phone], ['Country', r.country],
      ['Message', r.message],
    ])),
  }), `contact internal ${r.ref}`);
}

// A client left a review. Two emails fire: a warm thank-you to the reviewer,
// and an internal moderation alert to the DoveNest inbox.
const REVIEW_PRODUCT_LABELS = {
  motor: 'Motor', health: 'Health / Medical', life_assurance: 'Life Assurance',
  domestic: 'Domestic / Home', business: 'Business / Commercial', pensions: 'Pensions & Retirement',
  education: 'Education', diaspora: 'Diaspora', last_expense: 'Last Expense', general: 'Other / General',
};

// A gold star strip + their headline, for the thank-you email.
function reviewStarsBox(rating, headline) {
  const gold = '★'.repeat(rating || 0);
  const grey = '☆'.repeat(Math.max(0, 5 - (rating || 0)));
  return `<div style="background:#f7fafd;border:1px solid #e3ecf4;border-radius:12px;padding:20px;text-align:center;margin:4px 0 20px;">
    <div style="font-size:28px;letter-spacing:4px;color:#f6b81c;line-height:1;">${gold}<span style="color:#d7e0ea;">${grey}</span></div>
    ${headline ? `<div style="color:#08375f;font-size:15px;font-weight:600;margin-top:10px;">&ldquo;${esc(headline)}&rdquo;</div>` : ''}
  </div>`;
}

function notifyReview(r) {
  const name = [r.first_name, r.last_name].filter(Boolean).join(' ').trim();
  const firstName = (r.first_name || '').trim() || 'there';
  const stars = '★'.repeat(r.rating || 0) + '☆'.repeat(Math.max(0, 5 - (r.rating || 0)));

  // ── 1. Thank-you to the reviewer ──
  if (r.email) {
    fire(send({
      to: r.email,
      subject: `Thank you for your review, ${firstName}`,
      html: shell(
        h1('Thank you for sharing your experience') +
        p(`Hi ${esc(firstName)}, thank you for taking a moment to review <strong>DoveNest Insurance Brokers</strong>. Feedback from the people and organisations we serve means a great deal to us — it helps other families, SACCOs, churches and businesses choose their protection with confidence.`) +
        reviewStarsBox(r.rating, r.headline) +
        p('Our team will verify your review, and once approved it will appear on our website as a published endorsement. We may reach out briefly to confirm your details — purely to keep every review genuine.') +
        p('If there is ever anything we can help you with — a policy question, a claim, or reviewing your cover — simply reply to this email or call us on <strong>+254&nbsp;726&nbsp;001122</strong>. We are always glad to help.') +
        signoff(),
        'Thank you for reviewing DoveNest Insurance — your feedback means a lot.'),
    }), `review thank-you ${r.email}`);
  }

  // ── 2. Internal moderation alert ──
  fire(send({
    to: inbox(),
    subject: `New review (${r.rating}★) — ${name || 'Anonymous'} — awaiting moderation`,
    html: shell(h1('New client review — needs moderation') + kv([
      ['Rating', `${stars}  (${r.rating}/5)`],
      ['Name', name],
      ['Type', r.type === 'business' ? 'Business' : 'Individual'],
      ['Organisation', r.company_name || r.organisation],
      ['Product', REVIEW_PRODUCT_LABELS[r.product] || r.product],
      ['Location', [r.county, r.country].filter(Boolean).join(', ')],
      ['Email', r.email], ['Phone', r.phone],
      ['Source', r.source],
      ['Headline', r.headline],
      ['Review', r.review_text],
      ['Photo', r.photo_url ? 'attached (see admin)' : null],
    ]) + p('Open the admin dashboard to verify the client and approve, feature or reject this review.')),
  }), `review internal ${name || r.email || 'anon'}`);
}

module.exports = {
  send,
  notifyMotor, notifyTravel, notifyFlyingDoctor, notifyLastExpense, notifyGroupRegistered, notifyContact, notifyReview,
};
