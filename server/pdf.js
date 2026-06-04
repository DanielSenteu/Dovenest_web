// ─────────────────────────────────────────────────────────────────────────────
// pdf.js — generate a branded, professional PDF receipt for a form submission.
//
// generate(kind, data) → Promise<Buffer>
//   kind ∈ 'motor' | 'travel' | 'flying-doctor' | 'last-expense' | 'group'
//
// The PDF mirrors the confirmation email and is attached to it so the customer
// keeps a copy. Group submissions include the group code prominently.
// ─────────────────────────────────────────────────────────────────────────────

const PDFDocument = require('pdfkit');

const NAVY = '#08375f', GREEN = '#52B44B', GREY = '#7a8a99', INK = '#1a2b3c', LINE = '#e6ebf0';

const UW_LABELS    = { heritage: 'Liberty Life', absa: 'ABSA Life', capex: 'Capex Life' };
const COVER_LABELS = { member: 'Principal only', nuclear: 'Nuclear family', extended: 'Extended family', family: 'Family' };
const POLICY_LABELS = { personal: 'Personal', business: 'Business' };
const ksh = n => (n == null ? null : 'Ksh ' + Number(n).toLocaleString());
const cap = s => (s ? String(s)[0].toUpperCase() + String(s).slice(1) : s);

// Render the document from a simple description and resolve to a Buffer.
//   spec: { title, subtitle?, ref?, code?, sections: [{ heading, rows:[[k,v],...] }] }
function render(spec) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size: 'A4', margin: 50 });
    const chunks = [];
    doc.on('data', c => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    const left = doc.page.margins.left;
    const right = doc.page.width - doc.page.margins.right;
    const W = right - left;
    const bottom = doc.page.height - 70;
    let y = 0;

    const ensure = (h) => { if (y > bottom - h) { doc.addPage(); y = 50; } };

    // ── Header band ──
    doc.rect(0, 0, doc.page.width, 92).fill(NAVY);
    doc.fillColor('#ffffff').font('Helvetica-Bold').fontSize(20).text('DoveNest Insurance', left, 28);
    doc.fillColor('#9fc3e3').font('Helvetica').fontSize(10).text('Insurance Brokers Ltd · Regulated by the IRA', left, 54);
    doc.rect(left, 74, 54, 3).fill(GREEN);
    y = 118;

    // ── Title + meta ──
    doc.fillColor(NAVY).font('Helvetica-Bold').fontSize(18).text(spec.title, left, y);
    y = doc.y + 2;
    if (spec.subtitle) { doc.fillColor(GREY).font('Helvetica').fontSize(11).text(spec.subtitle, left, y); y = doc.y; }
    const stamp = new Date().toLocaleString('en-GB', { dateStyle: 'long', timeStyle: 'short' });
    doc.fillColor(GREY).font('Helvetica').fontSize(9).text('Generated ' + stamp, left, y + 4);
    y = doc.y + 12;

    if (spec.ref) {
      doc.roundedRect(left, y, W, 30, 6).fillAndStroke('#eef6ff', '#d3e6f7');
      doc.fillColor(GREY).font('Helvetica').fontSize(9).text('REFERENCE', left + 12, y + 7);
      doc.fillColor(NAVY).font('Helvetica-Bold').fontSize(13).text(spec.ref, left + 12, y + 16);
      y += 44;
    }

    if (spec.code) {
      ensure(70);
      doc.roundedRect(left, y, W, 64, 8).fill(NAVY);
      doc.fillColor('#9fc3e3').font('Helvetica').fontSize(9).text('YOUR GROUP CODE', left, y + 12, { width: W, align: 'center' });
      doc.fillColor('#ffffff').font('Helvetica-Bold').fontSize(26).text(spec.code, left, y + 26, { width: W, align: 'center', characterSpacing: 2 });
      y += 80;
    }

    // ── Sections ──
    for (const sec of spec.sections) {
      const rows = (sec.rows || []).filter(r => r && r[1] != null && r[1] !== '');
      if (!rows.length) continue;
      ensure(40);
      doc.fillColor(NAVY).font('Helvetica-Bold').fontSize(12).text(sec.heading, left, y);
      y = doc.y + 4;
      doc.moveTo(left, y).lineTo(right, y).lineWidth(1).strokeColor(LINE).stroke();
      y += 8;
      for (const [k, v] of rows) {
        const val = String(v);
        const kW = W * 0.40, vW = W * 0.57, vX = left + W * 0.43;
        const vH = doc.font('Helvetica-Bold').fontSize(10).heightOfString(val, { width: vW });
        ensure(vH + 8);
        doc.fillColor(GREY).font('Helvetica').fontSize(10).text(k, left, y, { width: kW });
        doc.fillColor(INK).font('Helvetica-Bold').fontSize(10).text(val, vX, y, { width: vW });
        y += Math.max(vH, 13) + 7;
      }
      y += 12;
    }

    // ── Footer ── (drop the bottom margin so the fixed footer doesn't paginate)
    doc.page.margins.bottom = 0;
    const fy = doc.page.height - 56;
    doc.moveTo(left, fy).lineTo(right, fy).lineWidth(1).strokeColor(LINE).stroke();
    doc.fillColor(GREY).font('Helvetica').fontSize(8).text(
      'DoveNest Insurance Brokers Ltd · 4th Floor, Uganda House, Kenyatta Avenue, Nairobi · +254 726 001122 · info@dovenestinsurance.com\n' +
      'This document is a summary of your submission and is not a contract of insurance. Cover is subject to underwriting and acceptance.',
      left, fy + 8, { width: W, align: 'center' });

    doc.end();
  });
}

const peopleRows = (arr, fields) => (arr || []).map((m, i) => {
  const parts = fields.map(f => m[f]).filter(Boolean);
  return [`${i + 1}.`, parts.join(' · ')];
});

// ── Per-form specs ───────────────────────────────────────────────────────────
function generate(kind, d) {
  if (kind === 'motor') return render({
    title: 'Motor Insurance — Quote Request', subtitle: 'Thank you for your enquiry. Our team will prepare your quote.',
    ref: d.ref,
    sections: [
      { heading: 'Applicant', rows: [
        ['Name', [d.first_name, d.last_name].filter(Boolean).join(' ')], ['Date of birth', d.date_of_birth],
        ['Driving experience', d.experience_years != null ? `${d.experience_years} years` : null],
        ['Email', d.email], ['Phone', d.phone] ] },
      { heading: 'Cover requested', rows: [
        ['Policy type', POLICY_LABELS[d.policy_type] || d.policy_type], ['Vehicle category', d.vehicle_category] ] },
    ],
  });

  if (kind === 'travel') return render({
    title: 'Travel Insurance — Application', subtitle: 'Your application has been received and is under review.',
    ref: d.ref,
    sections: [
      { heading: 'Trip', rows: [
        ['Destination', d.destination], ['Departure', d.departure_date], ['Return', d.return_date],
        ['Purpose', cap(d.purpose)], ['Cover type', d.cover_type], ['Payment method', d.payment_method] ] },
      { heading: 'Proposer', rows: [
        ['Name', d.full_name], ['Date of birth', d.date_of_birth], ['Occupation', d.occupation],
        ['Town', d.town], ['Email', d.email], ['Phone', d.phone] ] },
      { heading: 'Travellers', rows: peopleRows(d.travellers, ['full_name', 'date_of_birth', 'relation']) },
      { heading: 'Beneficiary', rows: [
        ['Name', d.beneficiary_name], ['Relationship', d.beneficiary_relation] ] },
    ],
  });

  if (kind === 'flying-doctor') return render({
    title: 'Amref Flying Doctors — Application', subtitle: 'Your application has been received and is under review.',
    ref: d.ref,
    sections: [
      { heading: 'Plan & applicant', rows: [
        ['Plan', cap(d.plan)], ['Applicant', d.full_name], ['Email', d.email], ['Phone', d.phone] ] },
      { heading: 'Members', rows: peopleRows(d.members, ['full_name', 'date_of_birth', 'relation']) },
    ],
  });

  if (kind === 'last-expense') {
    const pr = d.principal || {};
    const isGroup = d.application_type === 'group';
    return render({
      title: 'Last Expense — Application', subtitle: 'Your application has been received. We will confirm your cover shortly.',
      ref: d.ref, code: isGroup ? d.group_code : undefined,
      sections: [
        { heading: 'Cover', rows: [
          ['Underwriter', UW_LABELS[d.underwriter] || d.underwriter], ['Cover', COVER_LABELS[d.cover_scope] || d.cover_scope],
          ['Sum assured', ksh(d.cover_amount)], ['Annual premium', ksh(d.total_premium)],
          isGroup ? ['Group', d.group_name] : null, isGroup ? ['Group code', d.group_code] : null ] },
        { heading: 'Principal member', rows: [
          ['Name', pr.full_name], ['Date of birth', pr.date_of_birth], ['Gender', pr.gender],
          ['National ID', pr.national_id], ['KRA PIN', pr.kra_pin], ['Email', pr.email], ['Mobile', pr.mobile] ] },
        { heading: 'Dependents', rows: peopleRows(d.dependents, ['relationship', 'full_name', 'date_of_birth']) },
      ],
    });
  }

  if (kind === 'group') return render({
    title: 'Group Registration — Confirmation', subtitle: 'Your group is registered for Last Expense cover.',
    code: d.group_code,
    sections: [
      { heading: 'Share this code', rows: [
        ['Action', 'Give the code above to your members. Each member applies individually using it. A minimum of 10 principal members activates the scheme.'] ] },
      { heading: 'Group', rows: [
        ['Group name', d.group_name], ['Type', d.group_type], ['Underwriter', UW_LABELS[d.underwriter] || d.underwriter] ] },
      { heading: 'Primary contact', rows: [
        ['Contact person', d.contact_person], ['Email', d.contact_email], ['Phone', d.contact_phone],
        ['Additional contacts', (d.additional_contacts || []).length || 0] ] },
    ],
  });

  return Promise.reject(new Error('unknown pdf kind: ' + kind));
}

module.exports = { generate };
