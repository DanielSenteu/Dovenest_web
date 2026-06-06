const http   = require('http');
const https  = require('https');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

// Shared underwriter registry — single source of truth for pricing/rules
// (same module the quote page loads in the browser)
const LE = require('../public/last-expense-underwriters.js');
const V  = require('./validators.js'); // pure field validators (extracted)
const { createRequestGuard } = require('./request-guard.js');
const email = require('./email.js'); // transactional emails (Resend)
const pdf   = require('./pdf.js');   // downloadable PDF receipts

// Build a PDF receipt as base64 for the success response; never throw.
async function pdfReceipt(kind, data) {
  try { return (await pdf.generate(kind, data)).toString('base64'); }
  catch (e) { console.error(`[pdf] ${kind} failed: ${e.message}`); return null; }
}
// honeypot → rate-limit → CSRF, in one seam (checks injected so the guard is testable)
const guard = createRequestGuard({ checkRateLimit, validateCsrfToken });

const projectRoot = path.join(__dirname, '..');          // repo root: .env, data/, uploads/
const webRoot     = path.join(__dirname, '..', 'public'); // everything served to browsers
const port = process.env.PORT || 4173; // cloud hosts (Render, etc.) inject PORT

// Windows schannel certificate-revocation workaround — DEV ONLY.
// Never disable TLS verification in production (it weakens HTTPS to Supabase/Resend).
if (process.env.NODE_ENV !== 'production') {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
}

// ── Load .env (never committed to git) ──────────────────────────────────────
const envFile = path.join(projectRoot, '.env');
if (fs.existsSync(envFile)) {
  fs.readFileSync(envFile, 'utf8').split('\n').forEach(line => {
    const m = line.match(/^([^#=\s]+)\s*=\s*(.*)$/);
    if (m) process.env[m[1]] = m[2].trim().replace(/^['"]|['"]$/g, '');
  });
}

// ── CSRF configuration ──────────────────────────────────────────────────────
const CSRF_SECRET = process.env.CSRF_SECRET || 'dvn-motor-quote-secret-change-in-prod';
const CSRF_TTL_MS = 30 * 60 * 1000; // 30 minutes

function issueCsrfToken() {
  const ts  = Date.now().toString();
  const sig = crypto.createHmac('sha256', CSRF_SECRET).update(ts).digest('hex');
  return `${ts}.${sig}`;
}

function validateCsrfToken(token) {
  if (!token || typeof token !== 'string') return false;
  const dot = token.indexOf('.');
  if (dot === -1) return false;
  const ts  = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  // Check token age
  if (Date.now() - parseInt(ts, 10) > CSRF_TTL_MS) return false;
  // Constant-time comparison to prevent timing attacks
  const expected = crypto.createHmac('sha256', CSRF_SECRET).update(ts).digest('hex');
  try {
    return crypto.timingSafeEqual(
      Buffer.from(sig.padEnd(64, '0').slice(0, 64), 'hex'),
      Buffer.from(expected, 'hex')
    );
  } catch { return false; }
}

// ── Server-side field validation ────────────────────────────────────────────
// ── Rate limiting ────────────────────────────────────────────────────────────
const RATE_LIMIT_MAP    = new Map(); // ip -> { count, windowStart }
const RATE_LIMIT_MAX    = 5;                  // max submissions per window
const RATE_LIMIT_WINDOW = 60 * 60 * 1000;    // 1 hour in ms

function checkRateLimit(ip) {
  const now    = Date.now();
  const record = RATE_LIMIT_MAP.get(ip);

  if (!record || now - record.windowStart > RATE_LIMIT_WINDOW) {
    RATE_LIMIT_MAP.set(ip, { count: 1, windowStart: now });
    return true;
  }
  if (record.count >= RATE_LIMIT_MAX) return false;
  record.count++;
  return true;
}

// Purge expired entries every 5 minutes to prevent memory growth
setInterval(() => {
  const now = Date.now();
  for (const [ip, rec] of RATE_LIMIT_MAP.entries()) {
    if (now - rec.windowStart > RATE_LIMIT_WINDOW) RATE_LIMIT_MAP.delete(ip);
  }
}, 5 * 60 * 1000);

// ── n8n webhook forwarder ────────────────────────────────────────────────────
// URL is read from .env — never exposed to the client
function sendToN8n(quote) {
  const webhookUrl = process.env.N8N_MOTOR_WEBHOOK;
  if (!webhookUrl) {
    console.warn('[n8n] N8N_MOTOR_WEBHOOK not set in .env — skipping webhook');
    return;
  }

  let url;
  try { url = new URL(webhookUrl); }
  catch { console.error('[n8n] Invalid webhook URL in .env'); return; }

  const body = JSON.stringify(quote);
  const options = {
    hostname: url.hostname,
    port:     url.port || 443,
    path:     url.pathname + url.search,
    method:   'POST',
    headers:  { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
  };

  const req = https.request(options, res => {
    let data = '';
    res.on('data', c => data += c);
    res.on('end', () => console.log(`[n8n] webhook ${res.statusCode} — ${quote.ref}`));
  });
  req.on('error', e => console.error('[n8n] webhook error:', e.message));
  req.write(body);
  req.end();
}

// ── Supabase storage ─────────────────────────────────────────────────────────
const SUPABASE_URL         = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;

// All persistence goes through the store port (store.js). Production uses the
// Supabase adapter; tests use the in-memory adapter.
const { createSupabaseStore } = require('./store.js');
const store = createSupabaseStore({ url: SUPABASE_URL, key: SUPABASE_SERVICE_KEY });

function saveToSupabase(quote) {
  return store.insert('motor_quotes', {
    ref:              quote.ref,
    policy_type:      quote.policy_type,
    first_name:       quote.first_name,
    last_name:        quote.last_name,
    date_of_birth:    quote.date_of_birth,
    experience_years: quote.experience_years,
    email:            quote.email,
    phone:            quote.phone,
    vehicle_category: quote.vehicle_category,
    source:           'server',
    status:           'pending',
  });
}

function generateRef() {
  const ts   = Date.now().toString(36).toUpperCase();
  const rand = crypto.randomBytes(3).toString('hex').toUpperCase();
  return `DNM-${ts}-${rand}`;
}

function generateLeRef() {
  const ts   = Date.now().toString(36).toUpperCase();
  const rand = crypto.randomBytes(3).toString('hex').toUpperCase();
  return `LE-${ts}-${rand}`;
}

function generateGroupCode() {
  return 'GRP-' + crypto.randomBytes(3).toString('hex').toUpperCase();
}

function generateTqRef() {
  const ts   = Date.now().toString(36).toUpperCase();
  const rand = crypto.randomBytes(3).toString('hex').toUpperCase();
  return `TQ-${ts}-${rand}`;
}

function generateContactRef(kind) {
  const ts   = Date.now().toString(36).toUpperCase();
  const rand = crypto.randomBytes(3).toString('hex').toUpperCase();
  const prefix = kind === 'general' ? 'CT' : 'INQ';
  return `${prefix}-${ts}-${rand}`;
}

function hashIp(ip) {
  const salt = process.env.IP_HASH_SALT || CSRF_SECRET;
  return crypto.createHash('sha256').update(String(ip) + '|' + salt).digest('hex');
}

// ── Save travel quote to Supabase ────────────────────────────────────────────
async function saveTqToSupabase(record) {
  // Insert main quote
  const [quote] = await supabaseInsert('travel_quotes', {
    ref:                  record.ref,
    destination:          record.destination,
    departure_date:       record.departure_date,
    return_date:          record.return_date,
    purpose:              record.purpose,
    cover_type:           record.cover_type,
    medical_evac:         record.medical_evac,
    covid_extension:      record.covid_extension,
    full_name:            record.full_name,
    phone:                record.phone,
    email:                record.email,
    date_of_birth:        record.date_of_birth,
    national_id:          record.national_id || null,
    passport_no:          record.passport_no || null,
    kra_pin:              record.kra_pin || null,
    occupation:           record.occupation,
    town:                 record.town,
    payment_method:       record.payment_method,
    beneficiary_name:     record.beneficiary_name,
    beneficiary_id:       record.beneficiary_id || null,
    beneficiary_relation: record.beneficiary_relation,
    beneficiary_phone:    record.beneficiary_phone || null,
    status:               'pending',
  });

  // Insert travellers
  if (record.travellers && record.travellers.length > 0) {
    const travRows = record.travellers.map((t, i) => ({
      quote_id:      quote.id,
      full_name:     t.full_name,
      date_of_birth: t.date_of_birth,
      age:           t.age,
      label:         t.label,
      id_passport:   t.id_passport || null,
      relation:      t.relation || null,
      sort_order:    i,
    }));
    await supabaseInsert('travel_quote_travellers', travRows);
  }

  return quote.id;
}

// ── Flying Doctor ref generator ──────────────────────────────────────────────
function generateFdRef() {
  const ts   = Date.now().toString(36).toUpperCase();
  const rand = crypto.randomBytes(3).toString('hex').toUpperCase();
  return `FD-${ts}-${rand}`;
}

// ── Save Flying Doctor quote to Supabase ────────────────────────────────────
async function saveFdToSupabase(record) {
  const [quote] = await supabaseInsert('flying_doctor_quotes', {
    ref:         record.ref,
    plan:        record.plan,
    full_name:   record.full_name,
    phone:       record.phone,
    email:       record.email,
    payment_ref: record.payment_ref || null,
    status:      'pending',
  });

  if (record.members && record.members.length > 0) {
    const rows = record.members.map((m, i) => ({
      quote_id:      quote.id,
      full_name:     m.full_name,
      date_of_birth: m.date_of_birth,
      age:           m.age,
      id_passport:   m.id_passport,
      relation:      m.relation || null,
      sort_order:    i,
    }));
    await supabaseInsert('flying_doctor_members', rows);
  }

  return quote.id;
}

// ── Large body reader (for forms that include base64 docs) ───────────────────
function readLargeJsonBody(req, maxBytes = 60 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let raw = '';
    let size = 0;
    let tooLarge = false;
    const hardCeiling = maxBytes * 3; // abuse cutoff — only destroy past this
    req.on('data', chunk => {
      size += chunk.length;
      if (size > hardCeiling) { req.destroy(); return; }
      if (size > maxBytes) {
        // Over the limit: stop buffering but keep draining so the handler can
        // still send a proper JSON error (destroying the socket here would reach
        // the browser as a generic, misleading "network error").
        if (!tooLarge) { tooLarge = true; raw = ''; }
        return;
      }
      raw += chunk;
    });
    req.on('end', () => {
      if (tooLarge) {
        reject(new Error('Your upload is too large. Please reduce document sizes — compress PDF scans or upload phone photos instead — and try again.'));
        return;
      }
      try { resolve(JSON.parse(raw)); }
      catch { reject(new Error('Invalid JSON')); }
    });
    req.on('error', reject);
  });
}

// ── Supabase REST helpers — thin wrappers over the store port ────────────────
const supabaseInsert = (table, rows)  => store.insert(table, rows);
const supabaseSelect = (table, query) => store.select(table, query);

async function saveLeToSupabase(record) {
  // ── 1. Look up group_id if this is a group application ────
  let groupId = null;
  if (record.application_type === 'group' && record.group_code) {
    try {
      const rows = await supabaseSelect('groups', `group_code=eq.${record.group_code}&select=id`);
      if (rows.length > 0) groupId = rows[0].id;
    } catch (e) {
      console.error('[supabase] group lookup failed:', e.message);
    }
  }

  // ── 2. Insert application ──────────────────────────────────
  const p = record.principal;
  const [app] = await supabaseInsert('last_expense_applications', {
    ref:              record.ref,
    submitted_at:     record.submitted_at,
    status:           record.status,
    application_type: record.application_type,
    group_id:         groupId,
    underwriter:      record.underwriter,
    cover_option:     record.cover_option,
    cover_amount:     record.cover_amount,
    base_premium:     record.base_premium,
    extras_premium:   record.extras_premium,
    total_premium:    record.total_premium,
    full_name:        p.full_name,
    date_of_birth:    p.date_of_birth,
    gender:           p.gender,
    national_id:      p.national_id,
    kra_pin:          p.kra_pin,
    email:            p.email,
    mobile:           p.mobile,
    town:             p.town,
    occupation:       p.occupation,
    po_box:           p.po_box || null,
    postal_code:      p.postal_code || null,
  });
  const applicationId = app.id;

  // ── 3. Insert dependents, capture client_id → db UUID map ─
  const clientToDbId = {};
  if (record.dependents && record.dependents.length > 0) {
    const depRows = record.dependents.map((dep, i) => ({
      application_id:    applicationId,
      client_id:         dep.id,
      relationship:      dep.relationship,
      full_name:         dep.full_name,
      date_of_birth:     dep.date_of_birth,
      id_number:         dep.id_number || null,
      doc_type:          dep.doc_type,
      mobile:            dep.mobile || null,
      is_biological:     dep.is_biological !== undefined ? dep.is_biological : null,
      additional_premium: dep.additional_premium || 0,
      sort_order:        i,
    }));
    const inserted = await supabaseInsert('last_expense_dependents', depRows);
    inserted.forEach(row => { clientToDbId[row.client_id] = row.id; });
  }

  // ── 4. Insert documents ────────────────────────────────────
  if (record.documents && Object.keys(record.documents).length > 0) {
    const DOC_TYPE_MAP = {
      principal_national_id: 'national_id',
      principal_kra_pin:     'kra_pin',
      signature:             'signature',
    };

    const docRows = Object.entries(record.documents).map(([key, filePath]) => {
      const depMatch   = key.match(/^(dep-\d+)_/);
      const clientId   = depMatch ? depMatch[1] : null;
      const dependentId = clientId ? (clientToDbId[clientId] || null) : null;

      let documentType = DOC_TYPE_MAP[key] || 'unknown';
      if (documentType === 'unknown' && clientId) {
        const dep = record.dependents.find(d => d.id === clientId);
        if (dep) documentType = key.endsWith('_affidavit') ? 'affidavit' : dep.doc_type;
      }

      return {
        application_id: applicationId,
        dependent_id:   dependentId,
        document_key:   key,
        document_type:  documentType,
        file_path:      filePath,
        uploaded_at:    record.submitted_at,
      };
    });
    await supabaseInsert('last_expense_documents', docRows);
  }

  return applicationId;
}

// ── Upload one file to Supabase Storage ───────────────────────────────────────
const LE_BUCKET = 'last-expense-docs';

const uploadToSupabaseStorage = (storagePath, buffer, mimeType, bucket) =>
  store.upload(bucket || LE_BUCKET, storagePath, buffer, mimeType);

// ── Save uploaded base64 documents — Supabase Storage only ────────────────────
async function saveDocuments(ref, documents) {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
    throw new Error('Supabase Storage not configured');
  }
  const saved = {};
  for (const [key, doc] of Object.entries(documents)) {
    if (!doc || !doc.data) continue;
    const matches = doc.data.match(/^data:([A-Za-z-+/]+);base64,(.+)$/s);
    if (!matches) continue;

    const mimeType = matches[1];
    const buffer   = Buffer.from(matches[2], 'base64');
    const ext      = mimeType === 'image/png' ? 'png' : mimeType === 'application/pdf' ? 'pdf' : 'jpg';
    const filename = `${key}.${ext}`;
    const storagePath = await uploadToSupabaseStorage(`${ref}/${filename}`, buffer, mimeType);
    saved[key] = storagePath;
    console.log(`[storage] ✓ ${storagePath}`);
  }
  return saved;
}

// ── Generic document saver for flying-doctors / travel-quotes ─────────────────
async function saveFormDocuments(formType, ref, documents) {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
    throw new Error('Supabase Storage not configured');
  }
  const bucketName = formType + '-docs';
  const saved = {};
  for (const [key, docData] of Object.entries(documents)) {
    if (!docData) continue;
    const dataStr = typeof docData === 'string' ? docData : (docData.data || '');
    if (!dataStr) continue;

    const matches = dataStr.match(/^data:([A-Za-z-+/]+);base64,(.+)$/s);
    if (!matches) continue;

    const mimeType = matches[1];
    const buffer   = Buffer.from(matches[2], 'base64');
    const ext      = mimeType === 'image/png' ? 'png' : mimeType === 'application/pdf' ? 'pdf' : 'jpg';
    const filename = `${key}.${ext}`;
    const storagePath = await uploadToSupabaseStorage(`${ref}/${filename}`, buffer, mimeType, bucketName);
    saved[key] = storagePath;
    console.log(`[storage] ${formType} ✓ ${storagePath}`);
  }
  return saved;
}

// ── JSON body reader ─────────────────────────────────────────────────────────
function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', chunk => { raw += chunk; if (raw.length > 8192) reject(new Error('Body too large')); });
    req.on('end', () => {
      try { resolve(JSON.parse(raw)); }
      catch { reject(new Error('Invalid JSON')); }
    });
    req.on('error', reject);
  });
}

// ── JSON response helper ─────────────────────────────────────────────────────
function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    // Prevent CSRF from other origins
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(body);
}

// ── Static file MIME types ───────────────────────────────────────────────────
const mime = {
  '.html': 'text/html; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png':  'image/png',
  '.jpg':  'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif':  'image/gif',
  '.svg':  'image/svg+xml',
  '.webp': 'image/webp',
  '.mp4':  'video/mp4',
  '.webm': 'video/webm',
  '.pdf':  'application/pdf',
  '.woff': 'font/woff',
  '.woff2':'font/woff2',
  '.ttf':  'font/ttf',
  '.wasm': 'application/wasm',
};

// ── HTTP server ──────────────────────────────────────────────────────────────
http.createServer(async (req, res) => {
  const method  = req.method || 'GET';
  const urlPath = decodeURIComponent((req.url || '/').split('?')[0]);

  // ── Admin directory redirect ──────────────────────────────
  if (method === 'GET' && (urlPath === '/admin' || urlPath === '/admin/')) {
    res.writeHead(302, { Location: '/admin/login.html' });
    res.end();
    return;
  }

  // ── API: issue CSRF token ─────────────────────────────────
  if (method === 'GET' && urlPath === '/api/csrf-token') {
    sendJson(res, 200, { token: issueCsrfToken() });
    return;
  }

  // ── API: validate group code ──────────────────────────────
  if (method === 'GET' && urlPath.startsWith('/api/last-expense/group/') && urlPath.length > 24) {
    const code = urlPath.slice('/api/last-expense/group/'.length).toUpperCase();
    try {
      const rows = await supabaseSelect('groups', `group_code=eq.${encodeURIComponent(code)}&select=group_code,group_name,group_type,underwriter,group_email`);
      if (rows.length > 0) {
        const g = rows[0];
        sendJson(res, 200, {
          group_code:  g.group_code,
          group_name:  g.group_name,
          group_type:  g.group_type,
          underwriter: g.underwriter || null,
          group_email: g.group_email || null,
        });
      } else {
        sendJson(res, 404, { error: 'Group code not found' });
      }
    } catch (e) {
      console.error('[group verify] Supabase error:', e.message);
      sendJson(res, 503, { error: 'Group lookup unavailable. Please try again shortly.' });
    }
    return;
  }

  // ── API: register new group ───────────────────────────────
  if (method === 'POST' && urlPath === '/api/last-expense/group/register') {
    let body;
    try { body = await readJsonBody(req); }
    catch (err) { sendJson(res, 400, { error: err.message }); return; }

    // Honeypot → CSRF (group registration is exempt from the rate limit)
    const g = guard(req, body, {
      rateLimit: false,
      honeypotBody: () => ({ success: true, group_code: generateGroupCode() }),
      csrfMessage: 'Invalid session. Please refresh and try again.',
    });
    if (!g.ok) { sendJson(res, g.status, g.body); return; }

    // Validate group fields
    const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
    const errs = [];
    if (!body.group_name || String(body.group_name).trim().length < 2) errs.push('group_name is required');
    if (!['chama','church','sacco','alumni','welfare','other'].includes(body.group_type)) errs.push('group_type is required');
    if (!body.group_email || !EMAIL_RE.test(String(body.group_email).trim().toLowerCase())) errs.push('A valid group email is required');
    if (!body.group_contact_person || String(body.group_contact_person).trim().length < 2) errs.push('contact_person is required');
    if (!body.group_contact_position || String(body.group_contact_position).trim().length < 2) errs.push('contact_position is required');
    if (!body.group_contact_phone || !/^\+\d{9,15}$/.test(String(body.group_contact_phone).trim())) errs.push('A valid contact phone is required');
    if (!body.contact_email || !EMAIL_RE.test(String(body.contact_email).trim().toLowerCase())) errs.push('A valid primary contact email is required');
    const groupUw = LE.get(body.underwriter);
    if (!groupUw || !groupUw.availableFor.includes('group'))
      errs.push('Please choose a valid underwriter for your group.');

    if (!Array.isArray(body.additional_contacts) || body.additional_contacts.length < 1) {
      errs.push('At least one additional contact is required');
    } else if (body.additional_contacts.length > 3) {
      errs.push('Maximum 3 additional contacts');
    } else {
      body.additional_contacts.forEach((c, i) => {
        const p = `Additional contact ${i + 1}`;
        if (!c.full_name || String(c.full_name).trim().length < 2) errs.push(`${p}: name is required`);
        if (!c.email || !EMAIL_RE.test(String(c.email).trim().toLowerCase())) errs.push(`${p}: a valid email is required`);
        if (!c.phone || !/^\+\d{9,15}$/.test(String(c.phone).trim())) errs.push(`${p}: a valid phone is required`);
      });
    }

    if (errs.length > 0) { sendJson(res, 400, { error: errs[0], errors: errs }); return; }

    // Check for duplicate group name (case-insensitive) via Supabase
    const trimmedName = body.group_name.trim();
    try {
      const existing = await supabaseSelect('groups', `group_name=ilike.${encodeURIComponent(trimmedName)}&select=id`);
      if (existing.length > 0) {
        sendJson(res, 409, { error: 'A group with this name already exists. If this is your group, ask your leader for the group code.' }); return;
      }
    } catch (e) {
      console.error('[group register] duplicate-check failed:', e.message);
      sendJson(res, 503, { error: 'Group registry unavailable. Please try again shortly.' }); return;
    }

    const code = generateGroupCode();
    const newGroup = {
      group_code:       code,
      group_name:       trimmedName,
      group_type:       body.group_type,
      group_email:      String(body.group_email).trim().toLowerCase(),
      contact_email:    String(body.contact_email).trim().toLowerCase(),
      contact_person:   body.group_contact_person.trim(),
      contact_position: body.group_contact_position.trim(),
      contact_phone:    body.group_contact_phone.trim(),
      underwriter:      body.underwriter,
      registered:       body.group_registered === true || body.group_registered === 'true',
    };

    let groupId;
    try {
      const inserted = await supabaseInsert('groups', newGroup);
      groupId = inserted[0] && inserted[0].id;
      if (!groupId) throw new Error('group insert returned no id');
    } catch (e) {
      console.error('[group register] insert failed:', e.message);
      sendJson(res, 503, { error: 'Could not save group. Please try again shortly.' }); return;
    }

    // Insert additional contacts
    try {
      const contactRows = body.additional_contacts.map((c, i) => ({
        group_id:   groupId,
        full_name:  String(c.full_name).trim(),
        email:      String(c.email).trim().toLowerCase(),
        phone:      String(c.phone).trim(),
        sort_order: i,
      }));
      await supabaseInsert('group_contacts', contactRows);
    } catch (e) {
      console.error('[group register] contacts insert failed:', e.message);
      sendJson(res, 503, { error: 'Group was created but additional contacts could not be saved. Please contact support with code ' + code + '.' }); return;
    }

    console.log(`[group] Registered: ${code} — ${newGroup.group_name} (${newGroup.underwriter}, +${body.additional_contacts.length} contacts)`);
    const grpData = { ...newGroup, additional_contacts: body.additional_contacts };
    const grpPdf = await pdfReceipt('group', grpData);
    email.notifyGroupRegistered(grpData, grpPdf, `DoveNest-Group-${code}.pdf`);
    sendJson(res, 200, { success: true, group_code: code, group_name: newGroup.group_name, pdf: grpPdf, pdf_name: `DoveNest-Group-${code}.pdf` });
    return;
  }

  // ── API: submit last expense application ──────────────────
  if (method === 'POST' && urlPath === '/api/last-expense/apply') {
    let body;
    try { body = await readLargeJsonBody(req); }
    catch (err) { sendJson(res, 400, { error: err.message || 'Invalid request' }); return; }

    // Honeypot → rate-limit → CSRF
    const g = guard(req, body, {
      honeypotBody: () => ({ success: true, ref: generateLeRef() }),
      csrfMessage: 'Invalid or expired session. Please refresh and try again.',
    });
    if (!g.ok) {
      if (g.honeypot) console.log('[last-expense] Honeypot triggered');
      sendJson(res, g.status, g.body); return;
    }

    // Enforce the authoritative underwriter BEFORE validating:
    //    individual = Heritage only; group = the group's chosen underwriter.
    if (body.application_type === 'group') {
      try {
        const rows = await supabaseSelect('groups', `group_code=eq.${encodeURIComponent(body.group_code)}&select=id,underwriter`);
        if (rows.length === 0) {
          sendJson(res, 400, { error: 'Group code not found. Please verify your group code.' }); return;
        }
        if (rows[0].underwriter) body.underwriter = rows[0].underwriter;
      } catch (e) {
        console.error('[apply] group verify failed:', e.message);
        sendJson(res, 503, { error: 'Group lookup unavailable. Please try again shortly.' }); return;
      }
    } else if (body.application_type === 'individual') {
      body.underwriter = 'heritage';
    }

    // 5. Field validation
    const errors = V.validateLePayload(body);
    if (errors.length > 0) {
      sendJson(res, 400, { error: errors[0], errors }); return;
    }

    // 5b. Authoritative premium re-computation — never trust client-sent totals
    const uwProfile = LE.get(body.underwriter);
    const coverType = (uwProfile.coverTypes.length > 1) ? body.cover_scope : uwProfile.coverTypes[0];
    const priced = LE.computePremium(body.underwriter, {
      coverType: coverType,
      coverOption: Number(body.cover_option),
      dependents: body.dependents || [],
    }, V.ageYears);
    if (!priced) {
      sendJson(res, 400, { error: 'Could not price this cover selection.' }); return;
    }
    body.cover_scope    = coverType;
    body.cover_amount   = uwProfile.benefitTiers[Number(body.cover_option) - 1];
    body.base_premium   = priced.base;
    body.extras_premium = priced.extras;
    body.total_premium  = priced.total;

    // 6. Upload all documents to Supabase Storage (must all succeed)
    const ref = generateLeRef();
    let savedDocs = {};
    if (body.documents && typeof body.documents === 'object') {
      try { savedDocs = await saveDocuments(ref, body.documents); }
      catch (e) {
        console.error('[last-expense] Doc upload failed:', e.message);
        sendJson(res, 503, { error: 'Could not upload your documents. Please try again shortly.' }); return;
      }
    }

    // 7. Build application record
    const record = {
      ref,
      submitted_at: new Date().toISOString(),
      status: 'pending',
      application_type: body.application_type,
      group_code: body.group_code || null,
      group_name: body.group_name || null,
      underwriter: body.underwriter,
      cover_scope: body.cover_scope || null,
      cover_option: Number(body.cover_option),
      cover_amount: Number(body.cover_amount),
      base_premium: Number(body.base_premium),
      extras_premium: Number(body.extras_premium) || 0,
      total_premium: Number(body.total_premium),
      principal: {
        full_name: body.full_name.trim(),
        date_of_birth: body.date_of_birth,
        gender: body.gender,
        national_id: body.national_id.trim(),
        kra_pin: body.kra_pin.trim().toUpperCase(),
        email: body.email.trim().toLowerCase(),
        mobile: body.mobile.trim(),
        town: body.town.trim(),
        occupation: body.occupation.trim(),
        po_box: (body.po_box || '').trim(),
        postal_code: (body.postal_code || '').trim()
      },
      dependents: (body.dependents || []).map(d => ({
        id: d.id,
        relationship: d.relationship,
        full_name: String(d.full_name || '').trim(),
        date_of_birth: d.date_of_birth,
        id_number: d.id_number ? String(d.id_number).trim() : null,
        doc_type: d.doc_type,
        mobile: d.mobile || null,
        is_biological: d.is_biological !== undefined ? d.is_biological : null,
        additional_premium: Number(d.additional_premium) || 0
      })),
      documents: savedDocs
    };

    // 8. Save to Supabase (application + dependents + documents) — must succeed
    try {
      const id = await saveLeToSupabase(record);
      console.log(`[supabase] Last expense saved: ${ref} → ${id}`);
    } catch (e) {
      console.error(`[supabase] Last expense save failed: ${e.message}`);
      sendJson(res, 503, { error: 'Could not save your application. Please try again shortly.' }); return;
    }

    const lePdf = await pdfReceipt('last-expense', record);
    email.notifyLastExpense(record, lePdf, `DoveNest-LastExpense-${ref}.pdf`);
    sendJson(res, 200, { success: true, ref, pdf: lePdf, pdf_name: `DoveNest-LastExpense-${ref}.pdf` });
    return;
  }

  // ── API: submit flying doctor quote ─────────────────────
  if (method === 'POST' && urlPath === '/api/flying-doctor-quote') {
    let body;
    try { body = await readLargeJsonBody(req); }
    catch (err) { sendJson(res, 400, { error: err.message || 'Invalid request body' }); return; }

    // Honeypot → rate-limit → CSRF
    const g = guard(req, body, {
      honeypotBody: () => ({ success: true, ref: generateFdRef() }),
    });
    if (!g.ok) {
      if (g.honeypot) console.log('[flying-doctor] Honeypot triggered — bot submission silently dropped');
      sendJson(res, g.status, g.body); return;
    }

    // Field validation
    const fdErrors = V.validateFdPayload(body);
    if (fdErrors.length > 0) {
      sendJson(res, 400, { error: fdErrors[0], errors: fdErrors });
      return;
    }

    // 5. Upload documents to Supabase Storage (must all succeed)
    const ref = generateFdRef();
    let savedFdDocs = {};
    if (body.documents && typeof body.documents === 'object') {
      try { savedFdDocs = await saveFormDocuments('flying-doctor', ref, body.documents); }
      catch (e) {
        console.error('[flying-doctor] Doc upload failed:', e.message);
        sendJson(res, 503, { error: 'Could not upload your documents. Please try again shortly.' }); return;
      }
    }

    // 6. Build record
    const record = {
      ref,
      submitted_at: new Date().toISOString(),
      status:       'pending',
      plan:         body.plan,
      full_name:    body.full_name.trim(),
      phone:        body.phone.trim(),
      email:        body.email.trim().toLowerCase(),
      payment_ref:  (body.payment_ref || '').trim().toUpperCase(),
      members:      (body.members || []).map((m, i) => ({
        full_name:     String(m.full_name || '').trim(),
        date_of_birth: m.date_of_birth,
        age:           Number(m.age) || 0,
        id_passport:   String(m.id_passport || '').trim(),
        relation:      String(m.relation || '').trim(),
        sort_order:    i
      })),
      documents: savedFdDocs
    };

    // 7. Save to Supabase — must succeed
    try {
      await saveFdToSupabase(record);
      console.log(`[supabase] Flying doctor saved: ${ref} — ${record.full_name} (${record.plan})`);
    } catch (e) {
      console.error(`[supabase] Flying doctor save failed: ${e.message}`);
      sendJson(res, 503, { error: 'Could not save your application. Please try again shortly.' }); return;
    }

    const fdData = { ...record, ref };
    const fdPdf = await pdfReceipt('flying-doctor', fdData);
    email.notifyFlyingDoctor(fdData, fdPdf, `DoveNest-FlyingDoctor-${ref}.pdf`);
    sendJson(res, 200, { success: true, ref, pdf: fdPdf, pdf_name: `DoveNest-FlyingDoctor-${ref}.pdf` });
    return;
  }

  if (method === 'POST' && urlPath === '/api/travel-quote') {
    let body;
    try { body = await readLargeJsonBody(req); }
    catch (err) { sendJson(res, 400, { error: err.message || 'Invalid request body' }); return; }

    // Honeypot → rate-limit → CSRF
    const g = guard(req, body, {
      honeypotBody: () => ({ success: true, ref: generateTqRef() }),
    });
    if (!g.ok) {
      if (g.honeypot) console.log('[travel-quote] Honeypot triggered — bot submission silently dropped');
      sendJson(res, g.status, g.body); return;
    }

    // Field validation
    const tqErrors = V.validateTravelQuotePayload(body);
    if (tqErrors.length > 0) {
      sendJson(res, 400, { error: tqErrors[0], errors: tqErrors });
      return;
    }

    // 5. Upload documents to Supabase Storage (must all succeed)
    const ref = generateTqRef();
    let savedTqDocs = {};
    if (body.documents && typeof body.documents === 'object') {
      try { savedTqDocs = await saveFormDocuments('travel-quote', ref, body.documents); }
      catch (e) {
        console.error('[travel-quote] Doc upload failed:', e.message);
        sendJson(res, 503, { error: 'Could not upload your documents. Please try again shortly.' }); return;
      }
    }

    // 6. Build record
    const record = {
      ref,
      submitted_at:         new Date().toISOString(),
      status:               'pending',
      origin:               (body.origin || '').trim(),
      destination:          body.destination.trim(),
      departure_date:       body.departure_date,
      return_date:          body.return_date,
      purpose:              body.purpose,
      cover_type:           body.cover_type,
      medical_evac:         body.medical_evac === true,
      covid_extension:      body.covid_extension === true,
      full_name:            body.full_name.trim(),
      date_of_birth:        body.date_of_birth,
      national_id:          (body.national_id || '').trim(),
      passport_no:          (body.passport_no || '').trim(),
      kra_pin:              (body.kra_pin || '').trim().toUpperCase(),
      occupation:           body.occupation.trim(),
      town:                 body.town.trim(),
      phone:                body.phone.trim(),
      email:                body.email.trim().toLowerCase(),
      payment_method:       body.payment_method,
      beneficiary_name:     body.beneficiary_name.trim(),
      beneficiary_id:       (body.beneficiary_id || '').trim(),
      beneficiary_relation: body.beneficiary_relation,
      beneficiary_phone:    (body.beneficiary_phone || '').trim(),
      travellers:           (body.travellers || []).map((t, i) => ({
        full_name:     String(t.full_name || '').trim(),
        date_of_birth: t.date_of_birth,
        age:           Number(t.age) || 0,
        label:         (Number(t.age) >= 18 ? 'Adult' : 'Child') + ' ' + (i + 1),
        id_passport:   String(t.id_passport || '').trim(),
        relation:      String(t.relation || '').trim(),
        sort_order:    i
      })),
      documents: savedTqDocs
    };

    // Save to Supabase — must succeed
    try {
      await saveTqToSupabase(record);
      console.log(`[supabase] Travel quote saved: ${ref} — ${record.full_name} → ${record.destination}`);
    } catch (e) {
      console.error(`[supabase] Travel quote save failed: ${e.message}`);
      sendJson(res, 503, { error: 'Could not save your application. Please try again shortly.' }); return;
    }

    const tqData = { ...record, ref };
    const tqPdf = await pdfReceipt('travel', tqData);
    email.notifyTravel(tqData, tqPdf, `DoveNest-Travel-${ref}.pdf`);
    sendJson(res, 200, { success: true, ref, pdf: tqPdf, pdf_name: `DoveNest-Travel-${ref}.pdf` });
    return;
  }

  // ── API: submit motor quote ───────────────────────────────
  if (method === 'POST' && urlPath === '/api/motor-quote') {
    let body;
    try {
      body = await readJsonBody(req);
    } catch (err) {
      sendJson(res, 400, { error: err.message || 'Invalid request body' });
      return;
    }

    // Honeypot → rate-limit → CSRF
    const g = guard(req, body, {
      honeypotBody: () => ({ success: true, ref: generateRef() }),
    });
    if (!g.ok) {
      if (g.honeypot) console.log('[motor-quote] Honeypot triggered — bot submission silently dropped');
      sendJson(res, g.status, g.body); return;
    }

    // Validate all required fields (server-side — cannot be bypassed)
    const errors = V.validateMotorQuotePayload(body);
    if (errors.length > 0) {
      sendJson(res, 400, { error: errors[0], errors });
      return;
    }

    // 5. All checks passed — save to Supabase and respond
    const ref = generateRef();
    const quote = {
      ref,
      policy_type:      body.policy_type,
      first_name:       body.first_name.trim(),
      last_name:        body.last_name.trim(),
      date_of_birth:    body.date_of_birth,
      experience_years: Number(body.experience_years),
      email:            body.email.trim().toLowerCase(),
      phone:            body.phone.trim(),
      vehicle_category: body.vehicle_category,
    };

    try {
      await saveToSupabase(quote);
    } catch (e) {
      console.error('[supabase] Failed to save quote:', e.message);
      sendJson(res, 500, { error: 'Server error saving quote. Please try again.' });
      return;
    }

    console.log(`[motor-quote] Saved to Supabase: ${ref} — ${quote.first_name} ${quote.last_name}`);
    sendToN8n(quote); // fire-and-forget — doesn't delay the response
    const motorPdf = await pdfReceipt('motor', quote);
    email.notifyMotor(quote, motorPdf, `DoveNest-Motor-Quote-${ref}.pdf`);
    sendJson(res, 200, { success: true, ref, pdf: motorPdf, pdf_name: `DoveNest-Motor-Quote-${ref}.pdf` });
    return;
  }

  // ── API: submit contact / inquiry form ────────────────────
  if (method === 'POST' && urlPath === '/api/contact') {
    let body;
    try { body = await readJsonBody(req); }
    catch (err) { sendJson(res, 400, { error: err.message || 'Invalid request body' }); return; }

    // Honeypot → rate-limit → CSRF
    const g = guard(req, body, {
      honeypotBody: () => ({ success: true, ref: generateContactRef(body.kind || 'general') }),
    });
    if (!g.ok) {
      if (g.honeypot) console.log('[contact] Honeypot triggered — silently dropped');
      sendJson(res, g.status, g.body); return;
    }

    // Field validation
    const errors = V.validateContactPayload(body);
    if (errors.length > 0) {
      sendJson(res, 400, { error: errors[0], errors });
      return;
    }

    // 5. Build record
    const ref = generateContactRef(body.kind);
    const record = {
      ref,
      kind:             body.kind,
      source_page:      String(body.source_page).trim(),
      product:          body.product || null,
      full_name:        String(body.full_name).trim(),
      email:            String(body.email).trim().toLowerCase(),
      phone:            body.phone ? String(body.phone).trim() : null,
      country:          body.country ? String(body.country).trim() : null,
      city:             body.city ? String(body.city).trim() : null,
      message:          body.message ? String(body.message).trim() : null,
      consent_given_at: new Date().toISOString(),
      user_agent:       (req.headers['user-agent'] || '').slice(0, 500),
      ip_hash:          hashIp(g.ip),
    };

    // 6. Save to Supabase — must succeed
    try {
      await supabaseInsert('contact_inquiries', record);
      console.log(`[contact] Saved: ${ref} — ${record.kind} / ${record.product || '—'} — ${record.email}`);
    } catch (e) {
      console.error(`[contact] Supabase save failed: ${e.message}`);
      sendJson(res, 503, { error: 'Could not send your message. Please try again shortly.' });
      return;
    }

    email.notifyContact(record);
    sendJson(res, 200, { success: true, ref });
    return;
  }

  // ── Static file serving ───────────────────────────────────
  let reqPath = urlPath;
  if (reqPath === '/') reqPath = '/home.html';

  let filePath = path.normalize(path.join(webRoot, reqPath));
  if (!filePath.startsWith(webRoot)) {
    res.writeHead(403); res.end('Forbidden'); return;
  }

  if (fs.existsSync(filePath) && fs.statSync(filePath).isDirectory()) {
    filePath = path.join(filePath, 'home.html');
  }

  if (!fs.existsSync(filePath)) {
    res.writeHead(404); res.end('Not found'); return;
  }

  // Cache policy: long-lived for static assets (instant repeat visits), but keep
  // HTML fresh so content/deploys show immediately. CSS/JS get a short cache so a
  // deploy is picked up within the hour without a hard refresh.
  const ext = path.extname(filePath).toLowerCase();
  const LONG = new Set(['.jpg', '.jpeg', '.png', '.webp', '.gif', '.svg', '.ico', '.mp4', '.webm', '.woff', '.woff2', '.ttf', '.otf']);
  let cacheControl;
  if (ext === '.html')      cacheControl = 'no-cache';
  else if (LONG.has(ext))   cacheControl = 'public, max-age=2592000';      // 30 days
  else                      cacheControl = 'public, max-age=3600';         // 1 hour (css/js)

  res.writeHead(200, {
    'Content-Type': mime[ext] || 'application/octet-stream',
    'Cache-Control': cacheControl,
  });
  fs.createReadStream(filePath).pipe(res);

}).listen(port, '0.0.0.0', () => {
  console.log(`Server running at http://127.0.0.1:${port}/home.html`);
  console.log(`Motor quote form: http://127.0.0.1:${port}/motor-quote.html`);
});
