const http   = require('http');
const https  = require('https');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

const root = __dirname;
const port = 4173;

// ── Load .env (never committed to git) ──────────────────────────────────────
const envFile = path.join(root, '.env');
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
const VALID_POLICY_TYPES = ['personal', 'business'];
const VALID_VEHICLE_CATEGORIES = [
  'PRIVATE CAR',
  'MOTOR COMMERCIAL',
  'PRIVATE MOTOR CYCLE',
  'INSTITUTIONAL VEHICLES',
  'PETROLEUM TANKERS',
];

function validateMotorQuotePayload(body) {
  const errors = [];

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
      const now    = new Date();
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

function saveToSupabase(quote) {
  return new Promise((resolve, reject) => {
    if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
      return reject(new Error('Supabase credentials not set in .env'));
    }

    const row = {
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
    };

    const body = JSON.stringify(row);
    const url  = new URL('/rest/v1/motor_quotes', SUPABASE_URL);

    const options = {
      hostname: url.hostname,
      path:     url.pathname,
      method:   'POST',
      headers: {
        'Content-Type':  'application/json',
        'Content-Length': Buffer.byteLength(body),
        'apikey':        SUPABASE_SERVICE_KEY,
        'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Prefer':        'return=minimal',
      },
    };

    const req = https.request(options, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve();
        } else {
          reject(new Error(`Supabase ${res.statusCode}: ${data}`));
        }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
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

// ── Large body reader (for last expense with base64 docs) ─────────────────────
function readLargeJsonBody(req, maxBytes = 25 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let raw = '';
    let size = 0;
    req.on('data', chunk => {
      size += chunk.length;
      if (size > maxBytes) { reject(new Error('Body too large')); return; }
      raw += chunk;
    });
    req.on('end', () => {
      try { resolve(JSON.parse(raw)); }
      catch { reject(new Error('Invalid JSON')); }
    });
    req.on('error', reject);
  });
}

// ── Last expense: load/save helpers ──────────────────────────────────────────
const GROUPS_FILE = path.join(__dirname, 'data', 'groups.json');
const LE_QUOTES_FILE = path.join(__dirname, 'data', 'last-expense-quotes.json');

function loadJson(filePath) {
  try { return JSON.parse(fs.readFileSync(filePath, 'utf8')); }
  catch { return []; }
}

function saveJson(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
}

// ── Last expense field validation ─────────────────────────────────────────────
function validateLePayload(body) {
  const errors = [];
  const VALID_TYPES       = ['individual', 'group'];
  const VALID_UNDERWRITERS = ['absa', 'capex'];
  const VALID_OPTIONS     = [1, 2, 3, 4, 5, 6, 7];

  if (!VALID_TYPES.includes(body.application_type))
    errors.push('application_type must be "individual" or "group"');

  if (body.application_type === 'group' && !body.group_code)
    errors.push('group_code is required for group applications');

  if (!VALID_UNDERWRITERS.includes(body.underwriter))
    errors.push('underwriter must be "absa" or "capex"');

  if (!VALID_OPTIONS.includes(Number(body.cover_option)))
    errors.push('cover_option must be 1–7');

  // Principal
  if (!body.full_name || String(body.full_name).trim().length < 2)
    errors.push('full_name is required');

  if (!body.date_of_birth || !/^\d{4}-\d{2}-\d{2}$/.test(body.date_of_birth))
    errors.push('date_of_birth must be YYYY-MM-DD');
  else {
    const age = ageYears(body.date_of_birth);
    if (age < 18 || age > 69) errors.push('Principal member must be aged 18–69');
  }

  if (!['M', 'F'].includes(body.gender))
    errors.push('gender must be M or F');

  if (!body.national_id || String(body.national_id).trim().length < 4)
    errors.push('national_id is required');

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

  // Dependents
  if (body.dependents && Array.isArray(body.dependents)) {
    const spouseCount = body.dependents.filter(d => d.relationship === 'spouse').length;
    if (spouseCount > 1) errors.push('Maximum 1 spouse allowed');

    const parentTypes = ['mother', 'father', 'mother_in_law', 'father_in_law'];
    parentTypes.forEach(rel => {
      const count = body.dependents.filter(d => d.relationship === rel).length;
      if (count > 1) errors.push(`Maximum 1 ${rel.replace(/_/g,' ')} allowed`);
    });

    body.dependents.forEach((dep, i) => {
      const prefix = `Dependent ${i + 1} (${dep.relationship})`;
      if (!dep.full_name || String(dep.full_name).trim().length < 2)
        errors.push(`${prefix}: full_name is required`);
      if (!dep.date_of_birth || !/^\d{4}-\d{2}-\d{2}$/.test(dep.date_of_birth))
        errors.push(`${prefix}: date_of_birth is required (YYYY-MM-DD)`);
      else {
        const age = ageYears(dep.date_of_birth);
        if (dep.relationship === 'spouse' && (age < 18 || age > 69))
          errors.push(`${prefix}: spouse must be aged 18–69`);
        if (parentTypes.includes(dep.relationship) && (age < 31 || age > 85))
          errors.push(`${prefix}: parents must be aged 31–85`);
        if (dep.relationship === 'child') {
          if (age > 29) errors.push(`${prefix}: maximum age for children is 29 years`);
          if (age >= 25 && body.underwriter !== 'absa')
            errors.push(`${prefix}: children aged 25–29 are only available under ABSA`);
        }
      }
    });
  }

  // Documents — check at least the two mandatory principal docs are present
  if (!body.documents || !body.documents.principal_national_id)
    errors.push('National ID document (principal_national_id) is required');
  if (!body.documents || !body.documents.principal_kra_pin)
    errors.push('KRA PIN document (principal_kra_pin) is required');
  if (!body.documents || !body.documents.signature)
    errors.push('Signed declaration (signature) is required');

  return errors;
}

function ageYears(dob) {
  const d = new Date(dob); const now = new Date();
  let age = now.getFullYear() - d.getFullYear();
  const m = now.getMonth() - d.getMonth();
  if (m < 0 || (m === 0 && now.getDate() < d.getDate())) age--;
  return age;
}

// ── Supabase REST helpers (last expense) ─────────────────────────────────────
function supabaseInsert(table, rows) {
  return new Promise((resolve, reject) => {
    if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return reject(new Error('Supabase not configured'));
    const body = JSON.stringify(Array.isArray(rows) ? rows : [rows]);
    const url  = new URL(`/rest/v1/${table}`, SUPABASE_URL);
    const options = {
      hostname: url.hostname,
      path:     url.pathname,
      method:   'POST',
      headers: {
        'Content-Type':   'application/json',
        'Content-Length': Buffer.byteLength(body),
        'apikey':         SUPABASE_SERVICE_KEY,
        'Authorization':  `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Prefer':         'return=representation',
      },
    };
    const req = https.request(options, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          try { resolve(JSON.parse(d)); } catch { resolve([]); }
        } else {
          reject(new Error(`Supabase ${table} ${res.statusCode}: ${d}`));
        }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function supabaseSelect(table, query) {
  return new Promise((resolve, reject) => {
    if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return reject(new Error('Supabase not configured'));
    const url = new URL(`/rest/v1/${table}?${query}`, SUPABASE_URL);
    const options = {
      hostname: url.hostname,
      path:     url.pathname + url.search,
      method:   'GET',
      headers: {
        'apikey':        SUPABASE_SERVICE_KEY,
        'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
      },
    };
    const req = https.request(options, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve([]); } });
    });
    req.on('error', reject);
    req.end();
  });
}

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

function uploadToSupabaseStorage(storagePath, buffer, mimeType) {
  return new Promise((resolve, reject) => {
    if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
      return reject(new Error('Supabase credentials not configured'));
    }
    let url;
    try { url = new URL(`/storage/v1/object/${LE_BUCKET}/${storagePath}`, SUPABASE_URL); }
    catch { return reject(new Error('Invalid SUPABASE_URL')); }

    const options = {
      hostname: url.hostname,
      path:     url.pathname,
      method:   'POST',
      headers: {
        'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type':  mimeType,
        'Content-Length': buffer.length,
        'x-upsert':      'true',
      },
    };

    const req = https.request(options, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve(`${LE_BUCKET}/${storagePath}`);
        } else {
          reject(new Error(`Supabase Storage ${res.statusCode}: ${data}`));
        }
      });
    });
    req.on('error', reject);
    req.write(buffer);
    req.end();
  });
}

// ── Save uploaded base64 documents — local disk + Supabase Storage ────────────
async function saveDocuments(ref, documents) {
  const uploadDir = path.join(__dirname, 'uploads', 'last-expense', ref);
  fs.mkdirSync(uploadDir, { recursive: true });

  const useSupabase = !!(SUPABASE_URL && SUPABASE_SERVICE_KEY);
  const saved = {};

  for (const [key, doc] of Object.entries(documents)) {
    if (!doc || !doc.data) continue;
    const matches = doc.data.match(/^data:([A-Za-z-+/]+);base64,(.+)$/s);
    if (!matches) continue;

    const mimeType = matches[1];
    const buffer   = Buffer.from(matches[2], 'base64');
    const ext      = mimeType === 'image/png' ? 'png' : mimeType === 'application/pdf' ? 'pdf' : 'jpg';
    const filename = `${key}.${ext}`;
    const localPath = path.join(uploadDir, filename);

    // Always write to local disk as backup / dev fallback
    try {
      fs.writeFileSync(localPath, buffer);
    } catch (e) {
      console.error(`[last-expense] Local write failed for ${key}:`, e.message);
    }

    if (useSupabase) {
      try {
        const storagePath = await uploadToSupabaseStorage(`${ref}/${filename}`, buffer, mimeType);
        saved[key] = storagePath;
        console.log(`[storage] ✓ ${storagePath}`);
      } catch (e) {
        console.error(`[storage] Upload failed for ${key} — falling back to local:`, e.message);
        saved[key] = `uploads/last-expense/${ref}/${filename}`;
      }
    } else {
      saved[key] = `uploads/last-expense/${ref}/${filename}`;
    }
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
    const groups = loadJson(GROUPS_FILE);
    const group = groups.find(g => g.group_code === code);
    if (group) {
      sendJson(res, 200, { group_code: group.group_code, group_name: group.group_name, group_type: group.group_type });
    } else {
      sendJson(res, 404, { error: 'Group code not found' });
    }
    return;
  }

  // ── API: register new group ───────────────────────────────
  if (method === 'POST' && urlPath === '/api/last-expense/group/register') {
    let body;
    try { body = await readJsonBody(req); }
    catch (err) { sendJson(res, 400, { error: err.message }); return; }

    // Honeypot
    if (body.website && String(body.website).trim().length > 0) {
      sendJson(res, 200, { success: true, group_code: generateGroupCode() }); return;
    }

    // CSRF
    if (!validateCsrfToken(body.csrf_token)) {
      sendJson(res, 403, { error: 'Invalid session. Please refresh and try again.' }); return;
    }

    // Validate group fields
    const errs = [];
    if (!body.group_name || String(body.group_name).trim().length < 2) errs.push('group_name is required');
    if (!['chama','church','sacco','alumni','welfare','other'].includes(body.group_type)) errs.push('group_type is required');
    if (!body.group_contact_person || String(body.group_contact_person).trim().length < 2) errs.push('contact_person is required');
    if (!body.group_contact_position || String(body.group_contact_position).trim().length < 2) errs.push('contact_position is required');
    if (!body.group_contact_phone || !/^\+\d{9,15}$/.test(String(body.group_contact_phone).trim())) errs.push('A valid phone number is required');
    if (errs.length > 0) { sendJson(res, 400, { error: errs[0], errors: errs }); return; }

    // Check for duplicate group name (case-insensitive)
    const groups = loadJson(GROUPS_FILE);
    const nameNorm = body.group_name.trim().toLowerCase();
    if (groups.find(g => g.group_name.toLowerCase() === nameNorm)) {
      sendJson(res, 409, { error: 'A group with this name already exists. If this is your group, ask your leader for the group code.' }); return;
    }

    const code = generateGroupCode();
    const newGroup = {
      group_code: code,
      group_name: body.group_name.trim(),
      group_type: body.group_type,
      contact_person: body.group_contact_person.trim(),
      contact_position: body.group_contact_position.trim(),
      contact_phone: body.group_contact_phone.trim(),
      registered: body.group_registered === true || body.group_registered === 'true',
      created_at: new Date().toISOString()
    };
    groups.push(newGroup);
    saveJson(GROUPS_FILE, groups);

    console.log(`[group] Registered: ${code} — ${newGroup.group_name}`);
    sendJson(res, 200, { success: true, group_code: code, group_name: newGroup.group_name });
    return;
  }

  // ── API: submit last expense application ──────────────────
  if (method === 'POST' && urlPath === '/api/last-expense/apply') {
    let body;
    try { body = await readLargeJsonBody(req); }
    catch (err) { sendJson(res, 400, { error: err.message || 'Invalid request' }); return; }

    // 1. Honeypot
    if (body.website && String(body.website).trim().length > 0) {
      console.log('[last-expense] Honeypot triggered');
      sendJson(res, 200, { success: true, ref: generateLeRef() }); return;
    }

    // 2. Rate limit
    const clientIp = req.socket.remoteAddress || 'unknown';
    if (!checkRateLimit(clientIp)) {
      sendJson(res, 429, { error: 'Too many requests. Please try again later.' }); return;
    }

    // 3. CSRF
    if (!validateCsrfToken(body.csrf_token)) {
      sendJson(res, 403, { error: 'Invalid or expired session. Please refresh and try again.' }); return;
    }

    // 4. Field validation
    const errors = validateLePayload(body);
    if (errors.length > 0) {
      sendJson(res, 400, { error: errors[0], errors }); return;
    }

    // 5. If group application, verify group code exists
    if (body.application_type === 'group') {
      const groups = loadJson(GROUPS_FILE);
      const group = groups.find(g => g.group_code === body.group_code);
      if (!group) {
        sendJson(res, 400, { error: 'Group code not found. Please verify your group code.' }); return;
      }
    }

    // 6. Save documents to disk
    const ref = generateLeRef();
    let savedDocs = {};
    if (body.documents && typeof body.documents === 'object') {
      try { savedDocs = await saveDocuments(ref, body.documents); }
      catch (e) { console.error('[last-expense] Doc save error:', e.message); }
    }

    // 7. Build and save application record
    const record = {
      ref,
      submitted_at: new Date().toISOString(),
      status: 'pending',
      application_type: body.application_type,
      group_code: body.group_code || null,
      group_name: body.group_name || null,
      underwriter: body.underwriter,
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

    const quotes = loadJson(LE_QUOTES_FILE);
    quotes.push(record);
    saveJson(LE_QUOTES_FILE, quotes);

    console.log(`[last-expense] Saved locally: ${ref} — ${record.principal.full_name} (${body.underwriter.toUpperCase()} opt${body.cover_option})`);

    // Save to Supabase (application + dependents + documents)
    saveLeToSupabase(record)
      .then(id => console.log(`[supabase] Last expense saved: ${ref} → ${id}`))
      .catch(e  => console.error(`[supabase] Last expense save failed: ${e.message}`));

    sendJson(res, 200, { success: true, ref });
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

    // 1. Honeypot check — bots fill hidden fields, humans never see them
    //    Return a fake success so bots don't know they've been caught
    if (body.website && String(body.website).trim().length > 0) {
      console.log('[motor-quote] Honeypot triggered — bot submission silently dropped');
      sendJson(res, 200, { success: true, ref: generateRef() });
      return;
    }

    // 2. Rate limit — max 5 submissions per IP per hour
    const clientIp = req.socket.remoteAddress || 'unknown';
    if (!checkRateLimit(clientIp)) {
      sendJson(res, 429, { error: 'Too many requests. Please try again later.' });
      return;
    }

    // 3. Validate CSRF token — reject without explanation if missing/invalid
    if (!validateCsrfToken(body.csrf_token)) {
      sendJson(res, 403, { error: 'Invalid or expired session. Please refresh the page and try again.' });
      return;
    }

    // 4. Validate all required fields (server-side — cannot be bypassed)
    const errors = validateMotorQuotePayload(body);
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
    sendJson(res, 200, { success: true, ref });
    return;
  }

  // ── Static file serving ───────────────────────────────────
  let reqPath = urlPath;
  if (reqPath === '/') reqPath = '/home.html';

  let filePath = path.normalize(path.join(root, reqPath));
  if (!filePath.startsWith(root)) {
    res.writeHead(403); res.end('Forbidden'); return;
  }

  if (fs.existsSync(filePath) && fs.statSync(filePath).isDirectory()) {
    filePath = path.join(filePath, 'home.html');
  }

  if (!fs.existsSync(filePath)) {
    res.writeHead(404); res.end('Not found'); return;
  }

  res.writeHead(200, {
    'Content-Type': mime[path.extname(filePath).toLowerCase()] || 'application/octet-stream',
  });
  fs.createReadStream(filePath).pipe(res);

}).listen(port, '0.0.0.0', () => {
  console.log(`Server running at http://127.0.0.1:${port}/home.html`);
  console.log(`Motor quote form: http://127.0.0.1:${port}/motor-quote.html`);
});
