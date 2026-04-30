const http  = require('http');
const fs    = require('fs');
const path  = require('path');
const crypto = require('crypto');

const root = __dirname;
const port = 4173;

// ── CSRF configuration ──────────────────────────────────────────────────────
// Change this secret in production (set via environment variable)
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

  // 6. Vehicle category
  if (!body.vehicle_category || !VALID_VEHICLE_CATEGORIES.includes(body.vehicle_category)) {
    errors.push('vehicle_category must be one of: ' + VALID_VEHICLE_CATEGORIES.join(', '));
  }

  return errors;
}

// ── Quote storage ────────────────────────────────────────────────────────────
const DATA_DIR   = path.join(root, 'data');
const QUOTES_FILE = path.join(DATA_DIR, 'motor-quotes.json');

function saveQuote(quote) {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  let quotes = [];
  if (fs.existsSync(QUOTES_FILE)) {
    try { quotes = JSON.parse(fs.readFileSync(QUOTES_FILE, 'utf8')); } catch { quotes = []; }
  }
  quotes.push(quote);
  fs.writeFileSync(QUOTES_FILE, JSON.stringify(quotes, null, 2), 'utf8');
}

function generateRef() {
  const ts   = Date.now().toString(36).toUpperCase();
  const rand = crypto.randomBytes(3).toString('hex').toUpperCase();
  return `DNM-${ts}-${rand}`;
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

  // ── API: issue CSRF token ─────────────────────────────────
  if (method === 'GET' && urlPath === '/api/csrf-token') {
    sendJson(res, 200, { token: issueCsrfToken() });
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

    // 1. Validate CSRF token — reject without explanation if missing/invalid
    if (!validateCsrfToken(body.csrf_token)) {
      sendJson(res, 403, { error: 'Invalid or expired session. Please refresh the page and try again.' });
      return;
    }

    // 2. Validate all required fields (server-side — cannot be bypassed)
    const errors = validateMotorQuotePayload(body);
    if (errors.length > 0) {
      sendJson(res, 400, { error: errors[0], errors });
      return;
    }

    // 3. All checks passed — save and respond
    const ref = generateRef();
    const quote = {
      ref,
      submitted_at:     new Date().toISOString(),
      policy_type:      body.policy_type,
      first_name:       body.first_name.trim(),
      last_name:        body.last_name.trim(),
      date_of_birth:    body.date_of_birth,
      experience_years: Number(body.experience_years),
      vehicle_category: body.vehicle_category,
    };

    try {
      saveQuote(quote);
    } catch (e) {
      console.error('Failed to save quote:', e);
      sendJson(res, 500, { error: 'Server error saving quote. Please try again.' });
      return;
    }

    console.log(`[motor-quote] New quote received: ${ref} — ${quote.first_name} ${quote.last_name}`);
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

}).listen(port, '127.0.0.1', () => {
  console.log(`Server running at http://127.0.0.1:${port}/home.html`);
  console.log(`Motor quote form: http://127.0.0.1:${port}/motor-quote.html`);
});
