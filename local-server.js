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

  // 6. Vehicle category
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
      vehicle_category: quote.vehicle_category,
      source:           'server',
      status:           'new',
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

}).listen(port, '127.0.0.1', () => {
  console.log(`Server running at http://127.0.0.1:${port}/home.html`);
  console.log(`Motor quote form: http://127.0.0.1:${port}/motor-quote.html`);
});
