/**
 * fetch-partner-logos.js
 *
 * Downloads logos for all DoveNest insurance partners.
 * Strategy:
 *   1. Try Clearbit Logo API (best quality, 200px PNG)
 *   2. Fall back to fetching the site's favicon
 *
 * Run: node fetch-partner-logos.js
 * Output: images/partners/<filename>.png
 */

const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');

const OUT_DIR = path.join(__dirname, 'images', 'partners');
if (!fs.existsSync(OUT_DIR)) fs.mkdirSync(OUT_DIR, { recursive: true });

const PARTNERS = [
  // Tier 1 – Major Insurance Groups
  { name: 'AAR Insurance',         file: 'aar-insurance',       domain: 'aarinsurance.co.ke' },
  { name: 'Absa Life',             file: 'absa',                domain: 'absa.co.ke' },
  { name: 'APA Insurance',         file: 'apa-insurance',       domain: 'apacorp.com' },
  { name: 'Britam',                file: 'britam',              domain: 'britam.com' },
  { name: 'CIC Insurance Group',   file: 'cic-insurance',       domain: 'cicinsurancegroup.com' },
  { name: 'ICEA Lion Group',       file: 'icea-lion',           domain: 'icealion.com' },
  { name: 'Jubilee Allianz',       file: 'jubilee-allianz',     domain: 'jubileeinsurance.com' },
  { name: 'Old Mutual',            file: 'old-mutual',          domain: 'oldmutual.co.ke' },
  { name: 'Sanlam',                file: 'sanlam',              domain: 'sanlam.co.ke' },
  { name: 'Liberty Kenya',         file: 'liberty-kenya',       domain: 'libertylife.co.ke' },
  { name: 'NCBA Insurance',        file: 'ncba-insurance',      domain: 'ncbagroup.com' },
  { name: 'GA Insurance',          file: 'ga-insurance',        domain: 'gainsurance.co.ke' },
  { name: 'Heritage Insurance',    file: 'heritage-insurance',  domain: 'heritage.co.ke' },

  // Tier 2 – Other Licensed Insurers
  { name: 'AMACO',                 file: 'amaco',               domain: 'amacoke.com' },
  { name: 'Cannon Insurance',      file: 'cannon-insurance',    domain: 'cannoninsurance.co.ke' },
  { name: 'Capex Life',            file: 'capex-life',          domain: 'capexlife.co.ke' },
  { name: 'Directline Assurance',  file: 'directline',          domain: 'directline.co.ke' },
  { name: 'First Assurance',       file: 'first-assurance',     domain: 'firstassurance.co.ke' },
  { name: 'Geminia Insurance',     file: 'geminia',             domain: 'geminia.co.ke' },
  { name: 'KUSCCO Mutual',         file: 'kuscco',              domain: 'kuscco.com' },
  { name: 'MUA Insurance',         file: 'mua-insurance',       domain: 'mua.co.ke' },
  { name: 'PACIS Insurance',       file: 'pacis',               domain: 'pacis.co.ke' },
  { name: 'Monarch Insurance',     file: 'monarch-insurance',   domain: 'monarchinsurance.co.ke' },

  // Critical Add
  { name: 'AMREF Flying Doctors',  file: 'amref-flying-doctors', domain: 'amref.org' },
];

// ─── Helpers ────────────────────────────────────────────────────────────────

function fetch(url) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https') ? https : http;
    const req = lib.get(url, { headers: { 'User-Agent': 'Mozilla/5.0' }, timeout: 10000 }, res => {
      // Follow up to 3 redirects
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
        return fetch(res.headers.location).then(resolve).catch(reject);
      }
      if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode}`));
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({ buffer: Buffer.concat(chunks), contentType: res.headers['content-type'] || '' }));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
  });
}

function isValidImage(buffer, contentType) {
  if (buffer.length < 100) return false;                          // too small
  if (contentType.includes('html') || contentType.includes('text')) return false;
  // Check magic bytes
  const hex = buffer.slice(0, 4).toString('hex');
  const isPng  = hex.startsWith('89504e47');
  const isJpeg = hex.startsWith('ffd8ff');
  const isGif  = buffer.slice(0, 3).toString('ascii') === 'GIF';
  const isWebP = buffer.slice(0, 4).toString('ascii') === 'RIFF' && buffer.slice(8, 12).toString('ascii') === 'WEBP';
  const isSvg  = contentType.includes('svg') || buffer.slice(0, 5).toString('ascii') === '<?xml' || buffer.slice(0, 4).toString('ascii') === '<svg';
  const isIco  = hex.startsWith('00000100');
  return isPng || isJpeg || isGif || isWebP || isSvg || isIco;
}

function ext(contentType, fallback = '.png') {
  if (contentType.includes('svg'))  return '.svg';
  if (contentType.includes('jpeg') || contentType.includes('jpg')) return '.jpg';
  if (contentType.includes('gif'))  return '.gif';
  if (contentType.includes('webp')) return '.webp';
  if (contentType.includes('ico'))  return '.ico';
  return fallback;
}

// ─── Strategies ─────────────────────────────────────────────────────────────

async function tryClearbit(domain) {
  const url = `https://logo.clearbit.com/${domain}?size=200`;
  const res = await fetch(url);
  if (!isValidImage(res.buffer, res.contentType)) throw new Error('not a valid image');
  return { buffer: res.buffer, ext: '.png' };  // clearbit always returns PNG
}

async function tryFavicon(domain) {
  // Try common logo paths before falling back to favicon
  const paths = [
    `/logo.png`, `/logo.svg`, `/images/logo.png`, `/img/logo.png`,
    `/assets/logo.png`, `/assets/images/logo.png`,
    `/wp-content/uploads/logo.png`,
    `/favicon.png`, `/favicon.ico`,
  ];
  for (const p of paths) {
    try {
      const res = await fetch(`https://${domain}${p}`);
      if (isValidImage(res.buffer, res.contentType)) {
        return { buffer: res.buffer, ext: ext(res.contentType, '.png') };
      }
    } catch { /* try next */ }
  }
  throw new Error('no logo found at common paths');
}

async function tryGoogleFavicon(domain) {
  const url = `https://www.google.com/s2/favicons?domain=${domain}&sz=128`;
  const res = await fetch(url);
  if (!isValidImage(res.buffer, res.contentType)) throw new Error('invalid');
  return { buffer: res.buffer, ext: '.png' };
}

// ─── Main ────────────────────────────────────────────────────────────────────

const results = { success: [], failed: [] };

async function processPartner(partner) {
  const strategies = [
    { label: 'Clearbit',        fn: () => tryClearbit(partner.domain) },
    { label: 'Site favicon',    fn: () => tryFavicon(partner.domain) },
    { label: 'Google favicon',  fn: () => tryGoogleFavicon(partner.domain) },
  ];

  for (const { label, fn } of strategies) {
    try {
      const { buffer, ext: extension } = await fn();
      const outFile = path.join(OUT_DIR, `${partner.file}${extension}`);
      fs.writeFileSync(outFile, buffer);
      const kb = (buffer.length / 1024).toFixed(1);
      console.log(`  ✅  ${partner.name.padEnd(28)} [${label}]  →  ${partner.file}${extension}  (${kb} KB)`);
      results.success.push({ ...partner, strategy: label, outFile: `images/partners/${partner.file}${extension}` });
      return;
    } catch (err) {
      // try next strategy
    }
  }

  console.log(`  ❌  ${partner.name.padEnd(28)} — all strategies failed`);
  results.failed.push(partner);
}

async function run() {
  console.log(`\nFetching logos for ${PARTNERS.length} partners...\n`);
  console.log(`Output: ${OUT_DIR}\n`);

  // Run 4 at a time to be polite to remote servers
  for (let i = 0; i < PARTNERS.length; i += 4) {
    const batch = PARTNERS.slice(i, i + 4);
    await Promise.all(batch.map(processPartner));
  }

  console.log('\n─────────────────────────────────────────────────');
  console.log(`Done. ${results.success.length} downloaded, ${results.failed.length} failed.\n`);

  if (results.failed.length > 0) {
    console.log('⚠️  Failed — add these manually:');
    results.failed.forEach(p => console.log(`   • ${p.name}  (${p.domain})`));
    console.log();
  }

  // Write a summary JSON you can reference when updating home.html
  const summaryPath = path.join(__dirname, 'partner-logos-summary.json');
  fs.writeFileSync(summaryPath, JSON.stringify({
    downloaded: results.success.map(p => ({ name: p.name, file: p.outFile, strategy: p.strategy })),
    failed:     results.failed.map(p => ({ name: p.name, domain: p.domain })),
  }, null, 2));
  console.log(`Summary written to partner-logos-summary.json`);
}

run().catch(console.error);
