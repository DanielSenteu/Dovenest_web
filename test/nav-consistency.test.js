// Guards the site nav against drift. The nav is currently copy-pasted into every
// content page (no single source yet), and it has drifted before — pages showed
// different orderings and one Insurance dropdown was missing "Travel Insurance".
// These tests fail the moment any page's nav arrangement diverges from the rest.
//
// Run with: npm test

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..', 'public');

// The nav link arrangement of a page: the ordered sequence of top-level links,
// dropdown toggles (BTN:) and dropdown links — ignoring the per-page active mark.
function navSignature(html) {
  const i = html.indexOf('nav-links"');
  if (i < 0) return null;
  const j = html.indexOf('</nav>', i);
  const seg = html.slice(i, j < 0 ? i + 5000 : j);
  const items = [];
  const re = /<a\b[^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>|<button[^>]*class="nav-menu-btn[^"]*"[^>]*>([\s\S]*?)<\/button>/g;
  let m;
  while ((m = re.exec(seg))) {
    if (m[3] !== undefined) items.push('BTN:' + m[3].replace(/<[^>]+>/g, '').trim());
    else items.push(m[1].trim() + ' = ' + m[2].replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim());
  }
  return items;
}

// Every page that carries the marketing nav (forms/admin use a different header).
function pagesWithNav() {
  return fs.readdirSync(ROOT)
    .filter(f => f.endsWith('.html'))
    .map(f => ({ file: f, html: fs.readFileSync(path.join(ROOT, f), 'utf8') }))
    .filter(p => p.html.includes('class="nav-links"'))
    .map(p => ({ file: p.file, sig: navSignature(p.html) }));
}

test('every content page shares one identical nav arrangement', () => {
  const pages = pagesWithNav();
  assert.ok(pages.length >= 15, `expected the nav on most pages, found ${pages.length}`);

  const baseline = pages[0];
  const drifted = pages.filter(p => JSON.stringify(p.sig) !== JSON.stringify(baseline.sig));
  assert.deepEqual(
    drifted.map(p => p.file), [],
    `these pages have a different nav arrangement than ${baseline.file}:\n` +
    drifted.map(p => '  ' + p.file).join('\n')
  );
});

test('the Insurance dropdown lists every product, including Travel Insurance', () => {
  // The specific regression we hit: general-insurance.html was missing Travel.
  const required = [
    'life-insurance.html', 'life-pension-products.html', 'health-insurance.html',
    'education-insurance.html', 'motor-insurance.html', 'diaspora-insurance.html',
    'general-insurance.html', 'travel-insurance.html',
  ];
  for (const { file, sig } of pagesWithNav()) {
    const hrefs = sig.map(s => s.split(' = ')[0]);
    for (const r of required) {
      assert.ok(hrefs.includes(r), `${file} nav is missing "${r}"`);
    }
  }
});
