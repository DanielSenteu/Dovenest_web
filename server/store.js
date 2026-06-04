// ─────────────────────────────────────────────────────────────────────────────
// store.js — the persistence port and its adapters.
//
// Port (the seam every persistence call crosses):
//   insert(table, rows)              → Promise<row[]>   (rows gain an id)
//   select(table, query)            → Promise<row[]>   (PostgREST-style filters)
//   upload(bucket, path, buf, mime) → Promise<string>  (returns "bucket/path")
//
// Two adapters justify the seam:
//   • createSupabaseStore — production: Supabase REST + Storage over HTTPS.
//   • createMemoryStore   — tests: in-memory, no network, with eq./ilike. filters.
//
// The application logic (record-building, document encoding, the request flow)
// lives in server/server.js and talks only to this port, so it can run against
// the in-memory adapter offline.
// ─────────────────────────────────────────────────────────────────────────────

const https = require('https');

// ── Production adapter: Supabase REST + Storage ──────────────────────────────
function createSupabaseStore({ url: baseUrl, key } = {}) {
  function ensure() { if (!baseUrl || !key) throw new Error('Supabase not configured'); }

  return {
    insert(table, rows) {
      return new Promise((resolve, reject) => {
        try { ensure(); } catch (e) { return reject(e); }
        const body = JSON.stringify(Array.isArray(rows) ? rows : [rows]);
        const u = new URL(`/rest/v1/${table}`, baseUrl);
        const req = https.request({
          hostname: u.hostname, path: u.pathname, method: 'POST',
          headers: {
            'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body),
            'apikey': key, 'Authorization': `Bearer ${key}`, 'Prefer': 'return=representation',
          },
        }, res => {
          let d = ''; res.on('data', c => d += c);
          res.on('end', () => {
            if (res.statusCode >= 200 && res.statusCode < 300) { try { resolve(JSON.parse(d)); } catch { resolve([]); } }
            else reject(new Error(`Supabase ${table} ${res.statusCode}: ${d}`));
          });
        });
        req.on('error', reject); req.write(body); req.end();
      });
    },

    select(table, query) {
      return new Promise((resolve, reject) => {
        try { ensure(); } catch (e) { return reject(e); }
        const u = new URL(`/rest/v1/${table}?${query}`, baseUrl);
        const req = https.request({
          hostname: u.hostname, path: u.pathname + u.search, method: 'GET',
          headers: { 'apikey': key, 'Authorization': `Bearer ${key}` },
        }, res => {
          let d = ''; res.on('data', c => d += c);
          res.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve([]); } });
        });
        req.on('error', reject); req.end();
      });
    },

    upload(bucket, storagePath, buffer, mimeType) {
      return new Promise((resolve, reject) => {
        try { ensure(); } catch (e) { return reject(e); }
        let u;
        try { u = new URL(`/storage/v1/object/${bucket}/${storagePath}`, baseUrl); }
        catch { return reject(new Error('Invalid SUPABASE_URL')); }
        const req = https.request({
          hostname: u.hostname, path: u.pathname, method: 'POST',
          headers: { 'Authorization': `Bearer ${key}`, 'Content-Type': mimeType, 'Content-Length': buffer.length, 'x-upsert': 'true' },
        }, res => {
          let d = ''; res.on('data', c => d += c);
          res.on('end', () => {
            if (res.statusCode >= 200 && res.statusCode < 300) resolve(`${bucket}/${storagePath}`);
            else reject(new Error(`Supabase Storage ${res.statusCode}: ${d}`));
          });
        });
        req.on('error', reject); req.write(buffer); req.end();
      });
    },
  };
}

// ── Test adapter: in-memory ──────────────────────────────────────────────────
function createMemoryStore() {
  const tables = {};   // table -> row[]
  const uploads = [];  // { bucket, path, size, mimeType }
  let seq = 0;

  return {
    tables, uploads, // exposed for test assertions

    insert(table, rows) {
      const arr = Array.isArray(rows) ? rows : [rows];
      const saved = arr.map(r => ({ id: ++seq, ...r }));
      (tables[table] = tables[table] || []).push(...saved);
      return Promise.resolve(saved);
    },

    select(table, query) {
      let rows = tables[table] || [];
      for (const part of String(query).split('&')) {
        const m = part.match(/^([^=]+)=(eq|ilike)\.(.*)$/);
        if (!m) continue; // ignore select=, order=, etc.
        const [, field, op, raw] = m;
        const val = decodeURIComponent(raw).replace(/\*/g, '');
        rows = rows.filter(r => {
          const cell = String(r[field]);
          return op === 'ilike' ? cell.toLowerCase() === val.toLowerCase() : cell === val;
        });
      }
      return Promise.resolve(rows);
    },

    upload(bucket, storagePath, buffer, mimeType) {
      uploads.push({ bucket, path: storagePath, size: buffer.length, mimeType });
      return Promise.resolve(`${bucket}/${storagePath}`);
    },
  };
}

module.exports = { createSupabaseStore, createMemoryStore };
