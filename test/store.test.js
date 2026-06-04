// Tests for store.js — the persistence port.
// The in-memory adapter is exercised directly (it's what tests will use to run
// the save/quote flows offline). A contract check keeps both adapters in shape.
//
// Run with: npm test

const test = require('node:test');
const assert = require('node:assert/strict');
const { createMemoryStore, createSupabaseStore } = require('../server/store.js');

test('insert assigns ids, returns the rows, and accumulates them', async () => {
  const store = createMemoryStore();
  const [a] = await store.insert('groups', { group_code: 'GRP-1', name: 'Alpha' });
  const [b] = await store.insert('groups', { group_code: 'GRP-2', name: 'Beta' });
  assert.equal(a.id, 1);
  assert.equal(b.id, 2);
  assert.equal(a.group_code, 'GRP-1');
  assert.equal(store.tables.groups.length, 2);
});

test('insert accepts either a single row or an array', async () => {
  const store = createMemoryStore();
  const many = await store.insert('group_contacts', [{ name: 'X' }, { name: 'Y' }]);
  assert.equal(many.length, 2);
  assert.deepEqual(many.map(r => r.id), [1, 2]);
});

test('select filters with eq.', async () => {
  const store = createMemoryStore();
  await store.insert('groups', { group_code: 'GRP-1', underwriter: 'heritage' });
  await store.insert('groups', { group_code: 'GRP-2', underwriter: 'absa' });
  const rows = await store.select('groups', 'group_code=eq.GRP-2&select=id,underwriter');
  assert.equal(rows.length, 1);
  assert.equal(rows[0].underwriter, 'absa');
});

test('select filters with ilike. (case-insensitive) and ignores projection', async () => {
  const store = createMemoryStore();
  await store.insert('groups', { group_name: 'Sunrise Chama' });
  const hit = await store.select('groups', 'group_name=ilike.sunrise chama&select=id');
  assert.equal(hit.length, 1);
  const miss = await store.select('groups', 'group_name=ilike.other');
  assert.equal(miss.length, 0);
});

test('select on an unknown table is empty, not an error', async () => {
  const store = createMemoryStore();
  assert.deepEqual(await store.select('nope', 'x=eq.1'), []);
});

test('upload records the object and returns "bucket/path"', async () => {
  const store = createMemoryStore();
  const path = await store.upload('last-expense-docs', 'LE-1/id.png', Buffer.from('xy'), 'image/png');
  assert.equal(path, 'last-expense-docs/LE-1/id.png');
  assert.equal(store.uploads.length, 1);
  assert.equal(store.uploads[0].size, 2);
  assert.equal(store.uploads[0].bucket, 'last-expense-docs');
});

test('both adapters expose the same port surface', () => {
  const mem = createMemoryStore();
  const sb = createSupabaseStore({ url: 'https://x.supabase.co', key: 'k' });
  for (const method of ['insert', 'select', 'upload']) {
    assert.equal(typeof mem[method], 'function', `memory store missing ${method}`);
    assert.equal(typeof sb[method], 'function', `supabase store missing ${method}`);
  }
});

test('supabase adapter rejects cleanly when not configured (no network)', async () => {
  const sb = createSupabaseStore({}); // no url/key
  await assert.rejects(() => sb.insert('t', { a: 1 }), /not configured/);
  await assert.rejects(() => sb.select('t', 'a=eq.1'), /not configured/);
});
