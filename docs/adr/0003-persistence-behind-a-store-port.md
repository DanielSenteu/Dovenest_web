# 3. Persistence sits behind a store port

Date: 2026-06-03

## Status

Accepted

## Context

`local-server.js` had grown to 1,608 lines mixing routing, validation, the
security preamble, and Supabase access (REST + Storage) with bespoke `https`
plumbing repeated across several functions. Persistence calls were scattered, so
the request flows could only be exercised against a live Supabase over the
network — there was no way to test them offline.

## Decision

All persistence goes through a single **store port** (`store.js`) with three
operations: `insert(table, rows)`, `select(table, query)`, `upload(bucket, path,
buffer, mimeType)`. Two adapters implement it:

- `createSupabaseStore({ url, key })` — production (Supabase REST + Storage).
- `createMemoryStore()` — tests (in-memory; supports `eq.`/`ilike.` filters).

`local-server.js` creates the Supabase adapter and talks only to the port. The
field validators (`validators.js`) and the honeypot/rate-limit/CSRF guard
(`request-guard.js`) were extracted in the same effort. Each extracted module is
pure or injectable and covered by tests in `test/`.

## Consequences

- Two adapters justify a real seam (not just indirection): prod vs. in-memory.
- Persistence logic is concentrated in one adapter (locality); the bespoke
  per-call `https` blocks are gone.
- `local-server.js` is down to ~1,035 lines and no longer imports `https` for
  persistence (only for the n8n webhook notification).
- Request flows can now be made fully offline-testable by passing the store as a
  dependency — see CONTEXT.md "optional follow-up".
- Behavior is unchanged: insert/select/upload were verified end-to-end against
  real Supabase (group register, code lookup, motor save, last-expense apply).
