# DoveNest Insurance — Project Context & Domain Glossary

This file is the shared domain language for the codebase. The
`improve-codebase-architecture` skill reads it (plus `docs/adr/`) to ground its
analysis. Keep terms here consistent with the names used in code.

## What this is

A marketing website + self-hosted quote/application system for **DoveNest
Insurance Brokers Ltd** (Nairobi, Kenya — est. 2006). DoveNest is a **broker**,
not a direct insurer: it places clients with multiple **underwriters**.

- **Frontend:** static HTML pages + assets, all under `public/` (the web root the
  server serves). Shared styling in `public/shared-site.css`, shared JS helpers in
  `public/shared-*.js`. The nav is single-sourced (see below).
- **Backend:** a single Node `http` server, `server/server.js`, serving `public/`
  and handling quote/application submissions, persisting to **Supabase**.
- **Pricing/eligibility engine:** `public/last-expense-underwriters.js` — a UMD
  module loaded by both the browser (live quote ticker) and the server
  (authoritative re-check). **Single source of truth** for underwriters/tiers/ages.

## Repository layout

```
public/    web root — every page + asset the server serves (HTML, css, js,
           images/, videos/, downloads/, files/, admin/, the shared UMD module)
server/    backend only — server.js, validators.js, request-guard.js, store.js
scripts/   tooling — build.js (nav sync), fetch-partner-logos.js, seed SQL
partials/  nav.html (the single nav source build.js injects into public/*.html)
test/      node:test suites          docs/ ADRs + notes          data/ uploads/ runtime
```

Commands: `npm start` (run server), `npm test` (37 tests), `npm run build` (sync nav).

## Domain glossary

- **Broker** — DoveNest. Advises clients and places cover with underwriters; does
  not carry risk itself.
- **Underwriter** — the insurer that carries the risk. Last Expense underwriters:
  **Liberty Life** (id `heritage`, the only one available for individuals),
  **ABSA Life** (`absa`), **Capex Life** (`capex`). Do not reintroduce the old
  "Liberty | Heritage" label — see ADR-0002.
- **Last Expense** — funeral/bereavement cover. The one product line that remains
  explicitly product-and-price focused (vs. the advisory tone elsewhere).
- **Principal member** — the person who holds the policy. Group cover requires a
  minimum of **10 principal members** to activate.
- **Dependent** — a person covered under a principal's policy: `spouse`, `child`,
  `mother`, `father`, `mother_in_law`, `father_in_law`, `sibling`.
- **Parent relationship** — `mother | father | mother_in_law | father_in_law`
  (`PARENT_RELS`). Only **biological** parents are eligible; the applicant must
  attest this (client + server enforced).
- **Cover type / cover scope** — who is covered: `member` (principal only),
  `nuclear` (spouse + children), `extended` (+ parents/in-laws/siblings); legacy
  `family` for ABSA/Capex. Stored as `cover_scope`.
- **Cover option / benefit tier** — the sum assured (KES). A 1-based `cover_option`
  indexes into the underwriter's `benefitTiers`.
- **Pricing model** — `modular` (Liberty Life: member/nuclear base + per-parent
  add-ons) or `base_addon` (ABSA/Capex: family base + extra-child / 25–29 child).
- **Group** — a chama, church, SACCO, alumni or welfare group applying together.
  Registers once → gets a **group code** → members apply individually with it.
- **Application type** — `individual` or `group`.

## Form security vocabulary (every self-hosted form)

- **Honeypot** — hidden `website` field; server returns a fake success if filled.
- **Rate limit** — in-memory cap of 5 submissions / IP / hour.
- **CSRF token** — `timestamp.HMAC(timestamp, secret)`, 30-min TTL, fetched on
  load and sent with POST.
- Check order in every POST handler: **honeypot → rate limit → CSRF → field
  validation → save**. Field validation always re-runs server-side.

## Architecture map

| Concern | Lives in | Notes |
|---|---|---|
| Page markup | `public/*.html` | Footer still duplicated per page (drift risk) |
| Site nav | `partials/nav.html` → `scripts/build.js` | **Single source.** Edit the partial, run `npm run build` to sync all `public/*.html` between `<!-- nav:start/end -->` markers, with per-page active state. Locked by `test/nav-consistency.test.js` |
| Shared styles | `public/shared-site.css` | Loaded after per-page inline `<style>`, so it wins |
| Pricing & eligibility | `public/last-expense-underwriters.js` | UMD, loaded by browser + server. Pure, exported, **tested** |
| Field validation | `server/validators.js` | Deep module: `validate<Form>(payload[, now]) → string[]` for all 5 forms. Pure, exported, **tested**. Optional injected clock keeps age checks deterministic |
| Request guard | `server/request-guard.js` | One seam for honeypot → rate-limit → CSRF. Checks injected, so **tested** with fakes. `guard(req, body, opts) → { ok, ip } | { ok:false, status, body }` |
| Persistence | `server/store.js` | The store port: `insert / select / upload`. Two adapters — `createSupabaseStore` (prod) and `createMemoryStore` (offline tests). **tested** |
| HTTP routing + flow | `server/server.js` | Serves `public/`, runs request flows, builds records. Talks to the store port only. Imports validators (`V`), the guard, the store. ~1,035 lines (was 1,608) |
| Storage | Supabase | `groups`, `last_expense_applications`, `*_quotes`, buckets |

## Known architectural debt (candidates for the architecture skill)

1. **Duplicated chrome across 23 pages** — _nav resolved:_ single-sourced in
   `partials/nav.html`, synced by `build.js` (`npm run build`), guarded by a test.
   _Remaining:_ footers still vary 9 ways and are copy-pasted per page; single-
   sourcing them needs a content reconciliation first, then the same build step.
2. **`local-server.js` was a 1,608-line monolith** — routing + validators +
   request guard + Supabase + storage. _Resolved:_ field validators →
   `validators.js`; honeypot/rate-limit/CSRF → `request-guard.js`; all persistence
   → the `store.js` port (Supabase + in-memory adapters). File now **1,035 lines**.
   _Optional follow-up:_ extract the per-form request flows (validate → price →
   persist) into functions that take the store, so they can be integration-tested
   end-to-end against `createMemoryStore()` with no network.
3. **Per-page inline `<style>` blocks** — large duplication; shared-site.css only
   partially consolidates.
4. **No build step / no asset pipeline** — large unoptimised hero images (~13 MB),
   no minification, no cache hashing.

## Testing

- `npm test` runs Node's built-in test runner (`node --test`), no dependencies.
- `test/last-expense-underwriters.test.js` — pricing, tiers, eligibility,
  availability for all three underwriters.
- `test/validators.test.js` — every form validator through its interface, with a
  pinned clock for deterministic age-band checks.
- `test/request-guard.test.js` — honeypot/rate-limit/CSRF order and short-circuits,
  with injected fake checks.
- `test/store.test.js` — the in-memory store adapter (insert/select/upload) and the
  port contract shared by both adapters.
- `test/nav-consistency.test.js` — guards the nav arrangement against drift.
- **37 tests total, all green** (`npm test`).
- Next high-value target: extract per-form request flows so they run against
  `createMemoryStore()` for true offline integration tests.
