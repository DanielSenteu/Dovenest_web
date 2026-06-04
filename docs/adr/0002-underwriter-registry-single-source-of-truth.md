# 2. The underwriter registry is the single source of truth

Date: 2026-06-02

## Status

Accepted

## Context

Last Expense pricing, benefit tiers, age bands, eligibility and availability must
agree between the browser (live quote ticker) and the server (authoritative
re-check). Earlier, rules were duplicated: the server's group-registration
handler hard-coded an allow-list `['absa','capex']` that silently excluded
Liberty Life from group cover, even though the underwriter data said it was
available — a real bug that reached users.

## Decision

`last-expense-underwriters.js` is the single source of truth for all underwriter
facts (ids, labels, `availableFor`, `benefitTiers`, `coverTypes`, ages, limits,
pricing). Both client and server import this UMD module. Server-side checks must
be **derived from the registry**, never from parallel hard-coded lists. The
display label for the `heritage` underwriter is **"Liberty Life"** (the old
"Liberty | Heritage" / "(Heritage Insurance Company)" branding was removed).

## Consequences

- New underwriter rules are added in one place and apply everywhere.
- Validation reads `LE.get(id).availableFor` etc. rather than literal lists.
- The module is pure and exported, so it is unit-tested in
  `test/last-expense-underwriters.test.js`.
- Server validators that are *not* yet extracted from `local-server.js` remain
  harder to test in isolation — see `CONTEXT.md` debt #2.
