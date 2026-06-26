# DoveNest Reviews Platform — Build Spec

**Status:** Approved plan, pre-build · **Drafted:** 2026-06-17 · **Phase-1 go-live target:** ~24 June 2026 · **Endorsement target:** 100 verified by 30 June 2026

Replaces the about-page review popup with a public, moderated, SEO-indexed reviews platform that can be shared as a link via SMS / WhatsApp / email campaigns.

---

## 1. Decisions (locked)

| Topic | Decision |
|-------|----------|
| Link model | **One open public link** for everyone (no per-recipient tokens). Optional `?via=sms\|whatsapp\|email\|qr` query param for cheap channel attribution. |
| Verification | `verified=false` on submit; **staff tick "verified"** during moderation by matching to client records. |
| Product field | **Dropdown**, includes an **"Other / General"** option for people who just want to leave a general review. New column on the table. |
| Phase-1 scope | **Full platform**: submission page + public wall + individual permalinks + Review/AggregateRating schema. |
| Photo upload | **Optional at launch** (Supabase Storage). |
| Google Reviews | **Native only for now**; revisit Google Places badge/CTA later. |

---

## 2. What exists today (baseline)

- Popup modal on `public/about.html` ("Share Your Experience") → **direct Supabase insert from the browser** using the exposed anon key. No server in the loop.
- `reviews` table columns: `id, first_name, last_name, type, email, phone, rating, company_name, position, submitted_at`. **No review text, consent, photo, product, location, or status.**
- Public display = **hardcoded static carousel** in `about.html` (lines ~1583–1650). Submitted reviews never appear on the site.
- Admin `reviews.html` / `review.html` = **read-only**, no approve/reject.
- Security = client-side honeypot + JS validation only.

**Carryover risk:** the anon insert key is in page source. Once a public link is blasted to thousands, that endpoint is open to spam/bots. Submission MUST move server-side with moderation before go-live.

---

## 3. Target pages

| Page | URL | File | Purpose |
|------|-----|------|---------|
| Submission | `/review` | `public/review.html` | The campaign link. Mobile-first, <2 min, single job: collect one review. |
| Public wall | `/reviews` | `public/reviews.html` | Dynamic, growing social-proof page. Replaces the static carousel. Filter by product / client type; shows average rating + count. The credibility asset for donors, regulators, underwriters, procurement. |
| Permalink | `/reviews/<slug>` | served from `reviews.html?id=` or rewrite | Each **approved** review gets a unique, indexable URL with Review JSON-LD → Google star rich-snippets + shareable single endorsement. |

The about-page carousel stays but pulls **featured/approved** reviews instead of hardcoded cards.

---

## 4. Data model — `reviews` table changes

Keep existing columns. Add:

| Column | Type | Notes |
|--------|------|-------|
| `review_text` | text, **required** | The written testimonial (the gap). |
| `headline` | text, nullable | Short title; auto-derive from text if blank. |
| `product` | text, **required** | Dropdown value incl. `Other / General`. |
| `organisation` | text, nullable | For **everyone**, not just business type. |
| `county` | text, nullable | County/region. |
| `country` | text, nullable | Default Kenya; diaspora can change. |
| `photo_url` | text, nullable | Optional; Supabase Storage public URL. |
| `consent_to_publish` | boolean, **required true** | No publish without it. |
| `status` | text | `pending` (default) \| `approved` \| `rejected` \| `featured`. |
| `slug` | text, unique nullable | Generated on approval: `firstname-lastname-product-shortid`. |
| `verified` | boolean default false | Staff-confirmed real client. |
| `source` | text | `web` (default) \| `sms` \| `whatsapp` \| `email` \| `qr` from `?via=`. |
| `reviewed_by` | text, nullable | Admin email who actioned it. |
| `reviewed_at` | timestamptz, nullable | |
| `published_at` | timestamptz, nullable | Set on approve. |

**Product dropdown options:** Motor, Health / Medical, Life Assurance, Domestic / Home, Business / Commercial, Pensions & Retirement, Education Policy, Diaspora, Last Expense, **Other / General**.

---

## 5. Security (matches the project's documented 3-layer standard)

New endpoint **`POST /api/review`** in `server/server.js`, check order:
1. **Honeypot** — hidden `website`/`rvHp` field; if filled, return fake `{success:true}` 200, save nothing.
2. **Rate limit** — in-memory Map, max 5/IP/hour, 429 over limit (reuse `request-guard.js`).
3. **CSRF** — fetch `/api/csrf-token` on page load, send with POST; validate signature + 30-min TTL.
4. **Server validation** — `server/validators.js`: required fields, lengths, email/phone format, rating 1–5, consent must be true, product in allow-list.
5. **Insert** — via **service key**, force `status='pending'`, `verified=false`, ignore any client-supplied status/verified/slug.

**Supabase RLS:**
- anon role: `SELECT` only where `status IN ('approved','featured')`. **No anon insert.** (Closes the current open-key hole.)
- service role (server): full access.

**Photo upload:** server validates MIME (jpeg/png/webp) + size (≤ ~3 MB), re-keys filename, stores in Supabase Storage bucket `review-photos`; only the resulting URL goes in the row. No client-direct storage writes.

---

## 6. Moderation (admin)

Upgrade `public/admin/reviews.html` + `review.html`:
- Default queue = **Pending** filter; tabs for Pending / Approved / Rejected / Featured.
- Detail view shows full review text, photo, product, contact, source.
- Actions: **Approve**, **Reject**, **Feature**, **Mark verified**.
  - Approve → set `status`, `published_at`, `reviewed_by/at`, **generate `slug`**. Review appears on `/reviews` within seconds.
  - Feature → also surfaced in about-page carousel + homepage.
- Nothing is public until a human approves. This is the spam firewall for the blasted link.

---

## 7. Public display & SEO

- `/reviews`: dynamic grid/list of approved reviews, product + client-type filters, header shows **average rating + total count**.
- **JSON-LD**: `AggregateRating` on `/reviews`; `Review` on each permalink → star rich-snippets.
- Each permalink = unique keyword-rich URL (name + product + county) → long-tail SEO; fresh monthly content = recurring crawl signal.
- Add `/reviews` and permalinks to `sitemap.xml`.

---

## 8. Build task breakdown

1. **DB migration** — add columns above; write `scripts/` SQL or run in Supabase; set RLS policies; create `review-photos` storage bucket.
2. **Server** — `POST /api/review` (honeypot→rate-limit→CSRF→validate→insert), photo-upload handler, CSRF route reuse; `GET` helpers if wall reads via server (or keep wall reading approved rows via anon SELECT under RLS).
3. **Submission page** `review.html` — mobile-first form: name, optional organisation, county/country, **product dropdown**, star rating, **written review (required)**, **optional photo**, email/phone (for staff verification), **consent checkbox**, honeypot, CSRF. Reads `?via=` for source. <2 min.
4. **Public wall** `reviews.html` — dynamic approved reviews, filters, aggregate rating, AggregateRating JSON-LD.
5. **Permalinks** — per-review page/route + Review JSON-LD + share buttons.
6. **Moderation** — approve/reject/feature/verify in admin, slug generation.
7. **About-page carousel** — repoint to featured reviews; retire the hardcoded cards and the old popup → "Share Your Experience" now links to `/review`.
8. **SEO** — sitemap entries, meta/OG tags on wall + permalinks.

---

## 9. Timeline to 30 June (13 days — tight)

| Dates | Milestone |
|-------|-----------|
| Jun 18–20 | DB migration + RLS + storage; `/api/review` with full security |
| Jun 20–22 | Submission page `/review`; photo upload |
| Jun 22–23 | Moderation (approve/reject/feature/verify) + public wall `/reviews` |
| Jun 23–24 | Permalinks + Review/AggregateRating schema + sitemap; retire popup |
| **Jun 24** | **GO-LIVE** → launch SMS / WhatsApp / email campaigns (with `?via=` links) |
| Jun 24–30 | Reviews flow in, daily moderation + verification, push to 100 |

**Reality check:** 100 verified in 13 days needs the platform live by ~24 June so campaigns get a full week. The campaign window is the binding constraint, not the build.
