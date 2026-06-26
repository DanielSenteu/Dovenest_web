-- ============================================================================
-- DoveNest — Reviews Platform migration
-- ============================================================================
-- Run in the Supabase dashboard → SQL Editor → New query → Run.
-- Idempotent: safe to run more than once.
--
-- WHAT THIS DOES
--   1) Extends the existing `reviews` table with the new platform columns
--      (written testimonial, product, location, photo, consent, moderation
--      status, slug, verification, source, audit fields).
--   2) Locks the table with RLS:
--        • the PUBLIC (anon) can read ONLY approved/featured rows that have
--          consent — this is what the public reviews wall renders;
--        • admins (is_admin allowlist) get full access for moderation;
--        • NOBODY can insert as anon — the Node server writes with the SERVICE
--          key, which bypasses RLS. This closes the current hole where the
--          browser popup inserts directly with the anon key.
--   3) Creates a PUBLIC `review-photos` storage bucket (photos are shown on the
--      public wall). The server uploads with the service key; reads are public.
--
-- ⚠ AFTER running this, the OLD about-page popup (direct anon insert) will stop
--   working — that is intended. Ship the new POST /api/review endpoint and
--   retire the popup in the same release.
-- ============================================================================

-- 1) Columns -----------------------------------------------------------------
-- (ADD COLUMN IF NOT EXISTS backfills existing rows with the DEFAULT.)
alter table public.reviews add column if not exists review_text        text;
alter table public.reviews add column if not exists headline           text;
alter table public.reviews add column if not exists product            text;
alter table public.reviews add column if not exists organisation       text;
alter table public.reviews add column if not exists county             text;
alter table public.reviews add column if not exists country            text    default 'Kenya';
alter table public.reviews add column if not exists photo_url          text;
alter table public.reviews add column if not exists consent_to_publish boolean default false;
alter table public.reviews add column if not exists status             text    default 'pending';
alter table public.reviews add column if not exists slug               text;
alter table public.reviews add column if not exists verified           boolean default false;
alter table public.reviews add column if not exists source             text    default 'web';
alter table public.reviews add column if not exists reviewed_by        text;
alter table public.reviews add column if not exists reviewed_at        timestamptz;
alter table public.reviews add column if not exists published_at       timestamptz;

-- Constrain status to the known moderation states.
alter table public.reviews drop constraint if exists reviews_status_check;
alter table public.reviews add  constraint reviews_status_check
  check (status in ('pending', 'approved', 'rejected', 'featured'));

-- Slugs are unique, but only once assigned (pending rows have a NULL slug).
create unique index if not exists reviews_slug_uniq
  on public.reviews (slug) where slug is not null;

-- The public wall filters on status; index it.
create index if not exists reviews_status_idx on public.reviews (status);

-- 2) Row-Level Security ------------------------------------------------------
alter table public.reviews enable row level security;

-- Public reads ONLY published reviews that carry consent.
drop policy if exists "public read approved reviews" on public.reviews;
create policy "public read approved reviews" on public.reviews
  for select to anon
  using (status in ('approved', 'featured') and consent_to_publish = true);

-- Admins (is_admin allowlist) get full access for moderation.
-- Relies on public.is_admin() created in scripts/rls-policies.sql.
drop policy if exists "admins full access reviews" on public.reviews;
create policy "admins full access reviews" on public.reviews
  for all to authenticated
  using (public.is_admin())
  with check (public.is_admin());

-- 3) Storage: public bucket for optional profile photos ----------------------
insert into storage.buckets (id, name, public)
values ('review-photos', 'review-photos', true)
on conflict (id) do nothing;

-- ============================================================================
-- VERIFY (run after the above)
-- ============================================================================
--   select column_name, data_type, column_default
--   from information_schema.columns
--   where table_schema='public' and table_name='reviews' order by ordinal_position;
--
--   select tablename, rowsecurity from pg_tables
--   where schemaname='public' and tablename='reviews';
--
--   select policyname, roles, cmd from pg_policies
--   where schemaname='public' and tablename='reviews';
--
--   select id, public from storage.buckets where id='review-photos';
-- ============================================================================
