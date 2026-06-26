-- ============================================================================
-- DoveNest admin auth: switch from TOTP MFA (aal2) to passwordless email OTP.
--
-- Background: the admin pages used to gate on Supabase MFA assurance level
-- (`aal2`). Email OTP issues an `aal1` session, so the gate is now an
-- ALLOWLIST check: the signed-in email must exist in `admin_invites`.
--
-- Run this in the Supabase SQL editor. It is idempotent (safe to re-run).
-- ============================================================================

-- 1. The login/page guards read `admin_invites` to confirm the caller is an
--    admin. That SELECT must succeed for an aal1 (email-OTP) session. If your
--    existing policy required aal2, replace it with this one.
alter table public.admin_invites enable row level security;

drop policy if exists "authenticated can read invites" on public.admin_invites;
create policy "authenticated can read invites"
  on public.admin_invites
  for select
  to authenticated
  using (true);  -- emails only; the gate just needs presence lookups

-- 2. Reusable helper: is the current session an allowlisted admin?
--    Use this inside other tables' RLS so data is protected at the DB layer,
--    not just by the JavaScript guard (which a determined user can bypass).
create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.admin_invites
    where lower(email) = lower(auth.jwt() ->> 'email')
  );
$$;

-- 3. EXAMPLE — apply is_admin() to a data table the admin panel reads.
--    Repeat for every admin-read table: motor_quotes, travel_quotes,
--    flying_doctor_quotes, last_expense_applications (+ dependents/documents),
--    contact_inquiries, reviews, groups, group_contacts.
--
--    NOTE: the public submission forms (motor-quote, contact, review, etc.)
--    INSERT through the service key on the server, which bypasses RLS — so
--    locking SELECT to admins here will NOT break public form submissions.
--
-- alter table public.motor_quotes enable row level security;
-- drop policy if exists "admins read motor_quotes" on public.motor_quotes;
-- create policy "admins read motor_quotes"
--   on public.motor_quotes for select to authenticated
--   using (public.is_admin());

-- ============================================================================
-- WHAT TO CHECK MANUALLY (cannot be seen from the codebase):
--   • Supabase Auth → Providers → Email: "Enable Email OTP" must be ON.
--   • Auth → Email Templates → "Magic Link" AND "Confirm signup": both must
--     contain the {{ .Token }} variable (the 6-digit code).
--   • If ANY existing RLS policy references the aal claim
--     (auth.jwt() ->> 'aal' = 'aal2'), relax it — aal1 sessions will be
--     denied otherwise and admin pages will load empty.
-- ============================================================================
