-- ============================================================================
-- DoveNest — Row-Level Security: admins read everything, the public reads nothing
-- ============================================================================
-- Run this in the Supabase dashboard → SQL Editor → New query → Run.
--
-- HOW IT WORKS
--   • The Node server writes data with the SERVICE key, which BYPASSES RLS.
--     So enabling RLS here does NOT break form submissions.
--   • The admin pages read with the ANON key + the logged-in admin's session.
--     Those reads ARE governed by RLS — these policies grant access only to
--     users listed in the `admins` allowlist.
--   • Anyone with the public anon key but no admin session gets nothing.
-- ============================================================================

-- 1) Admin allowlist ---------------------------------------------------------
create table if not exists public.admins (
  user_id  uuid primary key references auth.users(id) on delete cascade,
  email    text,
  added_at timestamptz not null default now()
);
alter table public.admins enable row level security;

-- is the current request an allow-listed admin?
-- SECURITY DEFINER so it can read `admins` without tripping RLS recursion.
create or replace function public.is_admin()
  returns boolean
  language sql
  security definer
  stable
as $$ select exists (select 1 from public.admins where user_id = auth.uid()) $$;

-- admins can see the allowlist (so the dashboard can manage it); nobody else can
drop policy if exists "admins read admins" on public.admins;
create policy "admins read admins" on public.admins
  for select to authenticated using (public.is_admin());

-- 2) Lock every data table: full access for admins, nothing for anyone else ---
do $$
declare t text;
begin
  foreach t in array array[
    'groups',
    'group_contacts',
    'last_expense_applications',
    'last_expense_dependents',
    'last_expense_documents',
    'motor_quotes',
    'travel_quotes',
    'travel_quote_travellers',
    'flying_doctor_quotes',
    'flying_doctor_members',
    'contact_inquiries'
  ]
  loop
    execute format('alter table public.%I enable row level security;', t);
    execute format('drop policy if exists "admins full access" on public.%I;', t);
    execute format($f$
      create policy "admins full access" on public.%I
        for all to authenticated
        using (public.is_admin())
        with check (public.is_admin());
    $f$, t);
  end loop;
end $$;

-- 3) Storage: admins can read the document buckets; nobody else can -----------
-- (Also flip each bucket to PRIVATE in Storage → bucket → Settings.)
drop policy if exists "admins read docs" on storage.objects;
create policy "admins read docs" on storage.objects
  for select to authenticated
  using (
    bucket_id in ('last-expense-docs', 'flying-doctor-docs', 'travel-quote-docs')
    and public.is_admin()
  );

-- 4) Add your admin user(s) to the allowlist ---------------------------------
-- Replace the email with each real admin (they must already exist in Auth).
insert into public.admins (user_id, email)
select id, email from auth.users
where email in ('admin@dovenest.com')   -- <-- EDIT THIS
on conflict (user_id) do nothing;

-- ============================================================================
-- VERIFY (run these after the above)
-- ============================================================================
-- Every table should show rowsecurity = true:
--   select tablename, rowsecurity from pg_tables
--   where schemaname='public' order by tablename;
--
-- Policies should be listed for each table:
--   select tablename, policyname, roles, cmd from pg_policies
--   where schemaname='public' order by tablename;
--
-- Confirm your admin is enrolled:
--   select * from public.admins;
-- ============================================================================
