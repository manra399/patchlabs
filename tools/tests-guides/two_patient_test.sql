-- Two-patient RLS test for a Supabase-style schema (PatchLabs guide: supabase-mcp-patient-data).
-- Runs on plain Postgres: it creates stand-ins for Supabase's auth.uid() and roles.
-- Usage: psql -v ON_ERROR_STOP=1 -f two_patient_test.sql   (in a throwaway database)
create schema if not exists auth;
do $$ begin
  if not exists (select 1 from pg_roles where rolname='anon') then create role anon nologin; end if;
  if not exists (select 1 from pg_roles where rolname='authenticated') then create role authenticated nologin; end if;
end $$;
create or replace function auth.uid() returns uuid language sql stable as
$$ select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $$;
grant usage on schema auth to anon, authenticated;

drop table if exists public.consultations;
create table public.consultations (
  id bigint generated always as identity primary key,
  patient_id uuid not null,
  note text not null
);
alter table public.consultations enable row level security;
grant select, insert, update, delete on public.consultations to anon, authenticated;
insert into public.consultations (patient_id, note) values
  ('00000000-0000-0000-0000-00000000000a', 'Patient A: asthma review'),
  ('00000000-0000-0000-0000-00000000000b', 'Patient B: medication change');

-- The policy an AI builder often writes first: "logged-in users can read".
create policy "logged in can read" on public.consultations for select to authenticated using (true);

\echo '--- WRONG policy (using true for authenticated) ---'
set role anon;
select 'anon sees' as who, count(*) from public.consultations;
reset role;
set role authenticated; set request.jwt.claim.sub = '00000000-0000-0000-0000-00000000000a';
select 'patient A sees' as who, count(*) from public.consultations;
select 'patient A sees B rows' as who, count(*) from public.consultations where patient_id = '00000000-0000-0000-0000-00000000000b';
reset role; reset request.jwt.claim.sub;

-- The fix: each patient reads only their own rows.
drop policy "logged in can read" on public.consultations;
create policy "patients read own" on public.consultations for select to authenticated
  using (patient_id = (select auth.uid()));

\echo '--- FIXED policy (patient_id = auth.uid()) ---'
set role anon;
select 'anon sees' as who, count(*) from public.consultations;
reset role;
set role authenticated; set request.jwt.claim.sub = '00000000-0000-0000-0000-00000000000a';
select 'patient A sees' as who, count(*) from public.consultations;
select 'patient A sees B rows' as who, count(*) from public.consultations where patient_id = '00000000-0000-0000-0000-00000000000b';
reset role; reset request.jwt.claim.sub;
