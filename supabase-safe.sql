-- Secure Supabase schema for Fraud Report Center.
-- IMPORTANT: Run this entire script in Supabase SQL Editor.
-- Create the admin user through Supabase Authentication, then insert its UUID
-- into admin_users. Never put an admin password in GitHub.

create extension if not exists pgcrypto;

create table if not exists public.admin_users (
  user_id uuid primary key references auth.users(id) on delete cascade
);

create table if not exists public.reports (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  reference_number text unique not null,
  name text not null,
  phone text not null,
  email text not null,
  scam_type text not null,
  scammer_name text,
  scammer_phone text,
  scammer_email text,
  website text,
  amount numeric,
  currency text,
  incident_date date,
  description text not null,
  evidence_path text,
  status text not null default 'Submitted',
  admin_response text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.messages (
  id uuid primary key default gen_random_uuid(),
  report_id uuid not null references public.reports(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  sender_type text not null check (sender_type in ('user','admin')),
  message text not null,
  created_at timestamptz not null default now()
);

alter table public.admin_users enable row level security;
alter table public.reports enable row level security;
alter table public.messages enable row level security;

-- No direct client SELECT/UPDATE/DELETE policies for reports/messages.
-- Security-sensitive operations happen through SECURITY DEFINER RPCs below.

create or replace function public.is_admin_secure()
returns boolean language sql stable security definer set search_path=public
as $$ select exists(select 1 from public.admin_users where user_id=auth.uid()); $$;

revoke all on function public.is_admin_secure() from public;
grant execute on function public.is_admin_secure() to anon, authenticated;

create or replace function public.create_report_secure(
 p_name text,p_phone text,p_email text,p_scam_type text,p_scammer_name text,
 p_scammer_phone text,p_scammer_email text,p_website text,p_amount numeric,
 p_currency text,p_incident_date date,p_description text
) returns text language plpgsql security definer set search_path=public
as $$
declare r text;
begin
 if auth.uid() is null then raise exception 'Authentication required'; end if;
 if lower(coalesce(p_email,'')) <> lower(coalesce((select email from auth.users where id=auth.uid()),'')) then
   raise exception 'Email must match the authenticated account';
 end if;
 r := 'FR-' || extract(year from now())::int || '-' || lpad((floor(random()*1000000))::int::text,6,'0');
 insert into public.reports(user_id,reference_number,name,phone,email,scam_type,scammer_name,scammer_phone,scammer_email,website,amount,currency,incident_date,description)
 values(auth.uid(),r,p_name,p_phone,(select email from auth.users where id=auth.uid()),p_scam_type,p_scammer_name,p_scammer_phone,p_scammer_email,p_website,p_amount,p_currency,p_incident_date,p_description);
 return r;
end $$;
grant execute on function public.create_report_secure(text,text,text,text,text,text,text,text,numeric,text,date,text) to authenticated;

create or replace function public.get_my_report_secure(p_reference text)
returns table(reference_number text,status text,scam_type text,created_at timestamptz,updated_at timestamptz,admin_response text)
language sql stable security definer set search_path=public
as $$ select r.reference_number,r.status,r.scam_type,r.created_at,r.updated_at,r.admin_response
from public.reports r where r.reference_number=p_reference and r.user_id=auth.uid(); $$;
grant execute on function public.get_my_report_secure(text) to authenticated;

create or replace function public.get_my_messages_secure(p_reference text)
returns table(sender_type text,message text,created_at timestamptz)
language sql stable security definer set search_path=public
as $$ select m.sender_type,m.message,m.created_at from public.messages m
join public.reports r on r.id=m.report_id
where r.reference_number=p_reference and r.user_id=auth.uid() order by m.created_at; $$;
grant execute on function public.get_my_messages_secure(text) to authenticated;

create or replace function public.send_my_message_secure(p_reference text,p_message text)
returns void language plpgsql security definer set search_path=public
as $$
declare rid uuid;
begin
 select id into rid from public.reports where reference_number=p_reference and user_id=auth.uid();
 if rid is null then raise exception 'Report not found'; end if;
 if length(trim(p_message))=0 or length(p_message)>5000 then raise exception 'Invalid message'; end if;
 insert into public.messages(report_id,user_id,sender_type,message) values(rid,auth.uid(),'user',trim(p_message));
end $$;
grant execute on function public.send_my_message_secure(text,text) to authenticated;

create or replace function public.admin_list_reports_secure()
returns table(id uuid,reference_number text,name text,phone text,email text,scam_type text,description text,status text,admin_response text,created_at timestamptz,updated_at timestamptz)
language sql stable security definer set search_path=public
as $$ select r.id,r.reference_number,r.name,r.phone,r.email,r.scam_type,r.description,r.status,r.admin_response,r.created_at,r.updated_at
from public.reports r where public.is_admin_secure() order by r.created_at desc; $$;
grant execute on function public.admin_list_reports_secure() to authenticated;

create or replace function public.admin_update_report_secure(p_id uuid,p_status text)
returns void language plpgsql security definer set search_path=public
as $$
begin
 if not public.is_admin_secure() then raise exception 'Unauthorized'; end if;
 if p_status not in ('Under Review','More Information Needed','Confirmed Scam','Not Confirmed','Resolved','Closed') then raise exception 'Invalid status'; end if;
 update public.reports set status=p_status,updated_at=now() where id=p_id;
end $$;
grant execute on function public.admin_update_report_secure(uuid,text) to authenticated;

create or replace function public.admin_update_response_secure(p_id uuid,p_response text)
returns void language plpgsql security definer set search_path=public
as $$
begin
 if not public.is_admin_secure() then raise exception 'Unauthorized'; end if;
 update public.reports set admin_response=p_response,updated_at=now() where id=p_id;
end $$;
grant execute on function public.admin_update_response_secure(uuid,text) to authenticated;

create or replace function public.admin_get_messages_secure(p_reference text)
returns table(sender_type text,message text,created_at timestamptz)
language sql stable security definer set search_path=public
as $$ select m.sender_type,m.message,m.created_at from public.messages m
join public.reports r on r.id=m.report_id
where public.is_admin_secure() and r.reference_number=p_reference order by m.created_at; $$;
grant execute on function public.admin_get_messages_secure(text) to authenticated;

create or replace function public.admin_send_message_secure(p_reference text,p_message text)
returns void language plpgsql security definer set search_path=public
as $$
declare rid uuid; uid uuid;
begin
 if not public.is_admin_secure() then raise exception 'Unauthorized'; end if;
 select id,user_id into rid,uid from public.reports where reference_number=p_reference;
 if rid is null then raise exception 'Report not found'; end if;
 if length(trim(p_message))=0 or length(p_message)>5000 then raise exception 'Invalid message'; end if;
 insert into public.messages(report_id,user_id,sender_type,message) values(rid,uid,'admin',trim(p_message));
end $$;
grant execute on function public.admin_send_message_secure(text,text) to authenticated;

-- Lock down direct table access from the browser.
revoke all on public.reports from anon, authenticated;
revoke all on public.messages from anon, authenticated;
revoke all on public.admin_users from anon, authenticated;

-- Optional private evidence storage:
-- Create a PRIVATE Storage bucket named "evidence".
-- Do not create a public-read policy.
-- For production evidence downloads, add a server-side function that checks
-- auth.uid() against reports.user_id before issuing a short-lived signed URL.
