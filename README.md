# Fraud Report Center — Secure GitHub Pages Version

## What changed

This version is designed so a complainant cannot simply change a report number in browser code and read somebody else's report.

- Each complainant signs in with Supabase Auth.
- Each report stores the authenticated user's `auth.uid()`.
- Direct SELECT/UPDATE/DELETE access to reports/messages is revoked.
- Secure database functions check `auth.uid()` before returning a report or messages.
- Admin operations require membership in `admin_users`.
- Admin passwords are never stored in this repository.
- Evidence storage is intended to be private.

## Setup

1. Create a Supabase project.
2. Run `supabase-safe.sql` in SQL Editor.
3. Create the private Storage bucket `evidence`.
4. Create your administrator in Supabase Authentication.
5. Copy the administrator's user UUID and insert it:
   `insert into public.admin_users(user_id) values ('YOUR-ADMIN-UUID');`
6. In `app.js`, replace `YOUR_SUPABASE_URL` and `YOUR_SUPABASE_ANON_KEY`.
7. Upload the project files to GitHub.
8. Enable GitHub Pages.

## Admin credentials

Use Supabase Authentication to set the admin email/password. Do not put the password in GitHub or JavaScript.

## User privacy

The user lookup RPC ignores a supplied email and uses the authenticated account identity. A user receives only the report belonging to their `auth.uid()`.

For an actual public deployment, also configure Supabase Auth email templates/redirect URLs and consider adding CAPTCHA/rate limiting and a server-side evidence-download function.
