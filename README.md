# Fraud Report Center — Secure GitHub Pages Version

## What changed

This version has a substantially richer public-facing landing page while preserving the supplied secure Supabase architecture.

### Frontend improvements
- Polished responsive hero and navigation
- Scam-category section
- Four-step reporting process
- “If you've been scammed” safety guidance
- Privacy/security explanation
- Expanded FAQ
- Stronger report and tracking calls to action
- Improved report form layout
- Improved private case-tracking presentation
- Mobile-first responsive behavior

### Security model retained
- Each complainant signs in with Supabase Auth.
- Each report is associated with the authenticated user's `auth.uid()`.
- Secure RPC functions check the authenticated identity before returning a user's report/messages.
- Admin operations require membership in `admin_users`.
- Admin passwords are not stored in GitHub or JavaScript.
- Direct browser SELECT/UPDATE/DELETE access to reports/messages is revoked.

## Important production note

The current frontend includes an evidence file selector for the UI, but the supplied `app.js` does not upload that file. The page therefore explicitly warns users not to submit sensitive evidence through that control until private Storage and a server-side/signed-download flow are configured.

## Setup

1. Create a Supabase project.
2. Run `supabase-safe.sql` in the Supabase SQL Editor.
3. Create the private Storage bucket `evidence` if you intend to enable evidence uploads.
4. Create the administrator in Supabase Authentication.
5. Copy the administrator's user UUID and insert it into `admin_users`:
   `insert into public.admin_users(user_id) values ('YOUR-ADMIN-UUID');`
6. In `app.js`, replace `YOUR_SUPABASE_URL` and `YOUR_SUPABASE_ANON_KEY`.
7. Configure Supabase Auth email templates and redirect URLs for your GitHub Pages domain.
8. Upload the project files to GitHub.
9. Enable GitHub Pages.

## Admin credentials

Admin email for the sign-in form: `yomawisdom55@gmail.com`.

Set the corresponding password directly in Supabase Authentication. Do not put the password in GitHub, HTML, JavaScript, or this README.

## Recommended production hardening

- CAPTCHA and rate limiting on report/auth endpoints
- Email verification enforcement
- Server-side evidence upload/download flow using private Storage
- Audit logging for administrator actions
- Stronger content validation and abuse controls
- Custom domain and HTTPS
