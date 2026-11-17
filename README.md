# Coastal Cleaning Scheduler

Cleaners post the days they can work; Nicole posts cleans and assigns them.

- `docs/` web UI (static), served by GitHub Pages
- `supabase/functions/coastal-api/` API (Supabase Edge Function, verify_jwt = false, does its own auth)
- `supabase/migrations/` Postgres schema (private `coastal` schema, RLS on, no REST access)
- `local-server/` original Node + SQLite version for local testing

## Required Edge Function secrets
`COASTAL_ADMIN_PASSWORD` (Nicole's login) and `COASTAL_SESSION_SECRET` (random 64-char string, signs login tokens).
Set in Supabase dashboard > Edge Functions > Secrets. The function refuses to run without them.

## Deploy
1. Apply the migration. 2. Deploy `coastal-api` with JWT verification off. 3. Push to `main`; the Pages workflow publishes `docs/`.
