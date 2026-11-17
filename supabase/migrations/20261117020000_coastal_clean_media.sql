create table if not exists coastal.clean_media (
  id bigint generated always as identity primary key,
  clean_id bigint not null references coastal.cleans(id) on delete cascade,
  kind text not null check (kind in ('before','after','other')),
  path text not null unique,
  content_type text not null,
  size_bytes bigint,
  caption text,
  uploaded_by bigint references coastal.cleaners(id) on delete set null,
  created_at timestamptz not null default now()
);
create index if not exists clean_media_clean_idx on coastal.clean_media(clean_id);
alter table coastal.clean_media enable row level security;
revoke all on coastal.clean_media from anon, authenticated;

alter table coastal.cleans
  add column if not exists report_token text not null default (replace(gen_random_uuid()::text,'-','') || replace(gen_random_uuid()::text,'-','')),
  add column if not exists report_published boolean not null default false,
  add column if not exists report_note text;
create unique index if not exists cleans_report_token_idx on coastal.cleans(report_token);

-- Private bucket: no storage policies, so only the edge function (service role) can read/write.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('clean-media', 'clean-media', false, 52428800,
  array['image/jpeg','image/png','image/webp','image/heic','image/heif','video/mp4','video/quicktime','video/webm'])
on conflict (id) do update set public = false, file_size_limit = excluded.file_size_limit, allowed_mime_types = excluded.allowed_mime_types;
