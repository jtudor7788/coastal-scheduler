alter table coastal.cleans drop constraint if exists cleans_status_check;
alter table coastal.cleans add constraint cleans_status_check
  check (status in ('requested','declined','open','assigned','confirmed','done','cancelled'));
alter table coastal.cleans
  add column if not exists contact_name text,
  add column if not exists contact_phone text,
  add column if not exists contact_email text,
  add column if not exists source text not null default 'admin';
create index if not exists cleans_status_idx on coastal.cleans(status);
