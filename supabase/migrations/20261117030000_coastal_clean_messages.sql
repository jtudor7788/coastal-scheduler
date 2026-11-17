create table if not exists coastal.clean_messages (
  id bigint generated always as identity primary key,
  clean_id bigint not null references coastal.cleans(id) on delete cascade,
  thread text not null check (thread in ('crew','client')),
  sender text not null check (sender in ('admin','cleaner','client')),
  body text not null check (char_length(body) between 1 and 2000),
  fee_cents integer check (fee_cents > 0 and fee_cents <= 1000000),
  fee_status text check (fee_status in ('pending','approved','declined')),
  seen boolean not null default false,
  created_at timestamptz not null default now(),
  check (fee_cents is null or thread = 'client')
);
create index if not exists clean_messages_thread_idx on coastal.clean_messages(clean_id, thread, id);
alter table coastal.clean_messages enable row level security;
revoke all on coastal.clean_messages from anon, authenticated;
