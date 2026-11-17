create table if not exists coastal.availability_templates (
  cleaner_id bigint primary key references coastal.cleaners(id) on delete cascade,
  weekdays int[] not null default '{}',
  start_time time not null default '08:00',
  end_time time not null default '17:00',
  filled_through date
);
alter table coastal.availability_templates enable row level security;
revoke all on coastal.availability_templates from anon, authenticated;
create index if not exists cleans_date_idx on coastal.cleans(date);
create index if not exists cleans_client_idx on coastal.cleans(lower(client));
