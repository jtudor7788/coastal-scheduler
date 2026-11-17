-- Coastal Cleaning scheduler. Private schema: not exposed through the REST API.
-- Only the coastal-api edge function (direct DB connection) reads/writes these.
create schema if not exists coastal;
revoke all on schema coastal from anon, authenticated;

create table if not exists coastal.cleaners (
  id bigint generated always as identity primary key,
  name text not null,
  phone text,
  pin text not null,
  active boolean not null default true
);
create table if not exists coastal.availability (
  id bigint generated always as identity primary key,
  cleaner_id bigint not null references coastal.cleaners(id) on delete cascade,
  date date not null,
  start_time time not null default '08:00',
  end_time time not null default '17:00',
  note text,
  unique (cleaner_id, date)
);
create table if not exists coastal.cleans (
  id bigint generated always as identity primary key,
  date date not null,
  start_time time not null default '10:00',
  duration_hours numeric not null default 2 check (duration_hours > 0 and duration_hours <= 16),
  client text not null,
  address text default '',
  type text not null default 'Airbnb turnover',
  notes text default '',
  status text not null default 'open' check (status in ('open','assigned','confirmed','done','cancelled')),
  cleaner_id bigint references coastal.cleaners(id) on delete set null,
  created_at timestamptz not null default now()
);
create index if not exists cleans_date_idx on coastal.cleans(date);
create index if not exists availability_date_idx on coastal.availability(date);

alter table coastal.cleaners enable row level security;
alter table coastal.availability enable row level security;
alter table coastal.cleans enable row level security;
revoke all on all tables in schema coastal from anon, authenticated;
