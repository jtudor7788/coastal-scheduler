-- Properties, recurring cleans, checklists, clock in/out, release ("can't make it"), supply requests.
create table if not exists coastal.properties (
  id bigint generated always as identity primary key,
  name text not null,
  address text not null default '',
  owner_name text, owner_phone text, owner_email text,
  access_info text not null default '',
  checklist text not null default '',          -- one task per line; empty = use the default list
  default_type text not null default 'Airbnb turnover',
  default_hours numeric(4,1) not null default 2,
  active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists coastal.recurring_rules (
  id bigint generated always as identity primary key,
  property_id bigint references coastal.properties(id) on delete set null,
  client text not null, address text not null default '', type text not null default 'Residential',
  start_time time not null default '10:00', duration_hours numeric(4,1) not null default 2,
  notes text not null default '',
  contact_name text, contact_phone text, contact_email text,
  start_date date not null, every_weeks int not null default 1 check (every_weeks between 1 and 8),
  end_date date, active boolean not null default true,
  created_at timestamptz not null default now()
);

alter table coastal.cleans
  add column if not exists property_id bigint references coastal.properties(id) on delete set null,
  add column if not exists rule_id bigint references coastal.recurring_rules(id) on delete set null,
  add column if not exists clock_in timestamptz,
  add column if not exists clock_out timestamptz,
  add column if not exists release_note text;
create unique index if not exists cleans_rule_date_uq on coastal.cleans(rule_id, date) where rule_id is not null;

create table if not exists coastal.clean_tasks (
  id bigint generated always as identity primary key,
  clean_id bigint not null references coastal.cleans(id) on delete cascade,
  label text not null check (char_length(label) between 1 and 200),
  done boolean not null default false,
  done_at timestamptz,
  sort int not null default 0
);
create index if not exists clean_tasks_clean_idx on coastal.clean_tasks(clean_id);

create table if not exists coastal.supply_requests (
  id bigint generated always as identity primary key,
  clean_id bigint references coastal.cleans(id) on delete set null,
  cleaner_id bigint references coastal.cleaners(id) on delete set null,
  item text not null check (char_length(item) between 1 and 200),
  status text not null default 'open' check (status in ('open','ordered','done')),
  created_at timestamptz not null default now()
);

alter table coastal.properties enable row level security;
alter table coastal.recurring_rules enable row level security;
alter table coastal.clean_tasks enable row level security;
alter table coastal.supply_requests enable row level security;
revoke all on coastal.properties, coastal.recurring_rules, coastal.clean_tasks, coastal.supply_requests from anon, authenticated;
