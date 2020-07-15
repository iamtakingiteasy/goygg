create table users (
  id                         text primary key,
  email                      text not null unique,
  password                   text not null,
  profile_id                 text not null unique,
  profile_name               text not null unique,
  profile_texture_skin_url   text not null default '',
  profile_texture_skin_model text not null default '',
  profile_texture_cape_url   text not null default ''
);

create table tokens (
  user_id   text primary key,
  client    text not null unique,
  access    text not null unique,
  issued_at timestamp not null default now()
);