create table if not exists initialize (
	initialize_datetime datetime(6) default current_datetime(6)() not null
);

create table if not exists role (
    code varchar(32) not null primary key,
    description varchar(32),
    basic boolean not null default false
);

create table if not exists `user` (
    username varchar(32) not null primary key,
	email varchar(128) not null,
	credentials_key_expiry_datetime datetime(6),
	credentials_key varchar(32),
	last_updated_at datetime(6) not null,
	password varchar(64) not null,
	password_credentials_key_expiry_datetime datetime(6),
	password_credentials_key varchar(32),
	is_credentials boolean not null default false,
	registered_at datetime(6) not null,

	unique key uk_user_email (email)
);

create table if not exists user_authority (
    username varchar(32) not null,
    authority_code varchar(32) not null,

    constraint fk_user_authority_username foreign key (username) references user(username) on delete cascade,
    constraint fk_user_authority_role foreign key (authority_code) references role(code) on delete cascade
);

create table if not exists oauth2_clients (
	client_id varchar(32) not null primary key,
	access_token_validity bigint not null,
	client_name varchar(32) not null,
	oauth2_client_owner varchar(128) not null,
	refresh_token_validity bigint not null,
	client_secret varchar(64) not null,

	constraint fk_client_username foreign key (oauth2_client_owner) references user (username) on delete cascade
);

create table if not exists oauth2_scope (
	scope_id varchar(32) not null primary key,
	description varchar(64)
);

create table if not exists oauth2_access_token (
	token_id varchar(32) not null primary key,
	client_id varchar(32) not null,
	expiration datetime(6) not null,
	grant_type varchar(32) not null,
	username varchar(32),
	issued_at datetime(6) not null,
	constraint client_authentication_username unique (client_id, username),
	constraint fk_access_token_client_id foreign key (client_id) references oauth2_clients (client_id) on delete cascade,
	constraint fk_access_token_username foreign key (username) references user (username) on delete cascade
);

create table if not exists oauth2_access_token_additional_information (
	token_id varchar(32) not null,
	info_value varchar(128),
	info_key varchar(255) not null,
	primary key (token_id, info_key),
	constraint fk_account_token foreign key (token_id) references oauth2_access_token (token_id) on delete cascade
);

create table if not exists oauth2_authorization_code (
	authorization_code varchar(6) not null primary key,
	client_id varchar(32) not null,
	expiration_at datetime(6) not null,
	redirect_uri varchar(128) null,
	state varchar(12),
	username varchar(32),

    constraint fk_authorization_code_client_id foreign key (client_id) references oauth2_clients (client_id) on delete cascade,
	constraint fk_authorization_code_username foreign key (username) references user (username) on delete cascade
);

create table if not exists oauth2_client_grant_type (
	client_id varchar(32) not null,
	grant_type varchar(32) not null,
	primary key (client_id, grant_type),
	constraint fk_client_grant_type_client_id foreign key (client_id) references oauth2_clients (client_id)
);

create table if not exists oauth2_client_redirect_uri (
	client_id varchar(32) not null,
	redirect_uri varchar(128) not null,
	primary key (client_id, redirect_uri),
	constraint fk_client_redirect_uri_client_id foreign key (client_id) references oauth2_clients (client_id) on delete cascade
);

create table if not exists oauth2_client_scope (
	client_id varchar(32) not null,
	scope_id varchar(32) not null,
	primary key (client_id, scope_id),
	constraint fk_client_scope_client_id foreign key (client_id) references oauth2_clients (client_id) on delete cascade,
	constraint fk_client_scope_scope_id foreign key (scope_id) references oauth2_scope (scope_id) on delete cascade
);

create table if not exists oauth2_code_approved_scope
(
	authorization_code varchar(6) not null,
	scope_id varchar(32) not null,
	primary key (authorization_code, scope_id),
	constraint fk_approved_scope_code foreign key (authorization_code) references oauth2_authorization_code (authorization_code) on delete cascade,
	constraint fk_approved_scope_scope foreign key (scope_id) references oauth2_scope (scope_id) on delete cascade
);

create table if not exists oauth2_refresh_token (
	token_id varchar(32) not null primary key,
	expiration datetime(6) not null,
	access_token_token_id varchar(32) null,
	constraint fk_refresh_token_access_token foreign key (access_token_token_id) references oauth2_access_token (token_id) on delete cascade
);

create table if not exists oauth2_scope_accessible_authority (
	scope_id varchar(32) not null,
	authority varchar(32) not null,
	primary key (scope_id, authority),
	constraint fk_accessible_authority_scope_id foreign key (scope_id) references oauth2_scope (scope_id) on delete cascade,
	constraint fk_accessible_authority_authority foreign key (authority) references oauth2_scope (scope_id) on delete cascade
);

create table if not exists oauth2_token_scope (
	token_id varchar(32) not null,
	scope_id varchar(32) not null,
	primary key (token_id, scope_id),
	constraint fk_token_scope_token_id foreign key (token_id) references oauth2_access_token (token_id) on delete cascade,
	constraint fk_token_scope_scope_id foreign key (scope_id) references oauth2_scope (scope_id) on delete cascade
);

create table if not exists secured_resource (
	resource_id varchar(32) not null primary key,
	method varchar(32) not null,
	resource varchar(128) not null
);

create table if not exists authority_accessible_resources (
	authority varchar(32) not null,
	resource_id varchar(128) not null,
	primary key (authority, resource_id),
	constraint fk_accessible_resource_resource foreign key (resource_id) references secured_resource (resource_id) on delete cascade,
	constraint fk_accessible_resource_authority foreign key (authority) references oauth2_scope (scope_id) on delete cascade
);

commit;