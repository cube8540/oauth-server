insert into user(email, password, registered_at, last_updated_at) select 'admin', '$2a$10$uTSfWKXF20lwumttjUbxteWVJBedSEQkYxC6qJJbEVUYjzvM6q7Q2', current_timestamp, current_timestamp where not exists (select initialize_datetime from initialize);
insert into authority(code, is_basic, description) select 'ROLE_USER', true, 'Default Role' where not exists (select initialize_datetime from initialize);
insert into authority(code, is_basic, description) select 'ROLE_ADMIN', false, 'Admin Role' where not exists (select initialize_datetime from initialize);
insert into user_authority(email, authority_code) select 'admin', 'ROLE_ADMIN' where not exists (select initialize_datetime from initialize);
insert into user_authority(email, authority_code) select 'admin', 'ROLE_USER' where not exists (select initialize_datetime from initialize);

insert into secured_resource(resource_id, method, resource) select 'AUTHORITIES-API', 'ALL', '/api/authorities/**' where not exists (select initialize_datetime from initialize);
insert into secured_resource(resource_id, method, resource) select 'SECURED-RESOURCE-API', 'ALL', '/api/secured-resource/**' where not exists (select initialize_datetime from initialize);
insert into secured_resource(resource_id, method, resource) select 'OAUTH2-CLIENT-API', 'ALL', '/api/clients/**' where not exists (select initialize_datetime from initialize);
insert into secured_resource(resource_id, method, resource) select 'OAUTH2-SCOPE-API', 'ALL', '/api/scopes/**' where not exists (select initialize_datetime from initialize);
insert into secured_resource(resource_id, method, resource) select 'USER-PASSWORD-CHANGE-API', 'PUT', '/api/accounts/attributes/password' where not exists (select initialize_datetime from initialize);
insert into secured_resource(resource_id, method, resource) select 'TOKEN-API', 'ALL', '/api/tokens/**' where not exists (select initialize_datetime from initialize);

insert into authority_accessible_resources(authority, resource_id) select 'ROLE_ADMIN', 'AUTHORITIES-API' where not exists (select initialize_datetime from initialize);
insert into authority_accessible_resources(authority, resource_id) select 'ROLE_ADMIN', 'SECURED-RESOURCE-API' where not exists (select initialize_datetime from initialize);
insert into authority_accessible_resources(authority, resource_id) select 'ROLE_ADMIN', 'OAUTH2-CLIENT-API' where not exists (select initialize_datetime from initialize);
insert into authority_accessible_resources(authority, resource_id) select 'ROLE_ADMIN', 'OAUTH2-SCOPE-API' where not exists (select initialize_datetime from initialize);
insert into authority_accessible_resources(authority, resource_id) select 'ROLE_USER', 'USER-PASSWORD-CHANGE-API' where not exists (select initialize_datetime from initialize);
insert into authority_accessible_resources(authority, resource_id) select 'ROLE_USER', 'TOKEN-API' where not exists (select initialize_datetime from initialize);


insert into initialize select current_timestamp where not exists (select * from initialize);

commit;