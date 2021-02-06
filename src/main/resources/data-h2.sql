-- insert user scope
insert into oauth2_scope(scope_id, description) select 'access.oauth.scope', 'access oauth scope api' where not exists (select initialize_datetime from initialize);
insert into oauth2_scope(scope_id, description) select 'access.oauth.client', 'access oauth client api' where not exists (select initialize_datetime from initialize);
insert into oauth2_scope(scope_id, description) select 'access.oauth.token', 'access oauth token api' where not exists (select initialize_datetime from initialize);
insert into oauth2_scope(scope_id, description) select 'management.user', 'management user api' where not exists (select initialize_datetime from initialize);
update oauth2_scope set initialize = true where scope_id = 'access.oauth.scope';
update oauth2_scope set initialize = true where scope_id = 'access.oauth.client';
update oauth2_scope set initialize = true where scope_id = 'access.oauth.token';
update oauth2_scope set initialize = true where scope_id = 'management.user';

-- insert admin scope
insert into oauth2_scope(scope_id, description) select 'management.server', 'management server configuration' where not exists (select initialize_datetime from initialize);
insert into oauth2_scope(scope_id, description) select 'management.oauth', 'management oauth configuration' where not exists (select initialize_datetime from initialize);
update oauth2_scope set initialize = true where scope_id = 'management.server';
update oauth2_scope set initialize = true where scope_id = 'management.oauth';

-- oauth2 client security resource api
insert into secured_resource(resource_id, method, resource) select 'TOKEN-READ-API', 'GET', '/api/tokens/**' where not exists (select initialize_datetime from initialize);
insert into secured_resource(resource_id, method, resource) select 'OAUTH2-CLIENT-READ-API', 'GET', '/api/clients/**' where not exists (select initialize_datetime from initialize);
insert into secured_resource(resource_id, method, resource) select 'OAUTH2-CLIENT-REGISTER-API', 'POST', '/api/clients/**' where not exists (select initialize_datetime from initialize);
insert into secured_resource(resource_id, method, resource) select 'OAUTH2-CLIENT-MODIFY-API', 'PUT', '/api/clients/**' where not exists (select initialize_datetime from initialize);
insert into secured_resource(resource_id, method, resource) select 'OAUTH2-CLIENT-REMOVE-API', 'DELETE', '/api/clients/**' where not exists (select initialize_datetime from initialize);

-- oauth2 scope security resource api
insert into secured_resource(resource_id, method, resource) select 'OAUTH2-SCOPE-READ-API', 'GET', '/api/scopes/**' where not exists (select initialize_datetime from initialize);
insert into secured_resource(resource_id, method, resource) select 'OAUTH2-SCOPE-REGISTER-API', 'POST', '/api/scopes/**' where not exists (select initialize_datetime from initialize);
insert into secured_resource(resource_id, method, resource) select 'OAUTH2-SCOPE-MODIFY-API', 'PUT', '/api/scopes/**' where not exists (select initialize_datetime from initialize);
insert into secured_resource(resource_id, method, resource) select 'OAUTH2-SCOPE-REMOVE-API', 'DELETE', '/api/scopes/**' where not exists (select initialize_datetime from initialize);

-- user management security resource api
insert into secured_resource(resource_id, method, resource) select 'USER-MANAGEMENT-API', 'ALL', '/api/accounts/**' where not exists (select initialize_datetime from initialize);

-- security resource api
insert into secured_resource(resource_id, method, resource) select 'SECURED-RESOURCE-API', 'ALL', '/api/secured-resources/**' where not exists (select initialize_datetime from initialize);

-- connect security resource and scope
insert into authority_accessible_resources(authority, resource_id) select 'access.oauth.token', 'TOKEN-READ-API' where not exists (select initialize_datetime from initialize);
insert into authority_accessible_resources(authority, resource_id) select 'access.oauth.client', 'OAUTH2-CLIENT-READ-API' where not exists (select initialize_datetime from initialize);
insert into authority_accessible_resources(authority, resource_id) select 'access.oauth.client', 'OAUTH2-CLIENT-REGISTER-API' where not exists (select initialize_datetime from initialize);
insert into authority_accessible_resources(authority, resource_id) select 'access.oauth.client', 'OAUTH2-CLIENT-MODIFY-API' where not exists (select initialize_datetime from initialize);
insert into authority_accessible_resources(authority, resource_id) select 'access.oauth.client', 'OAUTH2-CLIENT-REMOVE-API' where not exists (select initialize_datetime from initialize);

insert into authority_accessible_resources(authority, resource_id) select 'access.oauth.scope', 'OAUTH2-SCOPE-READ-API' where not exists (select initialize_datetime from initialize);
insert into authority_accessible_resources(authority, resource_id) select 'management.oauth', 'OAUTH2-SCOPE-REGISTER-API' where not exists (select initialize_datetime from initialize);
insert into authority_accessible_resources(authority, resource_id) select 'management.oauth', 'OAUTH2-SCOPE-MODIFY-API' where not exists (select initialize_datetime from initialize);
insert into authority_accessible_resources(authority, resource_id) select 'management.oauth', 'OAUTH2-SCOPE-REMOVE-API' where not exists (select initialize_datetime from initialize);

insert into authority_accessible_resources(authority, resource_id) select 'management.server', 'SECURED-RESOURCE-API' where not exists (select initialize_datetime from initialize);

insert into authority_accessible_resources(authority, resource_id) select 'management.user', 'USER-MANAGEMENT-API' where not exists (select initialize_datetime from initialize);

insert into initialize select current_timestamp where not exists (select * from initialize);

update `user` set uid = replace(random_uuid(), '-', '') where uid is null;

commit;