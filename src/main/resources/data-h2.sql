-- insert user scope
insert into oauth2_scope(scope_id, description) select 'access.oauth.scope', 'access oauth scope api' where not exists (select scope_id from oauth2_scope where scope_id = 'access.oauth.scope');
insert into oauth2_scope(scope_id, description) select 'access.oauth.client', 'access oauth client api' where not exists (select scope_id from oauth2_scope where scope_id = 'access.oauth.client');
insert into oauth2_scope(scope_id, description) select 'access.oauth.token', 'access oauth token api' where not exists (select scope_id from oauth2_scope where scope_id = 'access.oauth.token');
insert into oauth2_scope(scope_id, description) select 'management.user', 'management user api' where not exists (select scope_id from oauth2_scope where scope_id = 'management.user');
update oauth2_scope set initialize = true where scope_id = 'access.oauth.scope';
update oauth2_scope set initialize = true where scope_id = 'access.oauth.client';
update oauth2_scope set initialize = true where scope_id = 'access.oauth.token';
update oauth2_scope set initialize = true where scope_id = 'management.user';

-- insert admin scope
insert into oauth2_scope(scope_id, description) select 'management.server', 'management server configuration' where not exists (select scope_id from oauth2_scope where scope_id = 'management.server');
insert into oauth2_scope(scope_id, description) select 'management.oauth', 'management oauth configuration' where not exists (select scope_id from oauth2_scope where scope_id = 'management.oauth');
update oauth2_scope set initialize = true where scope_id = 'management.server';
update oauth2_scope set initialize = true where scope_id = 'management.oauth';

-- oauth2 client security resource api
insert into secured_resource(resource_id, method, resource) select 'TOKEN-READ-API', 'GET', '/api/tokens/**' where not exists (select resource_id from secured_resource where resource_id = 'TOKEN-READ-API');
insert into secured_resource(resource_id, method, resource) select 'OAUTH2-CLIENT-READ-API', 'GET', '/api/clients/**' where not exists (select resource_id from secured_resource where resource_id = 'OAUTH2-CLIENT-READ-API');
insert into secured_resource(resource_id, method, resource) select 'OAUTH2-CLIENT-REGISTER-API', 'POST', '/api/clients/**' where not exists (select resource_id from secured_resource where resource_id = 'OAUTH2-CLIENT-REGISTER-API');
insert into secured_resource(resource_id, method, resource) select 'OAUTH2-CLIENT-MODIFY-API', 'PUT', '/api/clients/**' where not exists (select resource_id from secured_resource where resource_id = 'OAUTH2-CLIENT-MODIFY-API');
insert into secured_resource(resource_id, method, resource) select 'OAUTH2-CLIENT-REMOVE-API', 'DELETE', '/api/clients/**' where not exists (select resource_id from secured_resource where resource_id = 'OAUTH2-CLIENT-REMOVE-API');
insert into secured_resource(resource_id, method, resource) select 'OAUTH2-CLIENT-EDIT-API', 'PATCH', '/api/client/**' where not exists (select resource_id from secured_resource where resource_id = 'OAUTH2-CLIENT-EDIT-API');

-- oauth2 scope security resource api
insert into secured_resource(resource_id, method, resource) select 'OAUTH2-SCOPE-READ-API', 'GET', '/api/scopes/**' where not exists (select resource_id from secured_resource where resource_id = 'OAUTH2-SCOPE-READ-API');
insert into secured_resource(resource_id, method, resource) select 'OAUTH2-SCOPE-REGISTER-API', 'POST', '/api/scopes/**' where not exists (select resource_id from secured_resource where resource_id = 'OAUTH2-SCOPE-REGISTER-API');
insert into secured_resource(resource_id, method, resource) select 'OAUTH2-SCOPE-MODIFY-API', 'PUT', '/api/scopes/**' where not exists (select resource_id from secured_resource where resource_id = 'OAUTH2-SCOPE-MODIFY-API');
insert into secured_resource(resource_id, method, resource) select 'OAUTH2-SCOPE-EDIT-API', 'PATCH', '/api/scopes/**' where not exists (select resource_id from secured_resource where resource_id = 'OAUTH2-SCOPE-EDIT-API');
insert into secured_resource(resource_id, method, resource) select 'OAUTH2-SCOPE-REMOVE-API', 'DELETE', '/api/scopes/**' where not exists (select resource_id from secured_resource where resource_id = 'OAUTH2-SCOPE-REMOVE-API');

-- user management security resource api
insert into secured_resource(resource_id, method, resource) select 'USER-MANAGEMENT-API', 'ALL', '/api/accounts/**' where not exists (select resource_id from secured_resource where resource_id = 'USER-MANAGEMENT-API');

-- security resource api
insert into secured_resource(resource_id, method, resource) select 'SECURED-RESOURCE-API', 'ALL', '/api/secured-resources/**' where not exists (select resource_id from secured_resource where resource_id = 'SECURED-RESOURCE-API');

-- connect security resource and scope
insert into authority_accessible_resources(authority, resource_id) select 'access.oauth.token', 'TOKEN-READ-API' where not exists (select authority from authority_accessible_resources where authority = 'access.oauth.token' and resource_id = 'TOKEN-READ-API');
insert into authority_accessible_resources(authority, resource_id) select 'access.oauth.client', 'OAUTH2-CLIENT-READ-API' where not exists (select authority from authority_accessible_resources where authority = 'access.oauth.client' and resource_id = 'OAUTH2-CLIENT-READ-API');
insert into authority_accessible_resources(authority, resource_id) select 'access.oauth.client', 'OAUTH2-CLIENT-REGISTER-API' where not exists (select authority from authority_accessible_resources where authority = 'access.oauth.client' and resource_id = 'OAUTH2-CLIENT-REGISTER-API');
insert into authority_accessible_resources(authority, resource_id) select 'access.oauth.client', 'OAUTH2-CLIENT-MODIFY-API' where not exists (select authority from authority_accessible_resources where authority = 'access.oauth.client' and resource_id = 'OAUTH2-CLIENT-MODIFY-API');
insert into authority_accessible_resources(authority, resource_id) select 'access.oauth.client', 'OAUTH2-CLIENT-EDIT-API' where not exists (select authority from authority_accessible_resources where authority = 'access.oauth.client' and resource_id = 'OAUTH2-CLIENT-EDIT-API');
insert into authority_accessible_resources(authority, resource_id) select 'access.oauth.client', 'OAUTH2-CLIENT-REMOVE-API' where not exists (select authority from authority_accessible_resources where authority = 'access.oauth.client' and resource_id = 'OAUTH2-CLIENT-REMOVE-API');

insert into authority_accessible_resources(authority, resource_id) select 'access.oauth.scope', 'OAUTH2-SCOPE-READ-API' where not exists (select authority from authority_accessible_resources where authority = 'access.oauth.scope' and resource_id = 'OAUTH2-SCOPE-READ-API');
insert into authority_accessible_resources(authority, resource_id) select 'management.oauth', 'OAUTH2-SCOPE-REGISTER-API' where not exists (select authority from authority_accessible_resources where authority = 'management.oauth' and resource_id = 'OAUTH2-SCOPE-REGISTER-API');
insert into authority_accessible_resources(authority, resource_id) select 'management.oauth', 'OAUTH2-SCOPE-MODIFY-API' where not exists (select authority from authority_accessible_resources where authority = 'management.oauth' and resource_id = 'OAUTH2-SCOPE-MODIFY-API');
insert into authority_accessible_resources(authority, resource_id) select 'management.oauth', 'OAUTH2-SCOPE-EDIT-API' where not exists (select authority from authority_accessible_resources where authority = 'management.oauth' and resource_id = 'OAUTH2-SCOPE-EDIT-API');
insert into authority_accessible_resources(authority, resource_id) select 'management.oauth', 'OAUTH2-SCOPE-REMOVE-API' where not exists (select authority from authority_accessible_resources where authority = 'management.oauth' and resource_id = 'OAUTH2-SCOPE-REMOVE-API');

insert into authority_accessible_resources(authority, resource_id) select 'management.server', 'SECURED-RESOURCE-API' where not exists (select authority from authority_accessible_resources where authority = 'management.server' and resource_id = 'SECURED-RESOURCE-API');

insert into authority_accessible_resources(authority, resource_id) select 'management.user', 'USER-MANAGEMENT-API' where not exists (select authority from authority_accessible_resources where authority = 'management.user' and resource_id = 'USER-MANAGEMENT-API');

update `user` set uid = replace(uuid(), '-', '') where uid is null;

commit;