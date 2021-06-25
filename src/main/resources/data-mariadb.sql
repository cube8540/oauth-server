-- insert user scope
insert into oauth2_scope(scope_id, description, initialize) select 'oauth2.scope.read', 'oauth2 scope read scope', true where not exists (select scope_id from oauth2_scope where scope_id = 'oauth2.scope.read');
insert into oauth2_scope(scope_id, description, initialize) select 'oauth2.scope.write', 'oauth2 scope write scope', true where not exists (select scope_id from oauth2_scope where scope_id = 'oauth2.scope.write');
insert into oauth2_scope(scope_id, description, initialize) select 'oauth2.scope.remove', 'oauth2 scope remove scope', true where not exists (select scope_id from oauth2_scope where scope_id = 'oauth2.scope.remove');

insert into oauth2_scope(scope_id, description, initialize) select 'oauth2.client.read', 'oauth2 client read scope', true where not exists (select scope_id from oauth2_scope where scope_id = 'oauth2.client.read');
insert into oauth2_scope(scope_id, description, initialize) select 'oauth2.client.write', 'oauth2 client write scope', true where not exists (select scope_id from oauth2_scope where scope_id = 'oauth2.client.write');
insert into oauth2_scope(scope_id, description, initialize) select 'oauth2.client.remove', 'oauth2 client remove scope', true where not exists (select scope_id from oauth2_scope where scope_id = 'oauth2.client.remove');

insert into oauth2_scope(scope_id, description, initialize) select 'oauth2.token.read', 'oauth2 token read scope', true where not exists (select scope_id from oauth2_scope where scope_id = 'oauth2.token.read');

insert into oauth2_scope(scope_id, description, initialize) select 'oauth2.user.read', 'oauth2 user read scope', true where not exists (select scope_id from oauth2_scope where scope_id = 'oauth2.user.read');
insert into oauth2_scope(scope_id, description, initialize) select 'oauth2.user.write', 'oauth2 user write scope', true where not exists (select scope_id from oauth2_scope where scope_id = 'oauth2.user.write');
insert into oauth2_scope(scope_id, description, initialize) select 'oauth2.user.remove', 'oauth2 user remove scope', true where not exists (select scope_id from oauth2_scope where scope_id = 'oauth2.user.remove');

insert into oauth2_scope(scope_id, description, initialize) select 'server.sec-res.read', 'server security resource read', true where not exists (select scope_id from oauth2_scope where scope_id = 'server.sec-res.read');
insert into oauth2_scope(scope_id, description, initialize) select 'server.sec-res.write', 'server security resource read', true where not exists (select scope_id from oauth2_scope where scope_id = 'server.sec-res.write');
insert into oauth2_scope(scope_id, description, initialize) select 'server.sec-res.remove', 'server security resource read', true where not exists (select scope_id from oauth2_scope where scope_id = 'server.sec-res.remove');

-- oauth2 client security resource api
insert into secured_resource(resource_id, method, resource) select 'TOKEN-READ-API', 'GET', '/api/tokens/**' where not exists (select resource_id from secured_resource where resource_id = 'TOKEN-READ-API');

insert into secured_resource(resource_id, method, resource) select 'OAUTH2-CLIENT-READ-API', 'GET', '/api/clients/**' where not exists (select resource_id from secured_resource where resource_id = 'OAUTH2-CLIENT-READ-API');
insert into secured_resource(resource_id, method, resource) select 'OAUTH2-CLIENT-REGISTER-API', 'POST', '/api/clients/**' where not exists (select resource_id from secured_resource where resource_id = 'OAUTH2-CLIENT-REGISTER-API');
insert into secured_resource(resource_id, method, resource) select 'OAUTH2-CLIENT-MODIFY-API', 'PUT', '/api/clients/**' where not exists (select resource_id from secured_resource where resource_id = 'OAUTH2-CLIENT-MODIFY-API');
insert into secured_resource(resource_id, method, resource) select 'OAUTH2-CLIENT-EDIT-API', 'PATCH', '/api/client/**' where not exists (select resource_id from secured_resource where resource_id = 'OAUTH2-CLIENT-EDIT-API');
insert into secured_resource(resource_id, method, resource) select 'OAUTH2-CLIENT-REMOVE-API', 'DELETE', '/api/clients/**' where not exists (select resource_id from secured_resource where resource_id = 'OAUTH2-CLIENT-REMOVE-API');

-- oauth2 scope security resource api
insert into secured_resource(resource_id, method, resource) select 'OAUTH2-SCOPE-READ-API', 'GET', '/api/scopes/**' where not exists (select resource_id from secured_resource where resource_id = 'OAUTH2-SCOPE-READ-API');
insert into secured_resource(resource_id, method, resource) select 'OAUTH2-SCOPE-REGISTER-API', 'POST', '/api/scopes/**' where not exists (select resource_id from secured_resource where resource_id = 'OAUTH2-SCOPE-REGISTER-API');
insert into secured_resource(resource_id, method, resource) select 'OAUTH2-SCOPE-MODIFY-API', 'PUT', '/api/scopes/**' where not exists (select resource_id from secured_resource where resource_id = 'OAUTH2-SCOPE-MODIFY-API');
insert into secured_resource(resource_id, method, resource) select 'OAUTH2-SCOPE-EDIT-API', 'PATCH', '/api/scopes/**' where not exists (select resource_id from secured_resource where resource_id = 'OAUTH2-SCOPE-EDIT-API');
insert into secured_resource(resource_id, method, resource) select 'OAUTH2-SCOPE-REMOVE-API', 'DELETE', '/api/scopes/**' where not exists (select resource_id from secured_resource where resource_id = 'OAUTH2-SCOPE-REMOVE-API');

-- user management security resource api
insert into secured_resource(resource_id, method, resource) select 'OAUTH2-USER-READ-API', 'GET', '/api/accounts/**' where not exists (select resource_id from secured_resource where resource_id = 'OAUTH2-USER-READ-API');
insert into secured_resource(resource_id, method, resource) select 'OAUTH2-USER-REGISTER-API', 'POST', '/api/accounts/**' where not exists (select resource_id from secured_resource where resource_id = 'OAUTH2-USER-REGISTER-API');
insert into secured_resource(resource_id, method, resource) select 'OAUTH2-USER-MODIFY-API', 'PUT', '/api/accounts/**' where not exists (select resource_id from secured_resource where resource_id = 'OAUTH2-USER-MODIFY-API');
insert into secured_resource(resource_id, method, resource) select 'OAUTH2-USER-EDIT-API', 'PATCH', '/api/accounts/**' where not exists (select resource_id from secured_resource where resource_id = 'OAUTH2-USER-EDIT-API');
insert into secured_resource(resource_id, method, resource) select 'OAUTH2-USER-REMOVE-API', 'DELETE', '/api/accounts/**' where not exists (select resource_id from secured_resource where resource_id = 'OAUTH2-USER-REMOVE-API');

-- security resource api
insert into secured_resource(resource_id, method, resource) select 'SERVER-SEC-RES-READ-API', 'GET', '/api/secured-resources/**' where not exists (select resource_id from secured_resource where resource_id = 'SERVER-SEC-RES-READ-API');
insert into secured_resource(resource_id, method, resource) select 'SERVER-SEC-RES-REGISTER-API', 'POST', '/api/secured-resources/**' where not exists (select resource_id from secured_resource where resource_id = 'SERVER-SEC-RES-REGISTER-API');
insert into secured_resource(resource_id, method, resource) select 'SERVER-SEC-RES-MODIFY-API', 'PUT', '/api/secured-resources/**' where not exists (select resource_id from secured_resource where resource_id = 'SERVER-SEC-RES-MODIFY-API');
insert into secured_resource(resource_id, method, resource) select 'SERVER-SEC-RES-EDIT-API', 'PATCH', '/api/secured-resources/**' where not exists (select resource_id from secured_resource where resource_id = 'SERVER-SEC-RES-EDIT-API');
insert into secured_resource(resource_id, method, resource) select 'SERVER-SEC-RES-REMOVE-API', 'DELETE', '/api/secured-resources/**' where not exists (select resource_id from secured_resource where resource_id = 'SERVER-SEC-RES-REMOVE-API');

-- connect security resource and scope
insert into authority_accessible_resources(authority, resource_id) select 'oauth2.token.read', 'TOKEN-READ-API' where not exists (select authority from authority_accessible_resources where authority = 'oauth2.token.read' and resource_id = 'TOKEN-READ-API');

insert into authority_accessible_resources(authority, resource_id) select 'oauth2.client.read', 'OAUTH2-CLIENT-READ-API' where not exists (select authority from authority_accessible_resources where authority = 'oauth2.client.read' and resource_id = 'OAUTH2-CLIENT-READ-API');
insert into authority_accessible_resources(authority, resource_id) select 'oauth2.client.write', 'OAUTH2-CLIENT-REGISTER-API' where not exists (select authority from authority_accessible_resources where authority = 'oauth2.client.write' and resource_id = 'OAUTH2-CLIENT-REGISTER-API');
insert into authority_accessible_resources(authority, resource_id) select 'oauth2.client.write', 'OAUTH2-CLIENT-MODIFY-API' where not exists (select authority from authority_accessible_resources where authority = 'oauth2.client.write' and resource_id = 'OAUTH2-CLIENT-MODIFY-API');
insert into authority_accessible_resources(authority, resource_id) select 'oauth2.client.write', 'OAUTH2-CLIENT-EDIT-API' where not exists (select authority from authority_accessible_resources where authority = 'oauth2.client.write' and resource_id = 'OAUTH2-CLIENT-EDIT-API');
insert into authority_accessible_resources(authority, resource_id) select 'oauth2.client.remove', 'OAUTH2-CLIENT-REMOVE-API' where not exists (select authority from authority_accessible_resources where authority = 'oauth2.client.remove' and resource_id = 'OAUTH2-CLIENT-REMOVE-API');

insert into authority_accessible_resources(authority, resource_id) select 'oauth2.scope.read', 'OAUTH2-SCOPE-READ-API' where not exists (select authority from authority_accessible_resources where authority = 'oauth2.scope.read' and resource_id = 'OAUTH2-SCOPE-READ-API');
insert into authority_accessible_resources(authority, resource_id) select 'oauth2.scope.write', 'OAUTH2-SCOPE-REGISTER-API' where not exists (select authority from authority_accessible_resources where authority = 'oauth2.scope.write' and resource_id = 'OAUTH2-SCOPE-REGISTER-API');
insert into authority_accessible_resources(authority, resource_id) select 'oauth2.scope.write', 'OAUTH2-SCOPE-MODIFY-API' where not exists (select authority from authority_accessible_resources where authority = 'oauth2.scope.write' and resource_id = 'OAUTH2-SCOPE-MODIFY-API');
insert into authority_accessible_resources(authority, resource_id) select 'oauth2.scope.write', 'OAUTH2-SCOPE-EDIT-API' where not exists (select authority from authority_accessible_resources where authority = 'oauth2.scope.write' and resource_id = 'OAUTH2-SCOPE-EDIT-API');
insert into authority_accessible_resources(authority, resource_id) select 'oauth2.scope.remove', 'OAUTH2-SCOPE-REMOVE-API' where not exists (select authority from authority_accessible_resources where authority = 'management.oauth' and resource_id = 'OAUTH2-SCOPE-REMOVE-API');

insert into authority_accessible_resources(authority, resource_id) select 'server.sec-res.read', 'SERVER-SEC-RES-READ-API' where not exists (select authority from authority_accessible_resources where authority = 'server.sec-res.read' and resource_id = 'SERVER-SEC-RES-READ-API');
insert into authority_accessible_resources(authority, resource_id) select 'server.sec-res.write', 'SERVER-SEC-RES-REGISTER-API' where not exists (select authority from authority_accessible_resources where authority = 'server.sec-res.write' and resource_id = 'SERVER-SEC-RES-EDIT-API');
insert into authority_accessible_resources(authority, resource_id) select 'server.sec-res.write', 'SERVER-SEC-RES-MODIFY-API' where not exists (select authority from authority_accessible_resources where authority = 'server.sec-res.write' and resource_id = 'SERVER-SEC-RES-EDIT-API');
insert into authority_accessible_resources(authority, resource_id) select 'server.sec-res.write', 'SERVER-SEC-RES-EDIT-API' where not exists (select authority from authority_accessible_resources where authority = 'server.sec-res.write' and resource_id = 'SERVER-SEC-RES-EDIT-API');
insert into authority_accessible_resources(authority, resource_id) select 'server.sec-res.remove', 'SERVER-SEC-RES-REMOVE-API' where not exists (select authority from authority_accessible_resources where authority = 'server.sec-res.remove' and resource_id = 'SERVER-SEC-RES-REMOVE-API');

insert into authority_accessible_resources(authority, resource_id) select 'oauth2.user.read', 'OAUTH2-USER-READ-API' where not exists (select authority from authority_accessible_resources where authority = 'management.user' and resource_id = 'OAUTH2-USER-READ-API');
insert into authority_accessible_resources(authority, resource_id) select 'oauth2.user.write', 'OAUTH2-USER-REGISTER-API' where not exists (select authority from authority_accessible_resources where authority = 'management.user' and resource_id = 'OAUTH2-USER-REGISTER-API');
insert into authority_accessible_resources(authority, resource_id) select 'oauth2.user.write', 'OAUTH2-USER-MODIFY-API' where not exists (select authority from authority_accessible_resources where authority = 'management.user' and resource_id = 'OAUTH2-USER-MODIFY-API');
insert into authority_accessible_resources(authority, resource_id) select 'oauth2.user.write', 'OAUTH2-USER-EDIT-API' where not exists (select authority from authority_accessible_resources where authority = 'management.user' and resource_id = 'OAUTH2-USER-EDIT-API');
insert into authority_accessible_resources(authority, resource_id) select 'oauth2.user.remove', 'OAUTH2-USER-REMOVE-API' where not exists (select authority from authority_accessible_resources where authority = 'management.user' and resource_id = 'OAUTH2-SCOPE-REMOVE-API');

commit;