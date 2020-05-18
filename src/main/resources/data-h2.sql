-- insert default user
insert into user(username, email, password, registered_at, last_updated_at, is_credentials) select 'admin', 'admin', '$2a$10$uTSfWKXF20lwumttjUbxteWVJBedSEQkYxC6qJJbEVUYjzvM6q7Q2', current_timestamp, current_timestamp, true where not exists (select initialize_datetime from initialize);

-- insert default role
insert into role(code, description, basic) select 'ROLE_ADMIN', 'Admin Role', false where not exists (select initialize_datetime from initialize);
insert into role(code, description, basic) select 'ROLE_USER', 'Default User Role', true where not exists (select initialize_datetime from initialize);

-- insert user default role
insert into user_authority(username, authority_code) select 'admin', 'ROLE_ADMIN' where not exists (select initialize_datetime from initialize);
insert into user_authority(username, authority_code) select 'admin', 'ROLE_USER' where not exists (select initialize_datetime from initialize);

-- insert default client
insert into oauth2_clients(client_id, client_secret, client_name, access_token_validity, refresh_token_validity, oauth2_client_owner) select 'oauth-client', '$2a$10$IKIfJYgEf7s5fAdpDFLmIu7.nEIFFgqDRRbfptstuHNav6kVdvFxK', 'client-name', 600000000000, 7200000000000, 'admin' where not exists (select initialize_datetime from initialize);
insert into oauth2_client_grant_type(client_id, grant_type) select 'oauth-client', 'authorization_code' where not exists (select initialize_datetime from initialize);
insert into oauth2_client_grant_type(client_id, grant_type) select 'oauth-client', 'refresh_token' where not exists (select initialize_datetime from initialize);
insert into oauth2_client_grant_type(client_id, grant_type) select 'oauth-client', 'client_credentials' where not exists (select initialize_datetime from initialize);

-- insert user scope
insert into oauth2_scope(scope_id, description) select 'access.oauth.scope', 'access oauth scope api' where not exists (select initialize_datetime from initialize);
insert into oauth2_scope(scope_id, description) select 'access.oauth.client', 'access oauth client api' where not exists (select initialize_datetime from initialize);
insert into oauth2_scope(scope_id, description) select 'access.oauth.token', 'access oauth token api' where not exists (select initialize_datetime from initialize);
insert into oauth2_scope(scope_id, description) select 'access.user.attribute', 'access user attribute api' where not exists (select initialize_datetime from initialize);
insert into oauth2_scope(scope_id, description) select 'modify.user.attribute', 'modifiable user attribute' where not exists (select initialize_datetime from initialize);

-- insert admin scope
insert into oauth2_scope(scope_id, description) select 'management.server', 'management server configuration' where not exists (select initialize_datetime from initialize);
insert into oauth2_scope(scope_id, description) select 'management.oauth', 'management oauth configuration' where not exists (select initialize_datetime from initialize);
insert into oauth2_scope(scope_id, description) select 'management.secured-resource', 'management resource security configuration' where not exists (select initialize_datetime from initialize);

-- insert client scope
insert into oauth2_client_scope(client_id, scope_id) select 'oauth-client', 'access.oauth.scope' where not exists (select initialize_datetime from initialize);
insert into oauth2_client_scope(client_id, scope_id) select 'oauth-client', 'access.oauth.client' where not exists (select initialize_datetime from initialize);
insert into oauth2_client_scope(client_id, scope_id) select 'oauth-client', 'access.oauth.token' where not exists (select initialize_datetime from initialize);
insert into oauth2_client_scope(client_id, scope_id) select 'oauth-client', 'access.user.attribute' where not exists (select initialize_datetime from initialize);
insert into oauth2_client_scope(client_id, scope_id) select 'oauth-client', 'modify.user.attribute' where not exists (select initialize_datetime from initialize);

-- insert client redirect uri
insert into oauth2_client_redirect_uri(client_id, redirect_uri) select 'oauth-client', 'http://localhost:8080/callback' where not exists (select initialize_datetime from initialize);

-- insert accessible scope authority
insert into oauth2_scope_accessible_authority(scope_id, authority) select 'access.oauth.scope', 'access.oauth.scope' where not exists (select initialize_datetime from initialize);
insert into oauth2_scope_accessible_authority(scope_id, authority) select 'access.oauth.client', 'access.oauth.scope' where not exists (select initialize_datetime from initialize);
insert into oauth2_scope_accessible_authority(scope_id, authority) select 'access.oauth.token', 'access.oauth.scope' where not exists (select initialize_datetime from initialize);
insert into oauth2_scope_accessible_authority(scope_id, authority) select 'access.user.attribute', 'access.oauth.scope' where not exists (select initialize_datetime from initialize);
insert into oauth2_scope_accessible_authority(scope_id, authority) select 'modify.user.attribute', 'access.oauth.scope' where not exists (select initialize_datetime from initialize);

-- insert management scope authority
insert into oauth2_scope_accessible_authority(scope_id, authority) select 'management.server', 'management.server' where not exists (select initialize_datetime from initialize);
insert into oauth2_scope_accessible_authority(scope_id, authority) select 'management.oauth', 'management.server' where not exists (select initialize_datetime from initialize);
insert into oauth2_scope_accessible_authority(scope_id, authority) select 'management.secured-resource', 'management.server' where not exists (select initialize_datetime from initialize);

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

-- security resource api
insert into secured_resource(resource_id, method, resource) select 'SECURED-RESOURCE-API', 'ALL', '/api/secured-resources/**' where not exists (select initialize_datetime from initialize);

-- user security resource api
insert into secured_resource(resource_id, method, resource) select 'USER-PASSWORD-CHANGE-API', 'PUT', '/api/accounts/attributes/password' where not exists (select initialize_datetime from initialize);
insert into secured_resource(resource_id, method, resource) select 'USER-ME-API', 'GET', '/api/accounts/me' where not exists (select initialize_datetime from initialize);

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

insert into authority_accessible_resources(authority, resource_id) select 'modify.user.attribute', 'USER-PASSWORD-CHANGE-API' where not exists (select initialize_datetime from initialize);
insert into authority_accessible_resources(authority, resource_id) select 'access.user.attribute', 'USER-ME-API' where not exists (select initialize_datetime from initialize);


insert into initialize select current_timestamp where not exists (select * from initialize);

commit;