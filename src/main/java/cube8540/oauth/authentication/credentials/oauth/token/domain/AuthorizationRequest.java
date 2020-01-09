package cube8540.oauth.authentication.credentials.oauth.token.domain;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.users.domain.UserEmail;

import java.net.URI;
import java.util.Set;

public interface AuthorizationRequest {

    OAuth2ClientId clientId();

    UserEmail email();

    String state();

    URI redirectURI();

    Set<OAuth2ScopeId> approvedScopes();

}
