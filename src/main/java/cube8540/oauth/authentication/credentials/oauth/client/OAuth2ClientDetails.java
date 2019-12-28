package cube8540.oauth.authentication.credentials.oauth.client;

import cube8540.oauth.authentication.credentials.oauth.OAuth2GrantType;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;

import java.net.URI;
import java.util.Set;

public interface OAuth2ClientDetails {

    String clientId();

    String clientSecret();

    String clientName();

    Set<URI> registeredRedirectURI();

    Set<OAuth2GrantType> authorizedGrantType();

    Set<OAuth2ScopeId> scope();

    Integer accessTokenValiditySeconds();

    Integer refreshTokenValiditySeconds();

}
