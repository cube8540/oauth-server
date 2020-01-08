package cube8540.oauth.authentication.credentials.oauth.client.application;

import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.net.URI;
import java.util.Set;

public interface OAuth2ClientDetails {

    String clientId();

    String clientSecret();

    String clientName();

    Set<URI> registeredRedirectURI();

    Set<AuthorizationGrantType> authorizedGrantType();

    Set<OAuth2ScopeId> scope();

    Integer accessTokenValiditySeconds();

    Integer refreshTokenValiditySeconds();

}
