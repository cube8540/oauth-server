package cube8540.oauth.authentication.credentials.oauth;

import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.net.URI;
import java.util.Set;

public interface OAuth2ClientDetails {

    String getClientId();

    String getClientSecret();

    String getClientName();

    Set<URI> getRegisteredRedirectUris();

    Set<AuthorizationGrantType> getAuthorizedGrantTypes();

    Set<String> getScopes();

    String getOwner();

    Integer getAccessTokenValiditySeconds();

    Integer getRefreshTokenValiditySeconds();

}
