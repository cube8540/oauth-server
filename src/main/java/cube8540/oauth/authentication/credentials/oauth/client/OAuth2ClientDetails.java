package cube8540.oauth.authentication.credentials.oauth.client;

import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.net.URI;
import java.util.Set;

public interface OAuth2ClientDetails {

    String clientId();

    String clientSecret();

    String clientName();

    Set<URI> registeredRedirectURI();

    Set<AuthorizationGrantType> authorizedGrantType();

    Set<String> scope();

    String owner();

    Integer accessTokenValiditySeconds();

    Integer refreshTokenValiditySeconds();

}
