package cube8540.oauth.authentication.credentials.oauth.security;

import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.net.URI;
import java.util.Set;

public interface OAuth2TokenRequest {

    AuthorizationGrantType getGrantType();

    String getUsername();

    String getPassword();

    String getClientId();

    String getRefreshToken();

    String getCode();

    String getState();

    URI getRedirectUri();

    Set<String> getScopes();
}
