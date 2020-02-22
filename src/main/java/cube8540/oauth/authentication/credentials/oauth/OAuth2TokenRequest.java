package cube8540.oauth.authentication.credentials.oauth;

import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.net.URI;
import java.util.Set;

public interface OAuth2TokenRequest {

    AuthorizationGrantType grantType();

    String username();

    String password();

    String clientId();

    String refreshToken();

    String code();

    String state();

    URI redirectURI();

    Set<String> scopes();
}
