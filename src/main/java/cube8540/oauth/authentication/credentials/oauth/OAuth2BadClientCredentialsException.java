package cube8540.oauth.authentication.credentials.oauth;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

public class OAuth2BadClientCredentialsException extends AbstractOAuth2AuthenticationException {

    public OAuth2BadClientCredentialsException() {
        this(null, null);
    }

    public OAuth2BadClientCredentialsException(String message) {
        this(message, null);
    }

    public OAuth2BadClientCredentialsException(Throwable cause) {
        this(null, cause);
    }

    public OAuth2BadClientCredentialsException(String message, Throwable cause) {
        super(401, new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT, message, null), message, cause);
    }
}
