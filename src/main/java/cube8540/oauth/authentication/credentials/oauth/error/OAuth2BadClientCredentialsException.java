package cube8540.oauth.authentication.credentials.oauth.error;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

public class OAuth2BadClientCredentialsException extends AbstractOAuth2AuthenticationException {

    private static final int HTTP_STATUS_CODE = 401;

    public OAuth2BadClientCredentialsException() {
        super(HTTP_STATUS_CODE, new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT));
    }

    public OAuth2BadClientCredentialsException(String message) {
        super(HTTP_STATUS_CODE, new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT, message, null));
    }

    public OAuth2BadClientCredentialsException(Throwable cause) {
        super(HTTP_STATUS_CODE, new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT), cause);
    }

    public OAuth2BadClientCredentialsException(String message, Throwable cause) {
        super(HTTP_STATUS_CODE, new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT, message, null), cause);
    }
}
