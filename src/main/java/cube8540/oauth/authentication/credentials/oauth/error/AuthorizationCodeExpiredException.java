package cube8540.oauth.authentication.credentials.oauth.error;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

public class AuthorizationCodeExpiredException extends AbstractOAuth2AuthenticationException {

    private static final int HTTP_STATUS_CODE = 400;

    public AuthorizationCodeExpiredException() {
        super(HTTP_STATUS_CODE, new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT));
    }

    public AuthorizationCodeExpiredException(String message) {
        super(HTTP_STATUS_CODE, new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, message, null));
    }

    public AuthorizationCodeExpiredException(Throwable cause) {
        super(HTTP_STATUS_CODE, new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT), null);
    }

    public AuthorizationCodeExpiredException(String message, Throwable cause) {
        super(HTTP_STATUS_CODE, new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, message, null), cause);
    }
}
