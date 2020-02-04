package cube8540.oauth.authentication.credentials.oauth.error;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

public class UserDeniedAuthorizationException extends AbstractOAuth2AuthenticationException {

    private static final int HTTP_STATUS = 403;

    public UserDeniedAuthorizationException() {
        super(HTTP_STATUS, new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED));
    }

    public UserDeniedAuthorizationException(String message) {
        super(HTTP_STATUS, new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED, message, null));
    }

    public UserDeniedAuthorizationException(Throwable cause) {
        super(HTTP_STATUS, new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED), cause);
    }

    public UserDeniedAuthorizationException(String message, Throwable cause) {
        super(HTTP_STATUS, new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED, message, null), cause);
    }

}
