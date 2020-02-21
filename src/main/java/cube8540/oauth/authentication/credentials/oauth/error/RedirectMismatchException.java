package cube8540.oauth.authentication.credentials.oauth.error;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

public class RedirectMismatchException extends AbstractOAuth2AuthenticationException {

    private static final int HTTP_STATUS_CODE = 400;

    public RedirectMismatchException(String message) {
        super(HTTP_STATUS_CODE, new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, message, null));
    }

}
