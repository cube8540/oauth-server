package cube8540.oauth.authentication.credentials.oauth.error;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

public class InvalidClientException extends AbstractOAuth2AuthenticationException {

    private static final int HTTP_STATUS_CODE = 401;

    public InvalidClientException() {
        super(HTTP_STATUS_CODE, new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT));
    }

    public InvalidClientException(String message) {
        super(HTTP_STATUS_CODE, new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT, message, null));
    }

    public InvalidClientException(Throwable cause) {
        super(HTTP_STATUS_CODE, new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT), cause);
    }

    public InvalidClientException(String message, Throwable cause) {
        super(HTTP_STATUS_CODE, new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT, message, null), cause);
    }

}
