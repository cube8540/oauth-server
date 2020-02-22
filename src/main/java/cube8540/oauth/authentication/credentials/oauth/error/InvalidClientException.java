package cube8540.oauth.authentication.credentials.oauth.error;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

public class InvalidClientException extends AbstractOAuth2AuthenticationException {

    private static final int HTTP_STATUS_CODE = 401;

    private InvalidClientException(String errorCode, String message) {
        super(HTTP_STATUS_CODE, new OAuth2Error(errorCode, message, null));
    }

    public static InvalidClientException invalidClient(String message) {
        return new InvalidClientException(OAuth2ErrorCodes.INVALID_CLIENT, message);
    }

    public static InvalidClientException unauthorizedClient(String message) {
        return new InvalidClientException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, message);
    }

}
