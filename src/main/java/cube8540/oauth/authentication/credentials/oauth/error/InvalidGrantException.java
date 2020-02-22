package cube8540.oauth.authentication.credentials.oauth.error;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

public class InvalidGrantException extends AbstractOAuth2AuthenticationException {

    private static final int HTTP_STATUS_CODE = 400;

    protected InvalidGrantException(String errorCode, String message) {
        super(HTTP_STATUS_CODE, new OAuth2Error(errorCode, message, null));
    }

    public static InvalidGrantException invalidGrant(String message) {
        return new InvalidGrantException(OAuth2ErrorCodes.INVALID_GRANT, message);
    }

    public static InvalidGrantException invalidScope(String message) {
        return new InvalidGrantException(OAuth2ErrorCodes.INVALID_SCOPE, message);
    }

    public static InvalidGrantException unsupportedGrantType(String message) {
        return new InvalidGrantException(OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE, message);
    }
}
