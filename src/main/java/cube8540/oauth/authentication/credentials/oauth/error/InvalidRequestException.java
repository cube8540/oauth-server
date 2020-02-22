package cube8540.oauth.authentication.credentials.oauth.error;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

public class InvalidRequestException extends AbstractOAuth2AuthenticationException {

    private static final int HTTP_STATUS_CODE = 400;

    private InvalidRequestException(String errorCode, String description) {
        super(HTTP_STATUS_CODE, new OAuth2Error(errorCode, description, null));
    }

    public static InvalidRequestException invalidRequest(String message) {
        return new InvalidRequestException(OAuth2ErrorCodes.INVALID_REQUEST, message);
    }

    public static InvalidRequestException unsupportedResponseType(String message) {
        return new InvalidRequestException(OAuth2ErrorCodes.UNSUPPORTED_RESPONSE_TYPE, message);
    }

}
