package cube8540.oauth.authentication.credentials.oauth.error;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

public class UnsupportedResponseTypeException extends AbstractOAuth2AuthenticationException {

    private static final int HTTP_STATUS = 401;

    public UnsupportedResponseTypeException(String message) {
        super(HTTP_STATUS, new OAuth2Error(OAuth2ErrorCodes.UNSUPPORTED_RESPONSE_TYPE, message, null));
    }
}
