package cube8540.oauth.authentication.credentials.oauth.error;

import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

public class RedirectMismatchException extends InvalidGrantException {

    public RedirectMismatchException(String message) {
        super(OAuth2ErrorCodes.INVALID_GRANT, message);
    }

}
