package cube8540.oauth.authentication.credentials.oauth.token.domain.exception;

import cube8540.oauth.authentication.error.ServiceException;
import cube8540.oauth.authentication.error.message.ErrorCodes;

public class TokenAccessDeniedException extends ServiceException {

    public TokenAccessDeniedException(String code, String description) {
        super(code, description);
    }

    public static TokenAccessDeniedException denied(String description) {
        return new TokenAccessDeniedException(ErrorCodes.ACCESS_DENIED, description);
    }

}
