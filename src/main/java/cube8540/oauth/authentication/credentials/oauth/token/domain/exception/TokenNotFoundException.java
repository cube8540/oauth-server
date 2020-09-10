package cube8540.oauth.authentication.credentials.oauth.token.domain.exception;

import cube8540.oauth.authentication.error.ServiceException;
import cube8540.oauth.authentication.error.message.ErrorCodes;

public class TokenNotFoundException extends ServiceException {

    public TokenNotFoundException(String code, String description) {
        super(code, description);
    }

    public static TokenNotFoundException instance(String description) {
        return new TokenNotFoundException(ErrorCodes.NOT_FOUND, description);
    }
}
