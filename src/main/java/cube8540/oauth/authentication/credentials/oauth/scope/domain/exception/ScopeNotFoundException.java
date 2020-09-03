package cube8540.oauth.authentication.credentials.oauth.scope.domain.exception;

import cube8540.oauth.authentication.error.ServiceException;
import cube8540.oauth.authentication.error.message.ErrorCodes;

public class ScopeNotFoundException extends ServiceException {

    public ScopeNotFoundException(String code, String description) {
        super(code, description);
    }

    public static ScopeNotFoundException instance(String description) {
        return new ScopeNotFoundException(ErrorCodes.NOT_FOUND, description);
    }
}
