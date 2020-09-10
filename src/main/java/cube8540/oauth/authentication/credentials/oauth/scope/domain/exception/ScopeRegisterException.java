package cube8540.oauth.authentication.credentials.oauth.scope.domain.exception;

import cube8540.oauth.authentication.error.ServiceException;
import cube8540.oauth.authentication.error.message.ErrorCodes;

public class ScopeRegisterException extends ServiceException {

    public ScopeRegisterException(String code, String description) {
        super(code, description);
    }

    public static ScopeRegisterException existsIdentifier(String description) {
        return new ScopeRegisterException(ErrorCodes.EXISTS_IDENTIFIER, description);
    }

}
