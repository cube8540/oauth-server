package cube8540.oauth.authentication.users.domain.exception;

import cube8540.oauth.authentication.error.ServiceException;

public class UserRegisterException extends ServiceException {

    public UserRegisterException(String code, String description) {
        super(code, description);
    }

    public static UserRegisterException existsIdentifier(String description) {
        return new UserRegisterException(UserErrorCodes.EXISTS_IDENTIFIER, description);
    }
}
