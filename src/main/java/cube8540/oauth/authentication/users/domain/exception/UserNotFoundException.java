package cube8540.oauth.authentication.users.domain.exception;

import cube8540.oauth.authentication.error.ServiceException;

public class UserNotFoundException extends ServiceException {

    public UserNotFoundException(String code, String description) {
        super(code, description);
    }

    public static UserNotFoundException instance(String description) {
        return new UserNotFoundException(UserErrorCodes.NOT_FOUND, description);
    }
}
