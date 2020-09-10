package cube8540.oauth.authentication.users.domain.exception;

import cube8540.oauth.authentication.error.ServiceException;

public class UserAuthorizationException extends ServiceException {

    public UserAuthorizationException(String code, String description) {
        super(code, description);
    }

    public static UserAuthorizationException invalidPassword(String description) {
        return new UserAuthorizationException(UserErrorCodes.INVALID_PASSWORD, description);
    }

    public static UserAuthorizationException keyExpired(String description) {
        return new UserAuthorizationException(UserErrorCodes.KEY_EXPIRED, description);
    }

    public static UserAuthorizationException invalidKey(String description) {
        return new UserAuthorizationException(UserErrorCodes.INVALID_KEY, description);
    }

    public static UserAuthorizationException alreadyCredentials(String description) {
        return new UserAuthorizationException(UserErrorCodes.ALREADY_CREDENTIALS, description);
    }

}
