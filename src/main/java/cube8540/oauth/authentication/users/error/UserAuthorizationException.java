package cube8540.oauth.authentication.users.error;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class UserAuthorizationException extends RuntimeException {

    private String code;
    private String description;

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
