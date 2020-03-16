package cube8540.oauth.authentication.users.domain.exception;

import cube8540.oauth.authentication.error.message.ErrorCodes;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class UserErrorCodes extends ErrorCodes {

    public static final String INVALID_PASSWORD = "invalid_password";

    public static final String INVALID_KEY = "invalid_key";

    public static final String KEY_EXPIRED = "key_expired";

    public static final String ALREADY_CREDENTIALS = "already_credentials";

}
