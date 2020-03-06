package cube8540.oauth.authentication.users.error;

import cube8540.oauth.authentication.error.message.ErrorCodes;

public interface UserErrorCodes extends ErrorCodes {

    String INVALID_PASSWORD = "invalid_password";

    String INVALID_KEY = "invalid_key";

    String KEY_EXPIRED = "key_expired";

    String ALREADY_CREDENTIALS = "already_credentials";

}
