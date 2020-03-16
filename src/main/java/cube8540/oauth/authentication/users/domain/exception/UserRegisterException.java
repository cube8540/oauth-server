package cube8540.oauth.authentication.users.domain.exception;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class UserRegisterException extends RuntimeException {

    private final String code;
    private final String description;

    public static UserRegisterException existsIdentifier(String description) {
        return new UserRegisterException(UserErrorCodes.EXISTS_IDENTIFIER, description);
    }
}
