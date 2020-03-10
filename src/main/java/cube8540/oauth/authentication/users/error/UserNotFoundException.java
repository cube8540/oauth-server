package cube8540.oauth.authentication.users.error;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class UserNotFoundException extends RuntimeException {

    private final String code;
    private final String description;

    public static UserNotFoundException instance(String description) {
        return new UserNotFoundException(UserErrorCodes.NOT_FOUND, description);
    }
}
