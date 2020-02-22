package cube8540.oauth.authentication.users.error;

import lombok.Getter;

@Getter
public class UserNotFoundException extends RuntimeException {

    private String code;
    private String description;

    public UserNotFoundException(String description) {
        this.code = UserErrorCodes.NOT_FOUND;
        this.description = description;
    }
}
