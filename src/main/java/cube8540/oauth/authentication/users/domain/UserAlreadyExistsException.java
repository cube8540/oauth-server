package cube8540.oauth.authentication.users.domain;

public class UserAlreadyExistsException extends UserRegistrationException {
    public UserAlreadyExistsException(String message) {
        super(message);
    }

    public UserAlreadyExistsException(String message, Throwable cause) {
        super(message, cause);
    }
}
