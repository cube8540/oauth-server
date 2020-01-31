package cube8540.oauth.authentication.users.domain;

public class UserNotFoundException extends UserRegistrationException {
    public UserNotFoundException(String message) {
        super(message);
    }

    public UserNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
