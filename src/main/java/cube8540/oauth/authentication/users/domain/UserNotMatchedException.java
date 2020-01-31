package cube8540.oauth.authentication.users.domain;

public class UserNotMatchedException extends UserCertificationException {
    public UserNotMatchedException(String message) {
        super(message);
    }

    public UserNotMatchedException(String message, Throwable cause) {
        super(message, cause);
    }
}
