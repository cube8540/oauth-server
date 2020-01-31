package cube8540.oauth.authentication.users.domain;

public class UserExpiredException extends UserCertificationException {
    public UserExpiredException(String message) {
        super(message);
    }

    public UserExpiredException(String message, Throwable cause) {
        super(message, cause);
    }
}
