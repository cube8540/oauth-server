package cube8540.oauth.authentication.users.domain;

public class UserAlreadyCertificationException extends UserCertificationException {
    public UserAlreadyCertificationException(String message) {
        super(message);
    }

    public UserAlreadyCertificationException(String message, Throwable cause) {
        super(message, cause);
    }
}
