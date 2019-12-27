package cube8540.oauth.authentication.users.domain;

public class UserCertificationException extends RuntimeException {
    public UserCertificationException(String message) {
        super(message);
    }

    public UserCertificationException(String message, Throwable cause) {
        super(message, cause);
    }
}
