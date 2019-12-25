package cube8540.oauth.authentication.users.domain.exception;

public class UserExpiredException extends RuntimeException {

    public UserExpiredException(String message) {
        super(message);
    }

}
