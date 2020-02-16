package cube8540.oauth.authentication.credentials.authority.domain;

public class AuthorityAlreadyException extends RuntimeException {

    public AuthorityAlreadyException(String message) {
        super(message);
    }

    public AuthorityAlreadyException(String message, Throwable cause) {
        super(message, cause);
    }

}
