package cube8540.oauth.authentication.credentials.oauth.client.domain;

public class InvalidAuthorizationGrantTypeException extends RuntimeException {

    public InvalidAuthorizationGrantTypeException(String message) {
        super(message);
    }

    public InvalidAuthorizationGrantTypeException(String message, Throwable cause) {
        super(message, cause);
    }

}
