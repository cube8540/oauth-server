package cube8540.oauth.authentication.credentials.oauth.client.domain;

public class ClientOwnerNotMatchedException extends RuntimeException {

    public ClientOwnerNotMatchedException(String message) {
        super(message);
    }

    public ClientOwnerNotMatchedException(String message, Throwable cause) {
        super(message, cause);
    }

}
