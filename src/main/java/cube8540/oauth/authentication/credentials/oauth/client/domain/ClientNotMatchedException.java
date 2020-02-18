package cube8540.oauth.authentication.credentials.oauth.client.domain;

public class ClientNotMatchedException extends RuntimeException {

    public ClientNotMatchedException(String message) {
        super(message);
    }

    public ClientNotMatchedException(String message, Throwable cause) {
        super(message, cause);
    }

}
