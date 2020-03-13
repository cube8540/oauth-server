package cube8540.oauth.authentication.credentials.oauth.error;

public class OAuth2AccessTokenRegistrationException extends RuntimeException {
    public OAuth2AccessTokenRegistrationException(String message) {
        super(message);
    }

    public OAuth2AccessTokenRegistrationException(String message, Throwable cause) {
        super(message, cause);
    }
}
