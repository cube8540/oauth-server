package cube8540.oauth.authentication.credentials.oauth.error;

public class OAuth2ClientRegistrationException extends RuntimeException {
    public OAuth2ClientRegistrationException(String message) {
        super(message);
    }

    public OAuth2ClientRegistrationException(String message, Throwable cause) {
        super(message, cause);
    }
}
