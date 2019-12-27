package cube8540.oauth.authentication.credentials.oauth.client.domain;

public class OAuth2ClientNotFoundException extends OAuth2ClientRegistrationException {
    public OAuth2ClientNotFoundException(String message) {
        super(message);
    }

    public OAuth2ClientNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
