package cube8540.oauth.authentication.credentials.oauth.client.domain;

public class OAuth2ClientAlreadyExistsException extends OAuth2ClientRegistrationException {
    public OAuth2ClientAlreadyExistsException(String message) {
        super(message);
    }

    public OAuth2ClientAlreadyExistsException(String message, Throwable cause) {
        super(message, cause);
    }
}
