package cube8540.oauth.authentication.credentials.oauth.token.domain;

public class OAuth2AccessTokenNotFoundException extends OAuth2AccessTokenRegistrationException {
    public OAuth2AccessTokenNotFoundException(String message) {
        super(message);
    }

    public OAuth2AccessTokenNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
