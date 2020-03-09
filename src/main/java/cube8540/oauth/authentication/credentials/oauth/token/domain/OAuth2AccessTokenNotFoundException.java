package cube8540.oauth.authentication.credentials.oauth.token.domain;

public class OAuth2AccessTokenNotFoundException extends OAuth2AccessTokenRegistrationException {
    public OAuth2AccessTokenNotFoundException(String accessToken) {
        super(accessToken + " is not found");
    }

    public OAuth2AccessTokenNotFoundException(String accessToken, Throwable cause) {
        super(accessToken + " is not found", cause);
    }
}
