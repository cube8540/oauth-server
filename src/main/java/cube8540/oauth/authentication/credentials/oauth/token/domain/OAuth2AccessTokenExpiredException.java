package cube8540.oauth.authentication.credentials.oauth.token.domain;

import cube8540.oauth.authentication.credentials.oauth.error.OAuth2AccessTokenRegistrationException;

public class OAuth2AccessTokenExpiredException extends OAuth2AccessTokenRegistrationException {
    public OAuth2AccessTokenExpiredException(String message) {
        super(message);
    }

    public OAuth2AccessTokenExpiredException(String message, Throwable cause) {
        super(message, cause);
    }
}
