package cube8540.oauth.authentication.credentials.oauth.scope.domain;

public class OAuth2ScopeNotFoundException extends RuntimeException {

    public OAuth2ScopeNotFoundException(String message) {
        super(message);
    }

    public OAuth2ScopeNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }

}
