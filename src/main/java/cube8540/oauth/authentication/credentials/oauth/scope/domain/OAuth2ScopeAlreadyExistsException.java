package cube8540.oauth.authentication.credentials.oauth.scope.domain;

public class OAuth2ScopeAlreadyExistsException extends RuntimeException {

    public OAuth2ScopeAlreadyExistsException(String message) {
        super(message);
    }

    public OAuth2ScopeAlreadyExistsException(String message, Throwable cause) {
        super(message, cause);
    }

}
