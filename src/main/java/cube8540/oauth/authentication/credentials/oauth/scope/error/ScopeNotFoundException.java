package cube8540.oauth.authentication.credentials.oauth.scope.error;

import lombok.Getter;

@Getter
public class ScopeNotFoundException extends RuntimeException {

    private String code;
    private String description;

    public ScopeNotFoundException(String description) {
        this.code = ScopeErrorCodes.NOT_FOUND;
        this.description = description;
    }
}
