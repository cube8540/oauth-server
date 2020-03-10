package cube8540.oauth.authentication.credentials.oauth.scope.error;

import cube8540.oauth.authentication.error.message.ErrorCodes;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class ScopeNotFoundException extends RuntimeException {

    private final String code;
    private final String description;

    public static ScopeNotFoundException instance(String description) {
        return new ScopeNotFoundException(ErrorCodes.NOT_FOUND, description);
    }
}
