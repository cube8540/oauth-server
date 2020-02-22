package cube8540.oauth.authentication.credentials.oauth.scope.error;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class ScopeRegisterException extends RuntimeException {

    private String code;
    private String description;

    public static ScopeRegisterException existsIdentifier(String description) {
        return new ScopeRegisterException(ScopeErrorCodes.EXISTS_IDENTIFIER, description);
    }

}
