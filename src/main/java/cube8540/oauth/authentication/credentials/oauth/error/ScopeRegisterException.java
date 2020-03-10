package cube8540.oauth.authentication.credentials.oauth.error;

import cube8540.oauth.authentication.error.message.ErrorCodes;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class ScopeRegisterException extends RuntimeException {

    private final String code;
    private final String description;

    public static ScopeRegisterException existsIdentifier(String description) {
        return new ScopeRegisterException(ErrorCodes.EXISTS_IDENTIFIER, description);
    }

}
