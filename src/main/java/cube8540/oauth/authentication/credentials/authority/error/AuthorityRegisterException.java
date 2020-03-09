package cube8540.oauth.authentication.credentials.authority.error;

import cube8540.oauth.authentication.error.message.ErrorCodes;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class AuthorityRegisterException extends RuntimeException {

    private final String code;
    private final String description;

    public static AuthorityRegisterException existsIdentifier(String description) {
        return new AuthorityRegisterException(ErrorCodes.EXISTS_IDENTIFIER, description);
    }
}
