package cube8540.oauth.authentication.credentials.role.domain.exception;

import cube8540.oauth.authentication.error.message.ErrorCodes;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class RoleRegisterException extends RuntimeException {

    private final String code;
    private final String description;

    public static RoleRegisterException existsIdentifier(String description) {
        return new RoleRegisterException(ErrorCodes.EXISTS_IDENTIFIER, description);
    }
}
