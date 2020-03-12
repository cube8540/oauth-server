package cube8540.oauth.authentication.credentials.authority.error;

import cube8540.oauth.authentication.error.message.ErrorCodes;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class ResourceRegisterException extends RuntimeException {

    private final String code;
    private final String description;

    public static ResourceRegisterException existsIdentifier(String description) {
        return new ResourceRegisterException(ErrorCodes.EXISTS_IDENTIFIER, description);
    }
}
