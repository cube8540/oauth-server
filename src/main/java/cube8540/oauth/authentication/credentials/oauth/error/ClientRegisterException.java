package cube8540.oauth.authentication.credentials.oauth.error;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class ClientRegisterException extends RuntimeException {

    private final String code;
    private final String description;

    public static ClientRegisterException existsIdentifier(String description) {
        return new ClientRegisterException(ClientErrorCodes.EXISTS_IDENTIFIER, description);
    }

}
