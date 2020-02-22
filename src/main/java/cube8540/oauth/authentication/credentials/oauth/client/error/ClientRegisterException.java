package cube8540.oauth.authentication.credentials.oauth.client.error;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class ClientRegisterException extends RuntimeException {

    private String code;
    private String description;

    public static ClientRegisterException existsIdentifier(String description) {
        return new ClientRegisterException(ClientErrorCodes.EXISTS_IDENTIFIER, description);
    }

}
