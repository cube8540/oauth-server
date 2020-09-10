package cube8540.oauth.authentication.credentials.oauth.client.domain.exception;

import cube8540.oauth.authentication.error.ServiceException;
import cube8540.oauth.authentication.error.message.ErrorCodes;

public class ClientRegisterException extends ServiceException {

    public ClientRegisterException(String code, String description) {
        super(code, description);
    }

    public static ClientRegisterException existsIdentifier(String description) {
        return new ClientRegisterException(ErrorCodes.EXISTS_IDENTIFIER, description);
    }

}
