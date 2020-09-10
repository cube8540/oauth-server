package cube8540.oauth.authentication.credentials.oauth.client.domain.exception;

import cube8540.oauth.authentication.error.ServiceException;
import cube8540.oauth.authentication.error.message.ErrorCodes;

public class ClientNotFoundException extends ServiceException {

    public ClientNotFoundException(String code, String description) {
        super(code, description);
    }

    public static ClientNotFoundException instance(String description) {
        return new ClientNotFoundException(ErrorCodes.NOT_FOUND, description);
    }
}
