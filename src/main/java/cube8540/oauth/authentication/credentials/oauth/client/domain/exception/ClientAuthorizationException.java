package cube8540.oauth.authentication.credentials.oauth.client.domain.exception;

import cube8540.oauth.authentication.error.ServiceException;

public class ClientAuthorizationException extends ServiceException {

    public ClientAuthorizationException(String code, String description) {
        super(code, description);
    }

    public static ClientAuthorizationException invalidPassword(String description) {
        return new ClientAuthorizationException(ClientErrorCodes.INVALID_PASSWORD, description);
    }

}
