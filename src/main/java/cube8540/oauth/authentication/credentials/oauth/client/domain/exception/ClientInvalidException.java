package cube8540.oauth.authentication.credentials.oauth.client.domain.exception;

import cube8540.oauth.authentication.error.ServiceInvalidException;
import cube8540.oauth.authentication.error.message.ErrorCodes;
import cube8540.validator.core.ValidationError;

import java.util.Collection;
import java.util.List;

public class ClientInvalidException extends ServiceInvalidException {

    public ClientInvalidException(String code, Collection<ValidationError> errors) {
        super(code, errors);
    }

    public static ClientInvalidException instance(List<ValidationError> errors) {
        return new ClientInvalidException(ErrorCodes.INVALID_REQUEST, errors);
    }

}
