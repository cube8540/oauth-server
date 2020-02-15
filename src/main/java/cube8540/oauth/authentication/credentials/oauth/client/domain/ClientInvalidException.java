package cube8540.oauth.authentication.credentials.oauth.client.domain;

import cube8540.validator.core.ValidationError;
import cube8540.validator.core.exception.ValidateException;

import java.util.List;

public class ClientInvalidException extends ValidateException {
    public ClientInvalidException(List<ValidationError> errors) {
        super(errors);
    }
}
