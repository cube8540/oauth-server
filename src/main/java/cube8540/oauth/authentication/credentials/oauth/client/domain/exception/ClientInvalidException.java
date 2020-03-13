package cube8540.oauth.authentication.credentials.oauth.client.domain.exception;

import cube8540.oauth.authentication.error.message.ErrorCodes;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.exception.ValidateException;
import lombok.Getter;

import java.util.List;

@Getter
public class ClientInvalidException extends ValidateException {

    private final String code;

    private ClientInvalidException(String code, List<ValidationError> errors) {
        super(errors);
        this.code = code;
    }

    public static ClientInvalidException instance(List<ValidationError> errors) {
        return new ClientInvalidException(ErrorCodes.INVALID_REQUEST, errors);
    }

}
