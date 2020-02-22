package cube8540.oauth.authentication.credentials.oauth.client.error;

import cube8540.validator.core.ValidationError;
import cube8540.validator.core.exception.ValidateException;
import lombok.Getter;

import java.util.List;

@Getter
public class ClientInvalidException extends ValidateException {

    private String code;

    public ClientInvalidException(List<ValidationError> errors) {
        super(errors);
        this.code = ClientErrorCodes.INVALID_REQUEST;
    }

}
