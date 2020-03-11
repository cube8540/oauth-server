package cube8540.oauth.authentication.credentials.authority.error;

import cube8540.oauth.authentication.error.message.ErrorCodes;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.exception.ValidateException;
import lombok.Getter;

import java.util.List;

@Getter
public class ResourceInvalidException extends ValidateException {

    private String code;

    private ResourceInvalidException(String code, List<ValidationError> errors) {
        super(errors);
        this.code = code;
    }

    public static ResourceInvalidException instance(List<ValidationError> errors) {
        return new ResourceInvalidException(ErrorCodes.INVALID_REQUEST, errors);
    }

}
