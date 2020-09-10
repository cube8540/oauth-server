package cube8540.oauth.authentication.credentials.resource.domain.exception;

import cube8540.oauth.authentication.error.ServiceInvalidException;
import cube8540.oauth.authentication.error.message.ErrorCodes;
import cube8540.validator.core.ValidationError;

import java.util.Collection;
import java.util.List;

public class ResourceInvalidException extends ServiceInvalidException {

    public ResourceInvalidException(String code, Collection<ValidationError> errors) {
        super(code, errors);
    }

    public static ResourceInvalidException instance(List<ValidationError> errors) {
        return new ResourceInvalidException(ErrorCodes.INVALID_REQUEST, errors);
    }

}
