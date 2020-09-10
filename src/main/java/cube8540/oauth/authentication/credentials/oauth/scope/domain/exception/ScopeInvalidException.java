package cube8540.oauth.authentication.credentials.oauth.scope.domain.exception;

import cube8540.oauth.authentication.error.ServiceInvalidException;
import cube8540.oauth.authentication.error.message.ErrorCodes;
import cube8540.validator.core.ValidationError;

import java.util.Collection;
import java.util.List;

public class ScopeInvalidException extends ServiceInvalidException {

    public ScopeInvalidException(String code, Collection<ValidationError> errors) {
        super(code, errors);
    }

    public static ScopeInvalidException instance(List<ValidationError> errors) {
        return new ScopeInvalidException(ErrorCodes.INVALID_REQUEST, errors);
    }

}
