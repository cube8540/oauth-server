package cube8540.oauth.authentication.credentials.oauth.scope.error;

import cube8540.oauth.authentication.error.message.ErrorCodes;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.exception.ValidateException;
import lombok.Getter;

import java.util.List;

@Getter
public class ScopeInvalidException extends ValidateException {

    private final String code;

    public ScopeInvalidException(String code, List<ValidationError> errors) {
        super(errors);
        this.code = code;
    }

    public static ScopeInvalidException instance(List<ValidationError> errors) {
        return new ScopeInvalidException(ErrorCodes.INVALID_REQUEST, errors);
    }

}
