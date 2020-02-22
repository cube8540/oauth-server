package cube8540.oauth.authentication.credentials.oauth.scope.error;

import cube8540.validator.core.ValidationError;
import cube8540.validator.core.exception.ValidateException;
import lombok.Getter;

import java.util.List;

@Getter
public class ScopeInvalidException extends ValidateException {

    private String code;

    public ScopeInvalidException(List<ValidationError> errors) {
        super(errors);
        this.code = ScopeErrorCodes.INVALID_REQUEST;
    }

}
