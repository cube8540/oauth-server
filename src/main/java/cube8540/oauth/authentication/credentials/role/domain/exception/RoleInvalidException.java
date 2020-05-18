package cube8540.oauth.authentication.credentials.role.domain.exception;

import cube8540.oauth.authentication.error.message.ErrorCodes;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.exception.ValidateException;
import lombok.Getter;

import java.util.List;

@Getter
public class RoleInvalidException extends ValidateException {

    private final String code;

    public RoleInvalidException(String code, List<ValidationError> errors) {
        super(errors);
        this.code = code;
    }

    public static RoleInvalidException instance(List<ValidationError> errors) {
        return new RoleInvalidException(ErrorCodes.INVALID_REQUEST, errors);
    }

}
