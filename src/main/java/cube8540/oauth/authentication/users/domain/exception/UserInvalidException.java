package cube8540.oauth.authentication.users.domain.exception;

import cube8540.validator.core.ValidationError;
import cube8540.validator.core.exception.ValidateException;
import lombok.Getter;

import java.util.List;

@Getter
public class UserInvalidException extends ValidateException {

    private final String code;

    private UserInvalidException(String code, List<ValidationError> errors) {
        super(errors);
        this.code = code;
    }

    public static UserInvalidException instance(List<ValidationError> errors) {
        return new UserInvalidException(UserErrorCodes.INVALID_REQUEST, errors);
    }

}
