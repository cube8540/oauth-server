package cube8540.oauth.authentication.users.domain.exception;

import cube8540.oauth.authentication.error.ServiceInvalidException;
import cube8540.validator.core.ValidationError;

import java.util.List;

public class UserInvalidException extends ServiceInvalidException {

    private UserInvalidException(String code, List<ValidationError> errors) {
        super(code, errors);
    }

    public static UserInvalidException instance(List<ValidationError> errors) {
        return new UserInvalidException(UserErrorCodes.INVALID_REQUEST, errors);
    }

}
