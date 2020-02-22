package cube8540.oauth.authentication.users.error;

import cube8540.validator.core.ValidationError;
import cube8540.validator.core.exception.ValidateException;
import lombok.Getter;

import java.util.List;

@Getter
public class UserInvalidException extends ValidateException {

    private String code;

    public UserInvalidException(List<ValidationError> errors) {
        super(errors);
        this.code = UserErrorCodes.INVALID_REQUEST;
    }

}
