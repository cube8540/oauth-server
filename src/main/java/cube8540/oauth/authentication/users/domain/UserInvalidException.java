package cube8540.oauth.authentication.users.domain;

import cube8540.validator.core.ValidationError;
import cube8540.validator.core.exception.ValidateException;

import java.util.List;

public class UserInvalidException extends ValidateException {
    public UserInvalidException(List<ValidationError> messages) {
        super(messages);
    }
}
