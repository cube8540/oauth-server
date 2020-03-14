package cube8540.oauth.authentication.credentials.authority.domain.exception;

import cube8540.oauth.authentication.error.message.ErrorCodes;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.exception.ValidateException;
import lombok.Getter;

import java.util.List;

@Getter
public class AuthorityInvalidException extends ValidateException {

    private final String code;

    private AuthorityInvalidException(String code, List<ValidationError> errors) {
        super(errors);
        this.code = code;
    }

    public static AuthorityInvalidException instance(List<ValidationError> errors) {
        return new AuthorityInvalidException(ErrorCodes.INVALID_REQUEST, errors);
    }
}
