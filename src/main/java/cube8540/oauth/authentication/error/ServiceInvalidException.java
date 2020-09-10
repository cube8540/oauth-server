package cube8540.oauth.authentication.error;

import cube8540.validator.core.ValidationError;
import cube8540.validator.core.exception.ValidateException;
import lombok.Getter;

import java.util.Collection;

@Getter
public class ServiceInvalidException extends ValidateException {

    private final String code;

    public ServiceInvalidException(String code, ValidationError... errors) {
        super(errors);
        this.code = code;
    }

    public ServiceInvalidException(String code, Collection<ValidationError> errors) {
        super(errors);
        this.code = code;
    }

}
