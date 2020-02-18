package cube8540.oauth.authentication.credentials.oauth.scope.domain;

import cube8540.validator.core.ValidationError;
import cube8540.validator.core.exception.ValidateException;

import java.util.List;

public class OAuth2ScopeInvalidException extends ValidateException {

    public OAuth2ScopeInvalidException(List<ValidationError> errors) {
        super(errors);
    }

}
