package cube8540.oauth.authentication.credentials.oauth.scope.domain;

import cube8540.validator.core.Validator;

public interface OAuth2ScopeValidatorFactory {

    Validator<OAuth2Scope> createValidator(OAuth2Scope scope);

}
