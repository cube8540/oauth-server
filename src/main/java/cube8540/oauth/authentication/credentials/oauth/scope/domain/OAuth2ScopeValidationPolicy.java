package cube8540.oauth.authentication.credentials.oauth.scope.domain;

import cube8540.validator.core.ValidationRule;

public interface OAuth2ScopeValidationPolicy {

    ValidationRule<OAuth2Scope> scopeIdRule();

    ValidationRule<OAuth2Scope> accessibleRule();

}
