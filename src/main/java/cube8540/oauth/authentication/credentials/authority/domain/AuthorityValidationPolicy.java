package cube8540.oauth.authentication.credentials.authority.domain;

import cube8540.validator.core.ValidationRule;

public interface AuthorityValidationPolicy {

    ValidationRule<Authority> codeRule();

    ValidationRule<Authority> accessibleResourceRule();

}
