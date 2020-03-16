package cube8540.oauth.authentication.credentials.authority.domain;

import cube8540.validator.core.ValidationRule;

public interface SecuredResourceValidationPolicy {

    ValidationRule<SecuredResource> resourceIdRule();

    ValidationRule<SecuredResource> resourceRule();

    ValidationRule<SecuredResource> methodRule();

    ValidationRule<SecuredResource> authoritiesRule();

}