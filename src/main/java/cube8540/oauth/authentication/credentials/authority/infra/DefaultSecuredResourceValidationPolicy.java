package cube8540.oauth.authentication.credentials.authority.infra;

import cube8540.oauth.authentication.credentials.authority.domain.SecuredResource;
import cube8540.oauth.authentication.credentials.authority.domain.SecuredResourceValidationPolicy;
import cube8540.oauth.authentication.credentials.authority.infra.rule.SecuredResourceIdRule;
import cube8540.oauth.authentication.credentials.authority.infra.rule.SecuredResourceMethodRule;
import cube8540.oauth.authentication.credentials.authority.infra.rule.SecuredResourceRule;
import cube8540.validator.core.ValidationRule;

public class DefaultSecuredResourceValidationPolicy implements SecuredResourceValidationPolicy {
    @Override
    public ValidationRule<SecuredResource> resourceIdRule() {
        return new SecuredResourceIdRule();
    }

    @Override
    public ValidationRule<SecuredResource> resourceRule() {
        return new SecuredResourceRule();
    }

    @Override
    public ValidationRule<SecuredResource> methodRule() {
        return new SecuredResourceMethodRule();
    }

    @Override
    public ValidationRule<SecuredResource> authoritiesRule() {
        return null;
    }
}
