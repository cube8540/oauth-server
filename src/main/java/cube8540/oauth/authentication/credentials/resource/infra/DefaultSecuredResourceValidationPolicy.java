package cube8540.oauth.authentication.credentials.resource.infra;

import cube8540.oauth.authentication.credentials.AuthorityDetailsService;
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResource;
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceValidationPolicy;
import cube8540.oauth.authentication.credentials.resource.infra.rule.SecuredResourceAuthoritiesRule;
import cube8540.oauth.authentication.credentials.resource.infra.rule.SecuredResourceIdRule;
import cube8540.oauth.authentication.credentials.resource.infra.rule.SecuredResourceMethodRule;
import cube8540.oauth.authentication.credentials.resource.infra.rule.SecuredResourceRule;
import cube8540.validator.core.ValidationRule;
import lombok.Setter;

public class DefaultSecuredResourceValidationPolicy implements SecuredResourceValidationPolicy {

    @Setter
    private AuthorityDetailsService scopeAuthorityDetailsService;

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
    public ValidationRule<SecuredResource> scopeAuthoritiesRule() {
        SecuredResourceAuthoritiesRule validationRule = new SecuredResourceAuthoritiesRule();
        validationRule.setScopeDetailsService(scopeAuthorityDetailsService);
        return validationRule;
    }
}
