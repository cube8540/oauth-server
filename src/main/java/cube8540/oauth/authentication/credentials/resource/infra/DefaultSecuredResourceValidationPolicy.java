package cube8540.oauth.authentication.credentials.resource.infra;

import cube8540.oauth.authentication.credentials.AuthorityDetailsService;
import cube8540.oauth.authentication.credentials.resource.domain.AccessibleAuthority;
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

    @Setter
    private AuthorityDetailsService roleAuthorityDetailsService;

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
        SecuredResourceAuthoritiesRule validationRule = new SecuredResourceAuthoritiesRule(AccessibleAuthority.AuthorityType.OAUTH2_SCOPE);
        validationRule.setScopeDetailsService(scopeAuthorityDetailsService);
        return validationRule;
    }

    @Override
    public ValidationRule<SecuredResource> roleAuthoritiesRule() {
        SecuredResourceAuthoritiesRule validationRule = new SecuredResourceAuthoritiesRule(AccessibleAuthority.AuthorityType.AUTHORITY);
        validationRule.setScopeDetailsService(roleAuthorityDetailsService);
        return validationRule;
    }
}
