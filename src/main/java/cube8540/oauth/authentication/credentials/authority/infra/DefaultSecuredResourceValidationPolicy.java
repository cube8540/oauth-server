package cube8540.oauth.authentication.credentials.authority.infra;

import cube8540.oauth.authentication.credentials.authority.AuthorityDetailsService;
import cube8540.oauth.authentication.credentials.authority.domain.SecuredResource;
import cube8540.oauth.authentication.credentials.authority.domain.SecuredResourceValidationPolicy;
import cube8540.oauth.authentication.credentials.authority.infra.rule.SecuredResourceAuthoritiesRule;
import cube8540.oauth.authentication.credentials.authority.infra.rule.SecuredResourceIdRule;
import cube8540.oauth.authentication.credentials.authority.infra.rule.SecuredResourceMethodRule;
import cube8540.oauth.authentication.credentials.authority.infra.rule.SecuredResourceRule;
import cube8540.validator.core.ValidationRule;
import lombok.Setter;

public class DefaultSecuredResourceValidationPolicy implements SecuredResourceValidationPolicy {

    @Setter
    private AuthorityDetailsService authorityDetailsService;

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
        SecuredResourceAuthoritiesRule validationRule = new SecuredResourceAuthoritiesRule();
        validationRule.setAuthorityDetailsService(authorityDetailsService);
        return validationRule;
    }
}
