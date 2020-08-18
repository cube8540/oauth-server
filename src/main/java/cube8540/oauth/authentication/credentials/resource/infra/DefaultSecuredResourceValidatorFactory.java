package cube8540.oauth.authentication.credentials.resource.infra;

import cube8540.oauth.authentication.credentials.AuthorityDetailsService;
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResource;
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceValidatorFactory;
import cube8540.oauth.authentication.credentials.resource.infra.rule.SecuredResourceAuthoritiesRule;
import cube8540.oauth.authentication.credentials.resource.infra.rule.SecuredResourceIdRule;
import cube8540.oauth.authentication.credentials.resource.infra.rule.SecuredResourceMethodRule;
import cube8540.oauth.authentication.credentials.resource.infra.rule.SecuredResourceRule;
import cube8540.validator.core.Validator;
import lombok.Setter;

public class DefaultSecuredResourceValidatorFactory implements SecuredResourceValidatorFactory {

    @Setter
    private AuthorityDetailsService scopeAuthorityDetailsService;

    @Override
    public Validator<SecuredResource> createValidator(SecuredResource resource) {
        SecuredResourceAuthoritiesRule authoritiesRule = new SecuredResourceAuthoritiesRule();
        authoritiesRule.setScopeDetailsService(scopeAuthorityDetailsService);

        return Validator.of(resource).registerRule(new SecuredResourceIdRule())
                .registerRule(new SecuredResourceRule())
                .registerRule(new SecuredResourceMethodRule())
                .registerRule(authoritiesRule);
    }
}
