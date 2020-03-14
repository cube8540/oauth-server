package cube8540.oauth.authentication.credentials.authority.infra;

import cube8540.oauth.authentication.credentials.authority.application.SecuredResourceReadService;
import cube8540.oauth.authentication.credentials.authority.domain.Authority;
import cube8540.oauth.authentication.credentials.authority.domain.AuthorityValidationPolicy;
import cube8540.oauth.authentication.credentials.authority.infra.rule.AccessibleResourceRule;
import cube8540.oauth.authentication.credentials.authority.infra.rule.AuthorityCodeRule;
import cube8540.validator.core.ValidationRule;
import lombok.Setter;

public class DefaultAuthorityValidationPolicy implements AuthorityValidationPolicy {

    @Setter
    private SecuredResourceReadService securedResourceReadService;

    @Override
    public ValidationRule<Authority> codeRule() {
        return new AuthorityCodeRule();
    }

    @Override
    public ValidationRule<Authority> accessibleResourceRule() {
        AccessibleResourceRule resourceRule =  new AccessibleResourceRule();
        resourceRule.setSecuredResourceReadService(securedResourceReadService);
        return resourceRule;
    }
}
