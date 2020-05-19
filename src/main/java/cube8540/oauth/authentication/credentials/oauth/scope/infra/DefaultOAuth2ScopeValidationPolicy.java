package cube8540.oauth.authentication.credentials.oauth.scope.infra;

import cube8540.oauth.authentication.credentials.AuthorityDetailsService;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2Scope;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeValidationPolicy;
import cube8540.oauth.authentication.credentials.oauth.scope.infra.rule.DefaultScopeAccessibleAuthorityValidationRule;
import cube8540.oauth.authentication.credentials.oauth.scope.infra.rule.DefaultScopeIdValidationRule;
import cube8540.validator.core.ValidationRule;
import lombok.Setter;

public class DefaultOAuth2ScopeValidationPolicy implements OAuth2ScopeValidationPolicy {

    @Setter
    private AuthorityDetailsService authorityService;

    @Override
    public ValidationRule<OAuth2Scope> scopeIdRule() {
        return new DefaultScopeIdValidationRule();
    }

    @Override
    public ValidationRule<OAuth2Scope> accessibleRule() {
        DefaultScopeAccessibleAuthorityValidationRule rule = new DefaultScopeAccessibleAuthorityValidationRule();
        rule.setScopeDetailsServices(authorityService);
        return rule;
    }
}
