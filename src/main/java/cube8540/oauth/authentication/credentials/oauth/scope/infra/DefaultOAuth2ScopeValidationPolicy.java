package cube8540.oauth.authentication.credentials.oauth.scope.infra;

import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2Scope;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeValidationPolicy;
import cube8540.oauth.authentication.credentials.oauth.scope.infra.rule.DefaultScopeAccessibleAuthorityValidationRule;
import cube8540.oauth.authentication.credentials.oauth.scope.infra.rule.DefaultScopeIdValidationRule;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ScopeDetailsService;
import cube8540.validator.core.ValidationRule;
import lombok.Setter;

public class DefaultOAuth2ScopeValidationPolicy implements OAuth2ScopeValidationPolicy {

    @Setter
    private OAuth2ScopeDetailsService authorityService;

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
