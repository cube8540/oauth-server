package cube8540.oauth.authentication.credentials.oauth.scope.infra;

import cube8540.oauth.authentication.credentials.AuthorityDetailsService;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2Scope;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeValidatorFactory;
import cube8540.oauth.authentication.credentials.oauth.scope.infra.rule.DefaultScopeAccessibleAuthorityValidationRule;
import cube8540.oauth.authentication.credentials.oauth.scope.infra.rule.DefaultScopeIdValidationRule;
import cube8540.validator.core.Validator;
import lombok.Setter;

public class DefaultOAuth2ScopeValidatorFactory implements OAuth2ScopeValidatorFactory {

    @Setter
    private AuthorityDetailsService authorityService;

    @Override
    public Validator<OAuth2Scope> createValidator(OAuth2Scope scope) {
        DefaultScopeAccessibleAuthorityValidationRule authorityRule = new DefaultScopeAccessibleAuthorityValidationRule();
        authorityRule.setScopeDetailsServices(authorityService);

        return Validator.of(scope).registerRule(new DefaultScopeIdValidationRule())
                .registerRule(authorityRule);
    }
}
