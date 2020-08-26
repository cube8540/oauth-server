package cube8540.oauth.authentication.credentials.oauth.scope.infra;

import cube8540.oauth.authentication.credentials.AuthorityDetailsService;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2Scope;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeValidatorFactory;
import cube8540.oauth.authentication.credentials.oauth.scope.infra.rule.DefaultScopeAccessibleAuthorityValidationRule;
import cube8540.oauth.authentication.credentials.oauth.scope.infra.rule.DefaultScopeIdValidationRule;
import cube8540.validator.core.Validator;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

@Component
public class DefaultOAuth2ScopeValidatorFactory implements OAuth2ScopeValidatorFactory {

    @Setter(onMethod_ = {@Autowired, @Qualifier("defaultScopeDetailsService")})
    private AuthorityDetailsService authorityService;

    @Override
    public Validator<OAuth2Scope> createValidator(OAuth2Scope scope) {
        DefaultScopeAccessibleAuthorityValidationRule authorityRule = new DefaultScopeAccessibleAuthorityValidationRule();
        authorityRule.setScopeDetailsServices(authorityService);

        return Validator.of(scope).registerRule(new DefaultScopeIdValidationRule())
                .registerRule(authorityRule);
    }
}
