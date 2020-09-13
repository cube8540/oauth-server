package cube8540.oauth.authentication.credentials.oauth.scope.infra;

import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2Scope;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeValidatorFactory;
import cube8540.oauth.authentication.credentials.oauth.scope.infra.rule.DefaultScopeIdValidationRule;
import cube8540.validator.core.Validator;
import org.springframework.stereotype.Component;

@Component
public class DefaultOAuth2ScopeValidatorFactory implements OAuth2ScopeValidatorFactory {

    @Override
    public Validator<OAuth2Scope> createValidator(OAuth2Scope scope) {
        return Validator.of(scope).registerRule(new DefaultScopeIdValidationRule());
    }
}
