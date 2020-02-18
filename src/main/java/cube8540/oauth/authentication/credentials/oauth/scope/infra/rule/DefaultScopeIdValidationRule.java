package cube8540.oauth.authentication.credentials.oauth.scope.infra.rule;

import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2Scope;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;

public class DefaultScopeIdValidationRule implements ValidationRule<OAuth2Scope> {

    private static final String PROPERTY = "id";
    private static final String MESSAGE = "스코프 아이디를 입력해 주세요.";

    private String property;
    private String message;

    public DefaultScopeIdValidationRule() {
        this(PROPERTY, MESSAGE);
    }

    public DefaultScopeIdValidationRule(String property, String message) {
        this.property = property;
        this.message = message;
    }

    @Override
    public ValidationError error() {
        return new ValidationError(property, message);
    }

    @Override
    public boolean isValid(OAuth2Scope target) {
        return target.getId() != null && target.getId().getValue() != null;
    }
}
