package cube8540.oauth.authentication.credentials.role.infra.rule;

import cube8540.oauth.authentication.credentials.AuthorityCode;
import cube8540.oauth.authentication.credentials.role.domain.Role;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;

import java.util.Optional;

public class DefaultRoleCodeValidationRule implements ValidationRule<Role> {

    private final static String DEFAULT_PROPERTY = "code";
    private final static String DEFAULT_MESSAGE = "권한 코드를 입력해 주세요.";

    private final String property;
    private final String message;

    public DefaultRoleCodeValidationRule() {
        this(DEFAULT_PROPERTY, DEFAULT_MESSAGE);
    }

    public DefaultRoleCodeValidationRule(String property, String message) {
        this.property = property;
        this.message = message;
    }

    @Override
    public ValidationError error() {
        return new ValidationError(property, message);
    }

    @Override
    public boolean isValid(Role target) {
        return Optional.ofNullable(target.getCode())
                .map(AuthorityCode::getValue)
                .map(code -> !code.isEmpty())
                .orElse(false);
    }
}
