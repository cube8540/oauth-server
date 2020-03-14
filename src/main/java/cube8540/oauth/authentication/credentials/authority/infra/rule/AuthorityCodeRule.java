package cube8540.oauth.authentication.credentials.authority.infra.rule;

import cube8540.oauth.authentication.credentials.authority.domain.Authority;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;
import lombok.AllArgsConstructor;

@AllArgsConstructor
public class AuthorityCodeRule implements ValidationRule<Authority> {

    public static final String DEFAULT_PROPERTY = "code";
    public static final String DEFAULT_MESSAGE = "권한 코드를 입력해 주세요.";

    private String property;
    private String message;

    public AuthorityCodeRule() {
        this(DEFAULT_PROPERTY, DEFAULT_MESSAGE);
    }

    @Override
    public ValidationError error() {
        return new ValidationError(property, message);
    }

    @Override
    public boolean isValid(Authority target) {
        return target.getCode() != null && target.getCode().getValue() != null;
    }
}
