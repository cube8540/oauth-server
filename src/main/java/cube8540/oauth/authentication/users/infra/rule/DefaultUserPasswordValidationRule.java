package cube8540.oauth.authentication.users.infra.rule;

import cube8540.oauth.authentication.users.domain.User;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;

import java.util.regex.Pattern;

public class DefaultUserPasswordValidationRule implements ValidationRule<User> {

    private static final String REQUIRED_PATTERN_VALUE = "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{12,30}$";
    private static final String WHITELIST_PATTERN_VALUE = "^[#?!@$%^&*\\-a-zA-Z0-9 ]+$";

    private static final String PROPERTY = "password";
    private static final String MESSAGE = "패스워드는 특수문자(#?!@$%^&*)와 대소문자, 숫자 조합으로 12 ~ 30 글자로 입력해야 합니다.";

    private String property;
    private String errorMessage;

    public DefaultUserPasswordValidationRule() {
        this(PROPERTY, MESSAGE);
    }

    public DefaultUserPasswordValidationRule(String property, String errorMessage) {
        this.property = property;
        this.errorMessage = errorMessage;
    }

    @Override
    public ValidationError error() {
        return new ValidationError(property, errorMessage);
    }

    @Override
    public boolean isValid(User target) {
        return target.getPassword() != null && matchesRequiredPattern(target.getPassword())
                && matchesWhitelistPattern(target.getPassword());
    }

    private boolean matchesRequiredPattern(String password) {
        return Pattern.compile(REQUIRED_PATTERN_VALUE).matcher(password).matches();
    }

    private boolean matchesWhitelistPattern(String password) {
        return Pattern.compile(WHITELIST_PATTERN_VALUE).matcher(password).matches();
    }
}
