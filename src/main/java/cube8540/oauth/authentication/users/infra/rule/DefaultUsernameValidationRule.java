package cube8540.oauth.authentication.users.infra.rule;

import cube8540.oauth.authentication.users.domain.User;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DefaultUsernameValidationRule implements ValidationRule<User> {

    private static final String REQUIRED_PATTERN_VALUE = "^(?=.*?[a-z])(?=.*?[0-9]).{4,18}$";
    private static final String WHITELIST_PATTERN_VALUE = "^[A-Za-z0-9]{4,18}$";

    private static final String DEFAULT_PROPERTY = "username";
    private static final String DEFAULT_MESSAGE = "아이디는 영문과 숫자를 조합한 4 ~ 18 글자로 입력해 주세요.";

    private String property;
    private String errorMessage;

    public DefaultUsernameValidationRule() {
        this(DEFAULT_PROPERTY, DEFAULT_MESSAGE);
    }

    public DefaultUsernameValidationRule(String property, String errorMessage) {
        this.property = property;
        this.errorMessage = errorMessage;
    }

    @Override
    public ValidationError error() {
        return new ValidationError(property, errorMessage);
    }

    @Override
    public boolean isValid(User target) {
        return target.getUsername() != null && matchesRequiredPattern(target.getUsername().getValue()) &&
                matchesWhitelistPattern(target.getUsername().getValue());
    }

    private boolean matchesRequiredPattern(String username) {
        return Optional.ofNullable(username)
                .map(Pattern.compile(REQUIRED_PATTERN_VALUE)::matcher)
                .map(Matcher::matches).orElse(false);
    }

    private boolean matchesWhitelistPattern(String username) {
        return Optional.ofNullable(username)
                .map(Pattern.compile(WHITELIST_PATTERN_VALUE)::matcher)
                .map(Matcher::matches).orElse(false);
    }
}
