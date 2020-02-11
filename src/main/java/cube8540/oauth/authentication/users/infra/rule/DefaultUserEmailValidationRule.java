package cube8540.oauth.authentication.users.infra.rule;

import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserEmail;
import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DefaultUserEmailValidationRule implements ValidationRule<User> {

    private static final String PROPERTY = "email";
    private static final String MESSAGE = "이메일 형식을 다시 확인해 주세요.";

    private static final String PATTERN = "(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\""
            + "(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")@"
            + "(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}"
            + "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21-\\x5a\\x53-\\x7f]|"
            + "\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])+)])";

    private String property;
    private String errorMessage;

    public DefaultUserEmailValidationRule() {
        this(PROPERTY, MESSAGE);
    }

    public DefaultUserEmailValidationRule(String property, String errorMessage) {
        this.property = property;
        this.errorMessage = errorMessage;
    }

    @Override
    public ValidationError error() {
        return new ValidationError(property, errorMessage);
    }

    @Override
    public boolean isValid(User target) {
        return Optional.ofNullable(target.getEmail())
                .map(UserEmail::getValue)
                .map(Pattern.compile(PATTERN)::matcher)
                .map(Matcher::matches)
                .orElse(false);
    }
}
