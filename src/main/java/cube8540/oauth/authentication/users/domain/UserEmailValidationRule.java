package cube8540.oauth.authentication.users.domain;

import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;

import java.util.Optional;

public class UserEmailValidationRule implements ValidationRule<User> {

    public static final String PROPERTY = "email";
    public static final String MESSAGE = "email is invalid";

    protected UserEmailValidationRule() {}

    @Override
    public ValidationError error() {
        return new ValidationError(PROPERTY, MESSAGE);
    }

    @Override
    public boolean isValid(User target) {
        return Optional.ofNullable(target)
                .map(User::getEmail)
                .map(UserEmail::isValid).orElse(false);
    }
}
