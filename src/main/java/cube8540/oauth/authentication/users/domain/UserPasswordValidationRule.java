package cube8540.oauth.authentication.users.domain;

import cube8540.validator.core.ValidationError;
import cube8540.validator.core.ValidationRule;

import java.util.Optional;

public class UserPasswordValidationRule implements ValidationRule<User> {

    public static final String PROPERTY = "password";
    public static final String MESSAGE = "password is invalid";

    protected UserPasswordValidationRule() {}

    @Override
    public ValidationError error() {
        return new ValidationError(PROPERTY, MESSAGE);
    }

    @Override
    public boolean isValid(User target) {
        return Optional.ofNullable(target)
                .map(User::getPassword)
                .map(UserPassword::isValid).orElse(false);
    }
}
