package cube8540.oauth.authentication.users.infra;

import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserValidationPolicy;
import cube8540.oauth.authentication.users.infra.rule.DefaultUserEmailValidationRule;
import cube8540.oauth.authentication.users.infra.rule.DefaultUserPasswordValidationRule;
import cube8540.oauth.authentication.users.infra.rule.DefaultUsernameValidationRule;
import cube8540.validator.core.ValidationRule;

public class DefaultUserValidationPolicy implements UserValidationPolicy {
    @Override
    public ValidationRule<User> usernameRule() {
        return new DefaultUsernameValidationRule();
    }

    @Override
    public ValidationRule<User> emailRule() {
        return new DefaultUserEmailValidationRule();
    }

    @Override
    public ValidationRule<User> passwordRule() {
        return new DefaultUserPasswordValidationRule();
    }
}
