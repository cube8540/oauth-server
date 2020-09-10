package cube8540.oauth.authentication.users.infra;

import cube8540.oauth.authentication.users.domain.User;
import cube8540.oauth.authentication.users.domain.UserValidatorFactory;
import cube8540.oauth.authentication.users.infra.rule.DefaultUserPasswordValidationRule;
import cube8540.validator.core.Validator;
import org.springframework.stereotype.Component;

@Component
public class UserPasswordChangeValidatorFactory implements UserValidatorFactory {
    @Override
    public Validator<User> createValidator(User user) {
        return Validator.of(user).registerRule(new DefaultUserPasswordValidationRule());
    }
}
