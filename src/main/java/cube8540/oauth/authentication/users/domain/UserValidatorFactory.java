package cube8540.oauth.authentication.users.domain;

import cube8540.validator.core.Validator;

public interface UserValidatorFactory {

    Validator<User> createValidator(User user);

}
