package cube8540.oauth.authentication.users.domain;

import cube8540.validator.core.ValidationRule;

public interface UserValidationPolicy {

    ValidationRule<User> emailRule();

    ValidationRule<User> passwordRule();

}
