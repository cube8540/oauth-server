package cube8540.oauth.authentication.users.infra

import cube8540.oauth.authentication.users.domain.User
import cube8540.oauth.authentication.users.domain.UserValidatorFactory
import cube8540.validator.core.Validator
import org.springframework.stereotype.Component

@Component
class UserPasswordChangeValidatorFactory: UserValidatorFactory {
    override fun createValidator(user: User): Validator<User> =
        Validator.of(user).registerRule(DefaultUserPasswordValidationRule())
}

@Component
class DefaultUserValidatorFactory: UserValidatorFactory {
    override fun createValidator(user: User): Validator<User> =
        Validator.of(user)
            .registerRule(DefaultUsernameValidationRule())
            .registerRule(DefaultUserPasswordValidationRule())
}