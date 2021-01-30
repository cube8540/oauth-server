package cube8540.oauth.authentication.users.infra

import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetailsService
import cube8540.oauth.authentication.users.application.DefaultUserApprovalAuthorityService
import cube8540.oauth.authentication.users.domain.User
import cube8540.oauth.authentication.users.domain.UserValidatorFactory
import cube8540.validator.core.Validator
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
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

@Component
class DefaultApprovalAuthorityValidatorFactory: UserValidatorFactory {

    @set:[Autowired Qualifier("defaultOAuth2ClientDetailsService")]
    lateinit var clientDetailsService: OAuth2ClientDetailsService

    override fun createValidator(user: User): Validator<User> {
        val rule = DefaultApprovalAuthorityValidationRule()

        rule.clientDetailsService = clientDetailsService

        return Validator.of(user).registerRule(rule)
    }
}