package cube8540.oauth.authentication.users.application

import cube8540.oauth.authentication.users.domain.User
import cube8540.oauth.authentication.users.domain.UserCredentialsKeyGenerator
import cube8540.oauth.authentication.users.domain.UserKeyMatchedResult
import cube8540.oauth.authentication.users.domain.UserNotFoundException
import cube8540.oauth.authentication.users.domain.UserRepository
import cube8540.oauth.authentication.users.domain.UserValidatorFactory
import cube8540.oauth.authentication.users.domain.Username
import cube8540.oauth.authentication.users.infra.DefaultUserCredentialsKeyGenerator
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class DefaultUserPasswordService @Autowired constructor(
    private val repository: UserRepository,
    private val encoder: PasswordEncoder
): UserPasswordService {

    @set:[Autowired Qualifier("userPasswordChangeValidatorFactory")]
    lateinit var validatorFactory: UserValidatorFactory

    var keyGenerator: UserCredentialsKeyGenerator = DefaultUserCredentialsKeyGenerator()

    @Transactional
    override fun changePassword(username: String, changeRequest: ChangePasswordRequest): UserProfile {
        val user = getUser(username)

        user.changePassword(changeRequest.existingPassword, changeRequest.newPassword, encoder)
        user.validation(validatorFactory)
        user.encrypted(encoder)

        return UserProfile(repository.save(user))
    }

    @Transactional
    override fun forgotPassword(username: String): UserProfile {
        val user = getUser(username)

        user.forgotPassword(keyGenerator)
        return UserProfile(repository.save(user))
    }

    @Transactional
    override fun validateCredentialsKey(username: String, credentialsKey: String): Boolean {
        val user = getUser(username)

        return user.passwordCredentialsKey?.matches(credentialsKey) == UserKeyMatchedResult.MATCHED
    }

    @Transactional
    override fun resetPassword(resetRequest: ResetPasswordRequest): UserProfile {
        val user = getUser(resetRequest.username)

        user.resetPassword(resetRequest.credentialsKey, resetRequest.newPassword)
        user.validation(validatorFactory)
        user.encrypted(encoder)

        return UserProfile(repository.save(user))
    }

    private fun getUser(username: String): User = repository
        .findById(Username(username))
        .orElseThrow { UserNotFoundException.instance("$username is not found") }
}