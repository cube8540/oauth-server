package cube8540.oauth.authentication.users.application

import cube8540.oauth.authentication.users.domain.User
import cube8540.oauth.authentication.users.domain.UserCredentialsKeyGenerator
import cube8540.oauth.authentication.users.domain.UserNotFoundException
import cube8540.oauth.authentication.users.domain.UserRegisterException
import cube8540.oauth.authentication.users.domain.UserRepository
import cube8540.oauth.authentication.users.domain.UserUidGenerator
import cube8540.oauth.authentication.users.domain.UserValidatorFactory
import cube8540.oauth.authentication.users.domain.Username
import cube8540.oauth.authentication.users.infra.DefaultUserCredentialsKeyGenerator
import cube8540.oauth.authentication.users.infra.DefaultUserUidGenerator
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class DefaultUserManagementService @Autowired constructor(
    private val repository: UserRepository,

    private val encoder: PasswordEncoder
): UserManagementService {

    @set:[Autowired Qualifier("defaultUserValidatorFactory")]
    lateinit var validatorFactory: UserValidatorFactory

    var keyGenerator: UserCredentialsKeyGenerator = DefaultUserCredentialsKeyGenerator()

    var uidGenerator: UserUidGenerator = DefaultUserUidGenerator()

    @Transactional(readOnly = true)
    override fun countUser(username: String): Long = repository.countByUsername(Username(username))

    @Transactional(readOnly = true)
    override fun loadUserProfile(username: String): UserProfile = UserProfile(getUser(username))

    @Transactional
    override fun registerUser(registerRequest: UserRegisterRequest): CredentialsKeyUserProfile {
        if (countUser(registerRequest.username) > 0) {
            throw UserRegisterException.existsIdentifier("${registerRequest.username} is exists")
        }

        val registerUser = User(uidGenerator, registerRequest.username, registerRequest.password)
        registerUser.validation(validatorFactory)
        registerUser.encrypted(encoder)
        registerUser.generateCredentialsKey(keyGenerator)

        return CredentialsKeyUserProfile(repository.save(registerUser))
    }

    @Transactional
    override fun removeUser(username: String): UserProfile {
        val registerUser = getUser(username)

        repository.delete(registerUser)
        return UserProfile(registerUser)
    }

    private fun getUser(username: String): User = repository
        .findById(Username(username))
        .orElseThrow { UserNotFoundException.instance("$username is not found") }
}