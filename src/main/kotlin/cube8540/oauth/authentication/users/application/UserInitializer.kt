package cube8540.oauth.authentication.users.application

import cube8540.oauth.authentication.ApplicationInitializer
import cube8540.oauth.authentication.users.domain.User
import cube8540.oauth.authentication.users.domain.UserCredentialsKeyGenerator
import cube8540.oauth.authentication.users.domain.UserRepository
import cube8540.oauth.authentication.users.domain.UserUidGenerator
import cube8540.oauth.authentication.users.domain.Username
import cube8540.oauth.authentication.users.infra.DefaultUserCredentialsKeyGenerator
import cube8540.oauth.authentication.users.infra.DefaultUserUidGenerator
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.context.event.ApplicationReadyEvent
import org.springframework.context.ApplicationListener
import org.springframework.core.annotation.Order
import org.springframework.core.env.Environment
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
@Order(1)
class UserInitializer @Autowired constructor(
    private val repository: UserRepository,

    private val encoder: PasswordEncoder
): ApplicationInitializer, ApplicationListener<ApplicationReadyEvent> {

    companion object {
        const val USERNAME_KEY = "init-user.username"
        const val PASSWORD_KEY = "init-user.password"
    }

    var uidGenerator: UserUidGenerator = DefaultUserUidGenerator()

    var keyGenerator: UserCredentialsKeyGenerator = DefaultUserCredentialsKeyGenerator()

    override fun onApplicationEvent(event: ApplicationReadyEvent) = initialize(event.applicationContext.environment)

    @Transactional
    override fun initialize(environment: Environment) {
        val username: String = environment.getRequiredProperty(USERNAME_KEY)
        val password: String = environment.getRequiredProperty(PASSWORD_KEY)

        val user: User? = repository.findById(Username(username)).orElse(null)
        if (user == null) {
            val registerUser = User(uidGenerator, username, password)

            registerUser.generateCredentialsKey(keyGenerator)
            registerUser.credentials(registerUser.credentialsKey!!.keyValue)
            registerUser.encrypted(encoder)
            repository.save(registerUser)
        }
    }
}