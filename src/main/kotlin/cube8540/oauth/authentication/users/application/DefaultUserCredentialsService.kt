package cube8540.oauth.authentication.users.application

import cube8540.oauth.authentication.users.domain.User
import cube8540.oauth.authentication.users.domain.UserCredentialsKeyGenerator
import cube8540.oauth.authentication.users.domain.UserNotFoundException
import cube8540.oauth.authentication.users.domain.UserRepository
import cube8540.oauth.authentication.users.domain.Username
import cube8540.oauth.authentication.users.infra.DefaultUserCredentialsKeyGenerator
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class DefaultUserCredentialsService @Autowired constructor(
    private val repository: UserRepository
): UserCredentialsService {

    var keyGenerator: UserCredentialsKeyGenerator = DefaultUserCredentialsKeyGenerator()

    @Transactional
    override fun grantCredentialsKey(username: String): UserProfile {
        val user = getUser(username)

        user.generateCredentialsKey(keyGenerator)
        return UserProfile(repository.save(user))
    }

    @Transactional
    override fun accountCredentials(username: String, credentialsKey: String): UserProfile {
        val user = getUser(username)

        user.credentials(credentialsKey)
        return UserProfile(repository.save(user))
    }

    private fun getUser(username: String): User = repository
        .findById(Username(username))
        .orElseThrow { UserNotFoundException.instance("$username is not found") }
}