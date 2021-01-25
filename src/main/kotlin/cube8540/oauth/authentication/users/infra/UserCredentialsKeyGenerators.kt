package cube8540.oauth.authentication.users.infra

import cube8540.oauth.authentication.users.domain.UserCredentialsKey
import cube8540.oauth.authentication.users.domain.UserCredentialsKeyGenerator
import java.util.*

class DefaultUserCredentialsKeyGenerator: UserCredentialsKeyGenerator {
    override fun generateKey(): UserCredentialsKey {
        val uuid = UUID.randomUUID().toString().replace("-", "")
        return UserCredentialsKey(uuid)
    }
}