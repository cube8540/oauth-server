package cube8540.oauth.authentication.users.infra

import cube8540.oauth.authentication.users.domain.Uid
import cube8540.oauth.authentication.users.domain.UserCredentialsKey
import cube8540.oauth.authentication.users.domain.UserCredentialsKeyGenerator
import cube8540.oauth.authentication.users.domain.UserUidGenerator
import java.util.*

class DefaultUserCredentialsKeyGenerator: UserCredentialsKeyGenerator {
    override fun generateKey(): UserCredentialsKey {
        val uuid = UUID.randomUUID().toString().replace("-", "")
        return UserCredentialsKey(uuid)
    }
}

class DefaultUserUidGenerator: UserUidGenerator {
    override fun generateUid(): Uid {
        val uuid = UUID.randomUUID().toString().replace("-", "")
        return Uid(uuid)
    }
}