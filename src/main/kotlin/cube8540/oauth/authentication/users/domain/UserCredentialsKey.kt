package cube8540.oauth.authentication.users.domain

import cube8540.oauth.authentication.AuthenticationApplication
import java.time.Clock
import java.time.LocalDateTime
import javax.persistence.Embeddable

@Embeddable
data class UserCredentialsKey(var keyValue: String) {
    var expiryDateTime: LocalDateTime = LocalDateTime.now(clock).plusMinutes(5)

    companion object {
        @JvmStatic protected var clock: Clock = Clock.system(AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId())
    }

    fun matches(key: String): UserKeyMatchedResult = when {
        LocalDateTime.now(clock).isAfter(expiryDateTime) -> {
            UserKeyMatchedResult.EXPIRED
        }
        keyValue == key -> {
            UserKeyMatchedResult.MATCHED
        }
        else -> {
            UserKeyMatchedResult.NOT_MATCHED
        }
    }
}