package cube8540.oauth.authentication.user.domain

import cube8540.oauth.authentication.AuthenticationApplication
import cube8540.oauth.authentication.toDefaultInstance
import cube8540.oauth.authentication.users.domain.UserCredentialsKey
import cube8540.oauth.authentication.users.domain.UserKeyMatchedResult
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.LocalDateTime


class UserCredentialsKeyTest {
    private val defaultNow = LocalDateTime.of(2021, 2, 22, 23, 41)
    private val expirationDateTime = defaultNow.plusMinutes(5)

    private val notExpirationNow = expirationDateTime.minusNanos(1)
    private val expirationNow = expirationDateTime.plusNanos(1)

    @Nested
    inner class InitializationTest {
        private val key: UserCredentialsKey

        init {
            UserCredentialsKey.clock = Clock.fixed(defaultNow.toDefaultInstance(), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId())
            this.key = UserCredentialsKey("key")
        }

        @Test
        fun `set expiration datetime`() {
            assertThat(key.expiryDateTime).isEqualTo(expirationDateTime)
        }
    }

    @Nested
    inner class MatchTest {
        private val key: UserCredentialsKey

        init {
            UserCredentialsKey.clock = Clock.fixed(defaultNow.toDefaultInstance(), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId())
            this.key = UserCredentialsKey("key")
        }

        @Test
        fun `match expired key`() {
            UserCredentialsKey.clock = Clock.fixed(expirationNow.toDefaultInstance(), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId())

            val result = key.matches("key")
            assertThat(result).isEqualTo(UserKeyMatchedResult.EXPIRED)
        }

        @Test
        fun `match not equal key`() {
            UserCredentialsKey.clock = Clock.fixed(notExpirationNow.toDefaultInstance(), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId())

            val result = key.matches("not matched")
            assertThat(result).isEqualTo(UserKeyMatchedResult.NOT_MATCHED)
        }

        @Test
        fun `match equal key`() {
            UserCredentialsKey.clock = Clock.fixed(notExpirationNow.toDefaultInstance(), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId())

            val result = key.matches("key")
            assertThat(result).isEqualTo(UserKeyMatchedResult.MATCHED)
        }
    }
}
