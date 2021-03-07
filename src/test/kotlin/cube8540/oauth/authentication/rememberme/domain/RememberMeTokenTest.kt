package cube8540.oauth.authentication.rememberme.domain

import cube8540.oauth.authentication.AuthenticationApplication
import cube8540.oauth.authentication.toDefaultInstance
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.LocalDateTime

class RememberMeTokenTest {
    private val defaultNow = LocalDateTime.of(2021, 3, 7, 15, 8)
    private val expirationDateTime = defaultNow.plusSeconds(RememberMeToken.tokenValiditySeconds)
    private val notExpirationNow = expirationDateTime.minusNanos(1)
    private val expirationNow = expirationDateTime.plusNanos(1)

    private val generator: RememberMeTokenGenerator = mockk()

    init {
        every { generator.generateTokenSeries() } returns RememberMeTokenSeries("series")
        every { generator.generateTokenValue() } returns RememberMeTokenValue("tokenValue")
    }

    @Nested
    inner class InitializationTest {
        private val token: RememberMeToken

        init {
            RememberMeToken.clock = Clock.fixed(defaultNow.toDefaultInstance(), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId())
            this.token = RememberMeToken(generator, "username")
        }

        @Test
        fun `set last used time`() {
            assertThat(token.lastUsedAt).isEqualTo(defaultNow)
        }
    }

    @Nested
    inner class ExpirationTest {
        private val token: RememberMeToken

        init {
            RememberMeToken.clock = Clock.fixed(defaultNow.toDefaultInstance(), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId())
            this.token = RememberMeToken(generator, "username")
        }

        @Test
        fun `token is expiration`() {
            RememberMeToken.clock = Clock.fixed(expirationNow.toDefaultInstance(), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId())

            assertThat(token.isExpired()).isTrue
        }

        @Test
        fun `token is not expiration`() {
            RememberMeToken.clock = Clock.fixed(notExpirationNow.toDefaultInstance(), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId())

            assertThat(token.isExpired()).isFalse
        }
    }

    @Nested
    inner class UpdateLastUsedAtTest {
        private val now = LocalDateTime.of(2021, 3, 7, 15, 28)
        private val token: RememberMeToken

        init {
            RememberMeToken.clock = Clock.fixed(defaultNow.toDefaultInstance(), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId())
            this.token = RememberMeToken(generator, "username")
        }

        @Test
        fun `update last used at`() {
            RememberMeToken.clock = Clock.fixed(now.toDefaultInstance(), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId())

            token.updateLastUsedAt()
            assertThat(token.lastUsedAt).isEqualTo(now)
        }
    }
}