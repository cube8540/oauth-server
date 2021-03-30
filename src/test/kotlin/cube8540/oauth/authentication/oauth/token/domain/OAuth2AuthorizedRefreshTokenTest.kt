package cube8540.oauth.authentication.oauth.token.domain

import cube8540.oauth.authentication.AuthenticationApplication
import cube8540.oauth.authentication.toDefaultInstance
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.time.Clock
import java.time.LocalDateTime

class OAuth2AuthorizedRefreshTokenTest {

    private val tokenIdGenerator: OAuth2TokenIdGenerator = mockk {
        every { generateTokenValue() } returns OAuth2TokenId("tokenId")
    }
    private val refreshExpirationDateTime = LocalDateTime.of(2020, 1, 29, 11, 9)
    private val refreshToken: OAuth2AuthorizedRefreshToken = OAuth2AuthorizedRefreshToken(tokenIdGenerator, refreshExpirationDateTime, mockk(relaxed = true))

    @Nested
    inner class ExpirationTest {

        @Test
        fun `refresh token is expiration`() {
            val datetime = refreshExpirationDateTime.plusNanos(1)

            OAuth2AuthorizedRefreshToken.clock = Clock.fixed(datetime.toDefaultInstance(), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId())

            val isExpired = refreshToken.isExpired()
            val expires = refreshToken.expiresIn()
            assertThat(isExpired).isTrue
            assertThat(expires).isEqualTo(0)
        }

        @Test
        fun `refresh token is not expiration`() {
            val datetime = refreshExpirationDateTime.minusSeconds(10)

            OAuth2AuthorizedRefreshToken.clock = Clock.fixed(datetime.toDefaultInstance(), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId())

            val isExpired = refreshToken.isExpired()
            val expires = refreshToken.expiresIn()
            assertThat(isExpired).isFalse
            assertThat(expires).isEqualTo(10)
        }
    }
}