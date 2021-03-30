package cube8540.oauth.authentication.oauth.token.domain

import cube8540.oauth.authentication.AuthenticationApplication
import cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientId
import cube8540.oauth.authentication.security.AuthorityCode
import cube8540.oauth.authentication.toDefaultInstance
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.springframework.security.oauth2.core.AuthorizationGrantType
import java.time.Clock
import java.time.LocalDateTime

class OAuth2AuthorizedAccessTokenTest {

    private val tokenIdGenerator: OAuth2TokenIdGenerator = mockk {
        every { generateTokenValue() } returns OAuth2TokenId("tokenId")
    }
    private val expirationDatetime = LocalDateTime.of(2020, 1, 29, 22, 51)

    private val accessToken = OAuth2AuthorizedAccessToken(
        tokenIdGenerator = tokenIdGenerator,
        username = PrincipalUsername("username"),
        client = OAuth2ClientId("clientId"),
        scopes = emptySet<AuthorityCode>().toMutableSet(),
        expiration = expirationDatetime,
        tokenGrantType = AuthorizationGrantType.AUTHORIZATION_CODE,
        issuedAt = LocalDateTime.now()
    )

    @Nested
    inner class ExpirationTest {

        @Test
        fun `access token is expired`() {
            val datetime = expirationDatetime.plusNanos(1)

            OAuth2AuthorizedAccessToken.clock = Clock.fixed(datetime.toDefaultInstance(),
                AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId())

            assertThat(accessToken.isExpired()).isTrue
            assertThat(accessToken.expiresIn()).isEqualTo(0)
        }

        @Test
        fun `access token is not expired`() {
            val datetime = expirationDatetime.minusSeconds(10)

            OAuth2AuthorizedAccessToken.clock = Clock.fixed(datetime.toDefaultInstance(),
                AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId())

            assertThat(accessToken.isExpired()).isFalse
            assertThat(accessToken.expiresIn()).isEqualTo(10)
        }
    }

    @Nested
    inner class TokenAdditionalInformationTest {

        @Test
        fun `store additional information`() {
            accessToken.putAdditionalInformation("key-1", "value-1")
            accessToken.putAdditionalInformation("key-2", "value-2")
            accessToken.putAdditionalInformation("key-3", "value-3")

            assertThat(accessToken.additionalInformation!!["key-1"]).isEqualTo("value-1")
            assertThat(accessToken.additionalInformation!!["key-2"]).isEqualTo("value-2")
            assertThat(accessToken.additionalInformation!!["key-3"]).isEqualTo("value-3")
        }
    }

    @Nested
    inner class GenerateRefreshTokenTest {

        @Test
        fun `generate refresh token`() {
            val refreshTokenIdGenerator: OAuth2TokenIdGenerator = mockk {
                every { generateTokenValue() } returns OAuth2TokenId("refreshTokenId")
            }
            val refreshTokenExpirationDatetime = LocalDateTime.of(2020, 1, 29, 11, 9)

            accessToken.generateRefreshToken(refreshTokenIdGenerator, refreshTokenExpirationDatetime)
            assertThat(accessToken.refreshToken!!.tokenId).isEqualTo(OAuth2TokenId("refreshTokenId"))
            assertThat(accessToken.refreshToken!!.expiration).isEqualTo(refreshTokenExpirationDatetime)
        }
    }

    @Nested
    inner class GenerateComposeUniqueKey {

        @Test
        fun `generate compose unique key`() {
            val uniqueKeyGenerator: OAuth2ComposeUniqueKeyGenerator = mockk {
                every { generateKey(accessToken) } returns OAuth2ComposeUniqueKey("uniqueKey")
            }

            accessToken.generateComposeUniqueKey(uniqueKeyGenerator)
            assertThat(accessToken.composeUniqueKey).isEqualTo(OAuth2ComposeUniqueKey("uniqueKey"))
        }
    }
}