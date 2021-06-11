package cube8540.oauth.authentication.oauth.security.endpoint

import cube8540.oauth.authentication.oauth.AccessTokenIntrospectionKey
import cube8540.oauth.authentication.oauth.security.OAuth2AccessTokenDetails
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.time.LocalDateTime

class DefaultOAuth2AccessTokenIntrospectionConverterTest {

    private val converter = DefaultOAuth2AccessTokenIntrospectionConverter()

    @Test
    fun `access token convert when username is null`() {
        val accessToken: OAuth2AccessTokenDetails = mockk {
            every { tokenValue } returns "tokenId"
            every { clientId } returns "clientId"
            every { username } returns null
            every { expiration } returns LocalDateTime.of(2020, 2, 1, 22, 52)
            every { scopes } returns setOf("scope-1", "scope-2", "scope-3")
            every { expired } returns false
        }

        val result = converter.convertAccessToken(accessToken)
        assertThat(result[AccessTokenIntrospectionKey.CLIENT_ID]).isNull()
        assertThat(result[AccessTokenIntrospectionKey.EXPIRATION]).isNull()
        assertThat(result[AccessTokenIntrospectionKey.SCOPE]).isEqualTo("scope-1 scope-2 scope-3")
        assertThat(result[AccessTokenIntrospectionKey.USERNAME]).isNull()
    }

    @Test
    fun `access token convert when token is expired`() {
        val accessToken: OAuth2AccessTokenDetails = mockk {
            every { tokenValue } returns "tokenId"
            every { clientId } returns "clientId"
            every { username } returns "username"
            every { expiration } returns LocalDateTime.of(2020, 2, 1, 22, 52)
            every { scopes } returns setOf("scope-1", "scope-2", "scope-3")
            every { expired } returns true
        }

        val result = converter.convertAccessToken(accessToken)
        assertThat(result[AccessTokenIntrospectionKey.CLIENT_ID]).isNull()
        assertThat(result[AccessTokenIntrospectionKey.EXPIRATION]).isNull()
        assertThat(result[AccessTokenIntrospectionKey.SCOPE]).isEqualTo("scope-1 scope-2 scope-3")
        assertThat(result[AccessTokenIntrospectionKey.USERNAME]).isNull()
        assertThat(result[AccessTokenIntrospectionKey.ACTIVE].toString().toBoolean()).isFalse
    }
}