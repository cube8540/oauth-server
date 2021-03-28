package cube8540.oauth.authentication.oauth.security.introspector

import cube8540.oauth.authentication.oauth.security.OAuth2AccessTokenDetails
import cube8540.oauth.authentication.oauth.security.OAuth2AccessTokenDetailsService
import cube8540.oauth.authentication.oauth.security.provider.ClientCredentialsToken
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AccessTokenNotFoundException
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.catchThrowable
import org.junit.jupiter.api.Test
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException

class DefaultAccessTokenIntrospectorTest {

    private val clientId: String = "clientId"
    private val clientSecret: String = "clientSecret"

    private val service: OAuth2AccessTokenDetailsService = mockk()
    private val provider: AuthenticationProvider = mockk()

    private val introspector = DefaultAccessTokenIntrospector(service, provider)

    init {
        introspector.clientId = clientId
        introspector.clientSecret = clientSecret
    }

    @Test
    fun `introspect when access token is not found`() {
        every { service.readAccessToken("accessToken") } throws OAuth2AccessTokenNotFoundException("accessToken")

        val thrown = catchThrowable { introspector.introspect("accessToken") }
        assertThat(thrown).isInstanceOf(OAuth2IntrospectionException::class.java)
    }

    @Test
    fun `read access token client is different request client`() {
        val accessToken: OAuth2AccessTokenDetails = mockk(relaxed = true) {
            every { clientId } returns "accessTokenClientId"
        }
        val clientCredentialsToken = ClientCredentialsToken(clientId, clientSecret)

        val clientAuthentication: Authentication = mockk(relaxed = true) {
            every { name } returns clientId
        }

        every { service.readAccessToken("accessToken") } returns accessToken
        every { provider.authenticate(clientCredentialsToken) } returns clientAuthentication

        val thrown = catchThrowable { introspector.introspect("accessToken") }
        assertThat(thrown).isInstanceOf(OAuth2IntrospectionException::class.java)
    }

    @Test
    fun `throws exception during client authentication`() {
        val accessToken: OAuth2AccessTokenDetails = mockk(relaxed = true)
        val clientCredentialsToken = ClientCredentialsToken(clientId, clientSecret)

        every { accessToken.clientId } returns clientId
        every { service.readAccessToken("accessToken") } returns accessToken
        every { provider.authenticate(clientCredentialsToken) } throws RuntimeException()

        val thrown = catchThrowable { introspector.introspect("accessToken") }
        assertThat(thrown).isInstanceOf(OAuth2IntrospectionException::class.java)
    }

    @Test
    fun `access token is expired`() {
        val accessToken: OAuth2AccessTokenDetails = mockk(relaxed = true)
        val clientCredentialsToken = ClientCredentialsToken(clientId, clientSecret)

        val clientAuthentication: Authentication = mockk(relaxed = true)

        every { accessToken.clientId } returns clientId
        every { accessToken.expired } returns true
        every { service.readAccessToken("accessToken") } returns accessToken
        every { provider.authenticate(clientCredentialsToken) } returns clientAuthentication

        val thrown = catchThrowable { introspector.introspect("accessToken") }
        assertThat(thrown).isInstanceOf(OAuth2IntrospectionException::class.java)
    }

    @Test
    fun `access token owner is null`() {
        val accessToken: OAuth2AccessTokenDetails = mockk(relaxed = true)
        val clientCredentialsToken = ClientCredentialsToken(clientId, clientSecret)

        val clientAuthentication: Authentication = mockk(relaxed = true) {
            every { name } returns clientId
        }

        every { accessToken.clientId } returns clientId
        every { accessToken.username } returns null
        every { accessToken.expired } returns false
        every { service.readAccessToken("accessToken") } returns accessToken
        every { provider.authenticate(clientCredentialsToken) } returns clientAuthentication

        val result = introspector.introspect("accessToken")
        assertThat(result.attributes[OAuth2IntrospectionClaimNames.CLIENT_ID]).isEqualTo(clientId)
        assertThat(result.name).isNull()
    }

    @Test
    fun `access token owner is not null`() {
        val accessToken: OAuth2AccessTokenDetails = mockk(relaxed = true)
        val clientCredentialsToken = ClientCredentialsToken(clientId, clientSecret)

        val clientAuthentication: Authentication = mockk(relaxed = true) {
            every { name } returns clientId
        }

        every { accessToken.clientId } returns clientId
        every { accessToken.username } returns "username"
        every { accessToken.expired } returns false
        every { service.readAccessToken("accessToken") } returns accessToken
        every { provider.authenticate(clientCredentialsToken) } returns clientAuthentication

        val result = introspector.introspect("accessToken")
        assertThat(result.attributes[OAuth2IntrospectionClaimNames.CLIENT_ID]).isEqualTo(clientId)
        assertThat(result.name).isEqualTo("username")
    }
}