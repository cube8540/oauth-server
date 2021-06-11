package cube8540.oauth.authentication.oauth.security.endpoint

import cube8540.oauth.authentication.oauth.error.InvalidRequestException
import cube8540.oauth.authentication.oauth.security.OAuth2AccessTokenDetails
import cube8540.oauth.authentication.oauth.security.OAuth2AccessTokenDetailsService
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails
import cube8540.oauth.authentication.oauth.security.provider.ClientCredentialsToken
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.catchThrowable
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.springframework.security.authentication.InsufficientAuthenticationException
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import java.security.Principal

class OAuth2TokenIntrospectionEndpointTest {

    private val converter: OAuth2AccessTokenIntrospectionConverter = mockk()
    private val tokenDetailsService: OAuth2AccessTokenDetailsService = mockk()

    private val endpoint = OAuth2TokenIntrospectionEndpoint(tokenDetailsService)

    init {
        endpoint.converter = converter
    }

    @Nested
    inner class ReadTokenTest {

        @Test
        fun `requested principal class type is not credentials client`() {
            val principal: Principal = mockk()

            val thrown = catchThrowable { endpoint.introspection(principal, "token") }
            assertThat(thrown).isInstanceOf(InsufficientAuthenticationException::class.java)
        }

        @Test
        fun `requested principal details class type is not oauth2 client details`() {
            val principal: ClientCredentialsToken = mockk {
                every { principal } returns mockk<Principal>()
            }

            val thrown = catchThrowable { endpoint.introspection(principal, "token") }
            assertThat(thrown).isInstanceOf(InsufficientAuthenticationException::class.java)
        }

        @Test
        fun `requested token value is null`() {
            val principal: ClientCredentialsToken = mockk {
                every { principal } returns mockk<OAuth2ClientDetails>()
            }

            val thrown = catchThrowable { endpoint.introspection(principal, null) }
            assertThat(thrown).isInstanceOf(InvalidRequestException::class.java)
            assertThat((thrown as InvalidRequestException).error.errorCode).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST)
        }

        @Test
        fun `read token`() {
            val clientDetails: OAuth2ClientDetails = mockk()
            val principal: ClientCredentialsToken = mockk {
                every { principal } returns clientDetails
            }
            val accessToken: OAuth2AccessTokenDetails = mockk()
            val convertedAccessTokenMap: Map<String, String?> = mockk()

            every { tokenDetailsService.readAccessToken("tokenId") } returns accessToken
            every { converter.convertAccessToken(accessToken) } returns convertedAccessTokenMap

            val result = endpoint.introspection(principal, "tokenId")
            assertThat(result).isEqualTo(convertedAccessTokenMap)
        }
    }
}