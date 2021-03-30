package cube8540.oauth.authentication.oauth.security.endpoint

import cube8540.oauth.authentication.oauth.error.InvalidRequestException
import cube8540.oauth.authentication.oauth.error.RedirectMismatchException
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.catchThrowable
import org.junit.jupiter.api.Test
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import java.net.URI

class DefaultRedirectResolverTest {

    private val resolver = DefaultRedirectResolver()

    @Test
    fun `requested redirect uri is null and client has one redirect uri`() {
        val clientDetails: OAuth2ClientDetails = mockk {
            every { registeredRedirectUris } returns setOf(URI.create("http://localhost/callback"))
        }

        val result = resolver.resolveRedirectURI(null, clientDetails)
        assertThat(result).isEqualTo(URI.create("http://localhost/callback"))
    }

    @Test
    fun `requested redirect uri is null and client has several redirect uri`() {
        val registeredRedirectUriSet = setOf(URI.create("http://localhost/callback1"),
            URI.create("http://localhost/callback2"),
            URI.create("http://localhost/callback3"))
        val clientDetails: OAuth2ClientDetails = mockk {
            every { registeredRedirectUris } returns registeredRedirectUriSet
        }

        val thrown = catchThrowable { resolver.resolveRedirectURI(null,  clientDetails) }
        assertThat(thrown).isInstanceOf(InvalidRequestException::class.java)
        assertThat((thrown as InvalidRequestException).error.errorCode).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST)
    }

    @Test
    fun `requested redirect uri is not registered in client`() {
        val registeredRedirectUriSet = setOf(URI.create("http://localhost/callback1"),
            URI.create("http://localhost/callback2"),
            URI.create("http://localhost/callback3"))
        val clientDetails: OAuth2ClientDetails = mockk {
            every { registeredRedirectUris } returns registeredRedirectUriSet
        }

        val thrown = catchThrowable { resolver.resolveRedirectURI("http://localhost/different", clientDetails) }
        assertThat(thrown).isInstanceOf(RedirectMismatchException::class.java)
    }

    @Test
    fun `requested redirect uri is registered in client`() {
        val registeredRedirectUriSet = setOf(URI.create("http://localhost/callback1"),
            URI.create("http://localhost/callback2"),
            URI.create("http://localhost/callback3"))
        val clientDetails: OAuth2ClientDetails = mockk {
            every { registeredRedirectUris } returns registeredRedirectUriSet
        }

        val result = resolver.resolveRedirectURI("http://localhost/callback1", clientDetails)
        assertThat(result).isEqualTo(URI.create("http://localhost/callback1"))
    }
}