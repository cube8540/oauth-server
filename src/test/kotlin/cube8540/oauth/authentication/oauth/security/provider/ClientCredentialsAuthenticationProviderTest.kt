package cube8540.oauth.authentication.oauth.security.provider

import cube8540.oauth.authentication.oauth.error.OAuth2ClientRegistrationException
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetailsService
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.catchThrowable
import org.junit.jupiter.api.Test
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.InternalAuthenticationServiceException
import org.springframework.security.crypto.password.PasswordEncoder

class ClientCredentialsAuthenticationProviderTest {

    private val service: OAuth2ClientDetailsService = mockk()
    private val encoder: PasswordEncoder = mockk()

    private val provider = ClientCredentialsAuthenticationProvider(service, encoder)

    @Test
    fun `authentication when requested client id is null`() {
        val token = ClientCredentialsToken(null, "clientPassword")

        val thrown = catchThrowable { provider.authenticate(token) }
        assertThat(thrown).isInstanceOf(BadCredentialsException::class.java)
    }

    @Test
    fun `authentication when requested client not found`() {
        val token = ClientCredentialsToken("clientId", "clientPassword")

        every { service.loadClientDetailsByClientId("clientId") }
            .throws(OAuth2ClientRegistrationException("clientId"))

        val thrown = catchThrowable { provider.authenticate(token) }
        assertThat(thrown).isInstanceOf(BadCredentialsException::class.java)
    }

    @Test
    fun `authentication when requested client password is null`() {
        val token = ClientCredentialsToken("clientId", null)
        val clientDetails: OAuth2ClientDetails = mockk()

        every { service.loadClientDetailsByClientId("clientId") } returns clientDetails

        val thrown = catchThrowable { provider.authenticate(token) }
        assertThat(thrown).isInstanceOf(BadCredentialsException::class.java)
    }

    @Test
    fun `authentication when requested client password is mismatch`() {
        val token = ClientCredentialsToken("clientId", "clientPassword")
        val clientDetails: OAuth2ClientDetails = mockk {
            every { clientSecret } returns "registeredClientPassword"
        }

        every { encoder.matches("clientPassword", "registeredClientPassword") } returns false
        every { service.loadClientDetailsByClientId("clientId") } returns clientDetails

        val thrown = catchThrowable { provider.authenticate(token) }
        assertThat(thrown).isInstanceOf(BadCredentialsException::class.java)
    }

    @Test
    fun `authentication successful`() {
        val token = ClientCredentialsToken("clientId", "clientPassword")
        val clientDetails: OAuth2ClientDetails = mockk {
            every { clientSecret } returns "registeredClientPassword"
        }

        every { encoder.matches("clientPassword", "registeredClientPassword") } returns true
        every { service.loadClientDetailsByClientId("clientId") } returns clientDetails

        val result = provider.authenticate(token)
        assertThat(result.principal).isEqualTo(clientDetails)
        assertThat(result.isAuthenticated).isTrue
    }

    @Test
    fun `unexpected exception occurs during authentication`() {
        val token = ClientCredentialsToken("clientId", "clientPassword")

        every { service.loadClientDetailsByClientId("clientId") } throws RuntimeException()

        val thrown = catchThrowable { provider.authenticate(token) }
        assertThat(thrown).isInstanceOf(InternalAuthenticationServiceException::class.java)
    }
}