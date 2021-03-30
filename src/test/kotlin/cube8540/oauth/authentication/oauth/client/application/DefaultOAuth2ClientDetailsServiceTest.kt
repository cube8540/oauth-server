package cube8540.oauth.authentication.oauth.client.application

import cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientId
import cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientRepository
import cube8540.oauth.authentication.oauth.error.OAuth2ClientRegistrationException
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.catchThrowable
import org.junit.jupiter.api.Test
import java.util.*

class DefaultOAuth2ClientDetailsServiceTest {

    private val repository: OAuth2ClientRepository = mockk()

    private val service = DefaultOAuth2ClientDetailsService(repository)

    @Test
    fun `search not registered client in repository`() {
        every { repository.findByClientId(OAuth2ClientId("clientId")) } returns Optional.empty()

        val thrown = catchThrowable { service.loadClientDetailsByClientId("clientId") }
        assertThat(thrown).isInstanceOf(OAuth2ClientRegistrationException::class.java)
    }
}