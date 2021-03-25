package cube8540.oauth.authentication.oauth.token.application

import cube8540.oauth.authentication.oauth.token.domain.AccessTokenDetailsWithClient
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AccessTokenReadRepository
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class DefaultAccessTokenReadServiceTest {

    private val repository: OAuth2AccessTokenReadRepository = mockk()

    private val service = DefaultAccessTokenReadService(repository)

    @Test
    fun `get authenticated user access token`() {
        val accessTokenDetailsWithClient: List<AccessTokenDetailsWithClient> = mockk()

        every { repository.readAccessTokenWithClientByUsername("username") } returns accessTokenDetailsWithClient

        val result = service.getAuthorizeAccessTokens("username")
        assertThat(result).isEqualTo(accessTokenDetailsWithClient)
    }
}