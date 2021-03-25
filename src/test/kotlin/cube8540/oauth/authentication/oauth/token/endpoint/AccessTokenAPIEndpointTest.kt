package cube8540.oauth.authentication.oauth.token.endpoint

import cube8540.oauth.authentication.oauth.security.OAuth2AccessTokenDetails
import cube8540.oauth.authentication.oauth.security.OAuth2TokenRevoker
import cube8540.oauth.authentication.oauth.token.application.AccessTokenReadService
import cube8540.oauth.authentication.oauth.token.domain.AccessTokenDetailsWithClient
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class AccessTokenAPIEndpointTest {

    private val service: AccessTokenReadService = mockk()
    private val revoker: OAuth2TokenRevoker = mockk()

    private val endpoint = AccessTokenAPIEndpoint(service, revoker)

    @Test
    fun `get user access token`() {
        val accessTokenDetails: List<AccessTokenDetailsWithClient> = mockk()

        every { service.getAuthorizeAccessTokens("username") } returns accessTokenDetails

        val result = endpoint.getUserAccessToken("username")
        assertThat(result["tokens"]).isEqualTo(accessTokenDetails)
    }

    @Test
    fun `delete user access token`() {
        val tokenDetails: OAuth2AccessTokenDetails = mockk()

        every { revoker.revoke("accessToken") } returns tokenDetails

        val result = endpoint.deleteUserAccessToken("accessToken")
        assertThat(result).isEqualTo(tokenDetails)
    }
}