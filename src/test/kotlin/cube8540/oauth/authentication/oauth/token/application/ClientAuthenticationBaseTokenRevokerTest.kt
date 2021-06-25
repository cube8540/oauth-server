package cube8540.oauth.authentication.oauth.token.application

import cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientId
import cube8540.oauth.authentication.oauth.error.InvalidClientException
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AccessTokenNotFoundException
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AccessTokenRepository
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizedAccessToken
import cube8540.oauth.authentication.oauth.token.domain.OAuth2TokenId
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import java.util.Optional
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.catchThrowable
import org.junit.jupiter.api.Test
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.core.OAuth2ErrorCodes

class ClientAuthenticationBaseTokenRevokerTest {

    private val repository: OAuth2AccessTokenRepository = mockk(relaxed = true)

    private val revoker = ClientAuthenticationBaseTokenRevoker(repository)

    @Test
    fun `revoking not registered access token`() {
        every { repository.findById(OAuth2TokenId("tokenId")) } returns Optional.empty()

        val thrown = catchThrowable { revoker.revoke("tokenId") }
        assertThat(thrown).isInstanceOf(OAuth2AccessTokenNotFoundException::class.java)
    }

    @Test
    fun `requester is not matches token owner`() {
        val accessToken: OAuth2AuthorizedAccessToken = mockk {
            every { client } returns OAuth2ClientId("clientId")
        }

        SecurityContextHolder.getContext().authentication = mockk {
            every { name } returns "differentClient"
        }
        every { repository.findById(OAuth2TokenId("tokenId")) } returns Optional.of(accessToken)

        val thrown = catchThrowable { revoker.revoke("tokenId") }
        assertThat(thrown).isInstanceOf(InvalidClientException::class.java)
        assertThat((thrown as InvalidClientException).error.errorCode).isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT)
    }

    @Test
    fun `revoking successful`() {
        val accessToken: OAuth2AuthorizedAccessToken = mockk(relaxed = true) {
            every { client } returns OAuth2ClientId("clientId")
        }

        SecurityContextHolder.getContext().authentication = mockk {
            every { name } returns "clientId"
        }
        every { repository.findById(OAuth2TokenId("tokenId")) } returns Optional.of(accessToken)

        revoker.revoke("tokenId")
        verify { repository.delete(accessToken) }
    }
}