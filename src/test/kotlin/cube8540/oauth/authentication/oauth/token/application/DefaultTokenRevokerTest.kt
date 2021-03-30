package cube8540.oauth.authentication.oauth.token.application

import cube8540.oauth.authentication.oauth.token.domain.OAuth2AccessTokenRepository
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizedAccessToken
import cube8540.oauth.authentication.oauth.token.domain.OAuth2TokenId
import cube8540.oauth.authentication.oauth.token.domain.TokenNotFoundException
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.catchThrowable
import org.junit.jupiter.api.Test
import java.util.*

class DefaultTokenRevokerTest {

    private val repository: OAuth2AccessTokenRepository = mockk(relaxed = true)

    private val revoker = DefaultTokenRevoker(repository)

    @Test
    fun `revoking not registered access token`() {
        every { repository.findById(OAuth2TokenId("tokenId")) } returns Optional.empty()

        val thrown = catchThrowable { revoker.revoke("tokenId") }
        assertThat(thrown).isInstanceOf(TokenNotFoundException::class.java)
    }

    @Test
    fun `revoking access token`() {
        val accessToken: OAuth2AuthorizedAccessToken = mockk(relaxed = true)

        every { repository.findById(OAuth2TokenId("tokenId")) } returns Optional.of(accessToken)

        revoker.revoke("tokenId")
        verify { repository.delete(accessToken) }
    }

}