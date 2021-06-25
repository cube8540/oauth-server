package cube8540.oauth.authentication.oauth.token.application

import cube8540.oauth.authentication.oauth.token.domain.OAuth2AccessTokenNotFoundException
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AccessTokenRepository
import cube8540.oauth.authentication.oauth.token.domain.OAuth2TokenId
import io.mockk.every
import io.mockk.mockk
import java.util.Optional
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.catchThrowable
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

class OAuth2ClientNotCheckedAccessTokenDetailsServiceTest {

    private val repository: OAuth2AccessTokenRepository = mockk()

    private val service = OAuth2ClientNotCheckingAccessTokenDetailsService(repository)

    @Nested
    inner class ReadAccessTokenTest {

        @Test
        fun `read not registered access token`() {
            every { repository.findById(OAuth2TokenId("tokenId")) } returns Optional.empty()

            val thrown = catchThrowable { service.readAccessToken("tokenId") }
            assertThat(thrown).isInstanceOf(OAuth2AccessTokenNotFoundException::class.java)
        }
    }
}