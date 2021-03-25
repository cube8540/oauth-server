package cube8540.oauth.authentication.oauth.token.application

import cube8540.oauth.authentication.oauth.error.InvalidRequestException
import cube8540.oauth.authentication.oauth.token.domain.*
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.catchThrowable
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import java.util.*

class OAuth2ClientNotCheckedAccessTokenDetailsServiceTest {

    private val repository: OAuth2AccessTokenRepository = mockk()
    private val userDetailsService: UserDetailsService = mockk()

    private val service = OAuth2ClientNotCheckedAccessTokenDetailsService(repository, userDetailsService)

    @Nested
    inner class ReadAccessTokenTest {

        @Test
        fun `read not registered access token`() {
            every { repository.findById(OAuth2TokenId("tokenId")) } returns Optional.empty()

            val thrown = catchThrowable { service.readAccessToken("tokenId") }
            assertThat(thrown).isInstanceOf(OAuth2AccessTokenNotFoundException::class.java)
        }
    }

    @Nested
    inner class ReadAccessTokenUserTest {

        @Test
        fun `read not registered access token`() {
            every { repository.findById(OAuth2TokenId("tokenId")) } returns Optional.empty()

            val thrown = catchThrowable { service.readAccessTokenUser("tokenId") }
            assertThat(thrown).isInstanceOf(OAuth2AccessTokenNotFoundException::class.java)
        }

        @Test
        fun `read access token username is null`() {
            val accessToken: OAuth2AuthorizedAccessToken = mockk {
                every { username } returns null
            }

            every { repository.findById(OAuth2TokenId("tokenId")) } returns Optional.of(accessToken)

            val thrown = catchThrowable { service.readAccessTokenUser("tokenId") }
            assertThat(thrown).isInstanceOf(InvalidRequestException::class.java)
            assertThat((thrown as InvalidRequestException).error.errorCode).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST)
        }

        @Test
        fun `erase searched user sensitive data`() {
            val userDetails: User = mockk(relaxed = true)
            val accessToken: OAuth2AuthorizedAccessToken = mockk {
                every { username } returns PrincipalUsername("username")
            }

            every { repository.findById(OAuth2TokenId("tokenId")) } returns Optional.of(accessToken)
            every { userDetailsService.loadUserByUsername("username") } returns userDetails

            service.readAccessTokenUser("tokenId")
            verify { userDetails.eraseCredentials() }
        }
    }
}