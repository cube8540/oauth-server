package cube8540.oauth.authentication.oauth.token.application

import cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientId
import cube8540.oauth.authentication.oauth.error.InvalidClientException
import cube8540.oauth.authentication.oauth.error.InvalidRequestException
import cube8540.oauth.authentication.oauth.token.domain.*
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.catchThrowable
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import java.util.*

class DefaultOAuth2AccessTokenDetailsServiceTest {

    private val repository: OAuth2AccessTokenRepository = mockk(relaxed = true)
    private val userDetailsService: UserDetailsService = mockk()

    private val service = DefaultOAuth2AccessTokenDetailsService(repository, userDetailsService)

    @Nested
    inner class ReadAccessTokenTest {

        @Test
        fun `read not registered access token`() {
            every { repository.findById(OAuth2TokenId("tokenId")) } returns Optional.empty()

            val thrown = catchThrowable { service.readAccessToken("tokenId") }
            assertThat(thrown).isInstanceOf(OAuth2AccessTokenNotFoundException::class.java)
        }

        @Test
        fun `read access token client is different requested client`() {
            val authentication: Authentication = mockk {
                every { name } returns "differentClientId"
            }
            val accessToken: OAuth2AuthorizedAccessToken = mockk {
                every { client } returns OAuth2ClientId("clientId")
            }

            every { repository.findById(OAuth2TokenId("tokenId")) } returns Optional.of(accessToken)
            SecurityContextHolder.getContext().authentication = authentication

            val thrown = catchThrowable { service.readAccessToken("tokenId") }
            assertThat(thrown).isInstanceOf(InvalidClientException::class.java)
            assertThat((thrown as InvalidClientException).error.errorCode).isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT)
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
        fun `read access token client is different requested client`() {
            val authentication: Authentication = mockk {
                every { name } returns "differentClientId"
            }
            val accessToken: OAuth2AuthorizedAccessToken = mockk {
                every { client } returns OAuth2ClientId("clientId")
            }

            every { repository.findById(OAuth2TokenId("tokenId")) } returns Optional.of(accessToken)
            SecurityContextHolder.getContext().authentication = authentication

            val thrown = catchThrowable { service.readAccessTokenUser("tokenId") }
            assertThat(thrown).isInstanceOf(InvalidClientException::class.java)
            assertThat((thrown as InvalidClientException).error.errorCode).isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT)
        }

        @Test
        fun `read access token username is null`() {
            val authentication: Authentication = mockk {
                every { name } returns "clientId"
            }
            val accessToken: OAuth2AuthorizedAccessToken = mockk {
                every { client } returns OAuth2ClientId("clientId")
                every { username } returns null
            }

            every { repository.findById(OAuth2TokenId("tokenId")) } returns Optional.of(accessToken)
            SecurityContextHolder.getContext().authentication = authentication

            val thrown = catchThrowable { service.readAccessTokenUser("tokenId") }
            assertThat(thrown).isInstanceOf(InvalidRequestException::class.java)
            assertThat((thrown as InvalidRequestException).error.errorCode).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST)
        }

        @Test
        fun `erase searched user sensitive data`() {
            val userDetails: User = mockk(relaxed = true)
            val authentication: Authentication = mockk {
                every { name } returns "clientId"
            }
            val accessToken: OAuth2AuthorizedAccessToken = mockk {
                every { client } returns OAuth2ClientId("clientId")
                every { username } returns PrincipalUsername("username")
            }

            every { userDetailsService.loadUserByUsername("username") } returns userDetails
            every { repository.findById(OAuth2TokenId("tokenId")) } returns Optional.of(accessToken)
            SecurityContextHolder.getContext().authentication = authentication

            service.readAccessTokenUser("tokenId")
            verify { userDetails.eraseCredentials() }
        }
    }
}