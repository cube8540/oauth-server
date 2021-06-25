package cube8540.oauth.authentication.oauth.token.application

import cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientId
import cube8540.oauth.authentication.oauth.error.InvalidClientException
import cube8540.oauth.authentication.oauth.error.InvalidGrantException
import cube8540.oauth.authentication.oauth.error.InvalidRequestException
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails
import cube8540.oauth.authentication.oauth.security.OAuth2RequestValidator
import cube8540.oauth.authentication.oauth.security.OAuth2TokenRequest
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AccessTokenRepository
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizedAccessToken
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizedRefreshToken
import cube8540.oauth.authentication.oauth.token.domain.OAuth2RefreshTokenRepository
import cube8540.oauth.authentication.oauth.token.domain.OAuth2TokenId
import cube8540.oauth.authentication.oauth.token.domain.OAuth2TokenIdGenerator
import cube8540.oauth.authentication.oauth.token.domain.PrincipalUsername
import cube8540.oauth.authentication.security.AuthorityCode
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import java.util.Optional
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.catchThrowable
import org.junit.jupiter.api.Test
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.OAuth2ErrorCodes

class RefreshTokenGranterTest {

    private val tokenIdGenerator: OAuth2TokenIdGenerator = mockk {
        every { generateTokenValue() } returns OAuth2TokenId("tokenId")
    }
    private val refreshTokenRepository: OAuth2RefreshTokenRepository = mockk(relaxed = true) {
        every { save(any()) } returnsArgument 0
    }
    private val repository: OAuth2AccessTokenRepository = mockk(relaxed = true) {
        every { save(any()) } returnsArgument 0
    }
    private val validator: OAuth2RequestValidator = mockk()

    private val granter = RefreshTokenGranter(repository, refreshTokenRepository, tokenIdGenerator)

    init {
        granter.tokenRequestValidator = validator
    }

    @Test
    fun `create access token when request refresh token is null`() {
        val clientDetails: OAuth2ClientDetails = mockk()
        val tokenRequest: OAuth2TokenRequest = mockk {
            every { refreshToken } returns null
        }

        val thrown = catchThrowable { granter.createAccessToken(clientDetails, tokenRequest) }
        assertThat(thrown).isInstanceOf(InvalidRequestException::class.java)
        assertThat((thrown as InvalidRequestException).error.errorCode).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST)
    }

    @Test
    fun `create access token when request refresh token is not found`() {
        val clientDetails: OAuth2ClientDetails = mockk()
        val tokenRequest: OAuth2TokenRequest = mockk {
            every { refreshToken } returns "requestRefreshToken"
        }

        every { refreshTokenRepository.findById(OAuth2TokenId("requestRefreshToken")) } returns Optional.empty()

        val thrown = catchThrowable { granter.createAccessToken(clientDetails, tokenRequest) }
        assertThat(thrown).isInstanceOf(InvalidGrantException::class.java)
        assertThat((thrown as InvalidGrantException).error.errorCode).isEqualTo(OAuth2ErrorCodes.INVALID_GRANT)
    }

    @Test
    fun `create access token when refresh token client is different request client`() {
        val clientDetails: OAuth2ClientDetails = mockk {
            every { clientId } returns "clientId"
        }
        val tokenRequest: OAuth2TokenRequest = mockk {
            every { refreshToken } returns "requestRefreshToken"
        }
        val storedRefreshToken: OAuth2AuthorizedRefreshToken = mockk(relaxed = true) {
            every { isExpired() } returns false
            every { accessToken } returns mockk {
                every { client } returns OAuth2ClientId("differentId")
            }
        }

        every { refreshTokenRepository.findById(OAuth2TokenId("requestRefreshToken")) } returns Optional.of(storedRefreshToken)

        val thrown = catchThrowable { granter.createAccessToken(clientDetails, tokenRequest) }
        assertThat(thrown).isInstanceOf(InvalidClientException::class.java)
        assertThat((thrown as InvalidClientException).error.errorCode).isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT)
    }

    @Test
    fun `create access token when request refresh token is expired`() {
        val clientDetails: OAuth2ClientDetails = mockk {
            every { clientId } returns "clientId"
        }
        val tokenRequest: OAuth2TokenRequest = mockk {
            every { refreshToken } returns "requestRefreshToken"
        }
        val storedRefreshToken: OAuth2AuthorizedRefreshToken = mockk(relaxed = true) {
            every { isExpired() } returns true
            every { accessToken } returns mockk {
                every { client } returns OAuth2ClientId("clientId")
            }
        }

        every { refreshTokenRepository.findById(OAuth2TokenId("requestRefreshToken")) } returns Optional.of(storedRefreshToken)

        val thrown = catchThrowable { granter.createAccessToken(clientDetails, tokenRequest) }
        verify(exactly = 1) { refreshTokenRepository.delete(eq(storedRefreshToken)) }
        assertThat(thrown).isInstanceOf(InvalidGrantException::class.java)
        assertThat((thrown as InvalidGrantException).error.errorCode).isEqualTo(OAuth2ErrorCodes.INVALID_GRANT)
    }

    @Test
    fun `create access token when request scope is invalid`() {
        val clientDetails: OAuth2ClientDetails = mockk {
            every { clientId } returns "clientId"
        }
        val tokenRequest: OAuth2TokenRequest = mockk {
            every { scopes } returns setOf("request-scope-1", "request-scope-2", "request-scope-3")
            every { refreshToken } returns "requestRefreshToken"
        }
        val storedRefreshToken: OAuth2AuthorizedRefreshToken = mockk(relaxed = true) {
            every { isExpired() } returns false
            every { accessToken } returns mockk {
                every { client } returns OAuth2ClientId("clientId")
                every { scopes } returns setOf(AuthorityCode("stored-scope-1"), AuthorityCode("stored-scope-2"), AuthorityCode("stored-scope-3")).toMutableSet()
            }
        }

        every { validator.validateScopes(setOf("stored-scope-1", "stored-scope-2", "stored-scope-3"), setOf("request-scope-1", "request-scope-2", "request-scope-3")) }
            .returns(false)
        every { refreshTokenRepository.findById(OAuth2TokenId("requestRefreshToken")) } returns Optional.of(storedRefreshToken)

        val thrown = catchThrowable { granter.createAccessToken(clientDetails, tokenRequest) }
        verify(exactly = 1) { refreshTokenRepository.delete(eq(storedRefreshToken)) }
        assertThat(thrown).isInstanceOf(InvalidGrantException::class.java)
        assertThat((thrown as InvalidGrantException).error.errorCode).isEqualTo(OAuth2ErrorCodes.INVALID_SCOPE)
    }

    @Test
    fun `create access token when request scope is allowed and refresh token id generator is not set`() {
        val clientDetails: OAuth2ClientDetails = mockk {
            every { clientId } returns "clientId"
            every { accessTokenValiditySeconds } returns 10
            every { refreshTokenValiditySeconds } returns 10
        }
        val tokenRequest: OAuth2TokenRequest = mockk {
            every { scopes } returns setOf("request-scope-1", "request-scope-2", "request-scope-3")
            every { refreshToken } returns "requestRefreshToken"
        }
        val storedAccessToken: OAuth2AuthorizedAccessToken = mockk {
            every { username } returns PrincipalUsername("username")
            every { client } returns OAuth2ClientId("clientId")
            every { tokenGrantType } returns AuthorizationGrantType.AUTHORIZATION_CODE
            every { scopes } returns setOf(AuthorityCode("stored-scope-1"), AuthorityCode("stored-scope-2"), AuthorityCode("stored-scope-3")).toMutableSet()

        }
        val storedRefreshToken: OAuth2AuthorizedRefreshToken = mockk(relaxed = true) {
            every { isExpired() } returns false
            every { accessToken } returns storedAccessToken
        }

        granter.refreshTokenIdGenerator = null
        every { validator.validateScopes(setOf("stored-scope-1", "stored-scope-2", "stored-scope-3"), setOf("request-scope-1", "request-scope-2", "request-scope-3")) }
            .returns(true)
        every { refreshTokenRepository.findById(OAuth2TokenId("requestRefreshToken")) } returns Optional.of(storedRefreshToken)

        val result = granter.createAccessToken(clientDetails, tokenRequest)
        assertThat(result.tokenId).isEqualTo(OAuth2TokenId("tokenId"))
        assertThat(result.client).isEqualTo(OAuth2ClientId("clientId"))
        assertThat(result.username).isEqualTo(PrincipalUsername("username"))
        assertThat(result.tokenGrantType).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE)
        assertThat(result.refreshToken).isNotNull
        assertThat(result.refreshToken!!.tokenId).isEqualTo(OAuth2TokenId("tokenId"))
        verify { refreshTokenRepository.delete(storedRefreshToken) }
    }

    @Test
    fun `create access token when request scope is allowed and refresh token id generator is set`() {
        val clientDetails: OAuth2ClientDetails = mockk {
            every { clientId } returns "clientId"
            every { accessTokenValiditySeconds } returns 10
            every { refreshTokenValiditySeconds } returns 10
        }
        val tokenRequest: OAuth2TokenRequest = mockk {
            every { scopes } returns setOf("request-scope-1", "request-scope-2", "request-scope-3")
            every { refreshToken } returns "requestRefreshToken"
        }
        val storedAccessToken: OAuth2AuthorizedAccessToken = mockk {
            every { username } returns PrincipalUsername("username")
            every { client } returns OAuth2ClientId("clientId")
            every { tokenGrantType } returns AuthorizationGrantType.AUTHORIZATION_CODE
            every { scopes } returns setOf(AuthorityCode("stored-scope-1"), AuthorityCode("stored-scope-2"), AuthorityCode("stored-scope-3")).toMutableSet()

        }
        val storedRefreshToken: OAuth2AuthorizedRefreshToken = mockk(relaxed = true) {
            every { isExpired() } returns false
            every { accessToken } returns storedAccessToken
        }

        granter.refreshTokenIdGenerator = mockk {
            every { generateTokenValue() } returns OAuth2TokenId("refreshTokenId")
        }
        every { validator.validateScopes(setOf("stored-scope-1", "stored-scope-2", "stored-scope-3"), setOf("request-scope-1", "request-scope-2", "request-scope-3")) }
            .returns(true)
        every { refreshTokenRepository.findById(OAuth2TokenId("requestRefreshToken")) } returns Optional.of(storedRefreshToken)

        val result = granter.createAccessToken(clientDetails, tokenRequest)
        assertThat(result.tokenId).isEqualTo(OAuth2TokenId("tokenId"))
        assertThat(result.client).isEqualTo(OAuth2ClientId("clientId"))
        assertThat(result.username).isEqualTo(PrincipalUsername("username"))
        assertThat(result.tokenGrantType).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE)
        assertThat(result.refreshToken).isNotNull
        assertThat(result.refreshToken!!.tokenId).isEqualTo(OAuth2TokenId("refreshTokenId"))
        verify { refreshTokenRepository.delete(storedRefreshToken) }
    }

    @Test
    fun `create access token when request scope is null`() {
        val clientDetails: OAuth2ClientDetails = mockk {
            every { clientId } returns "clientId"
            every { accessTokenValiditySeconds } returns 10
            every { refreshTokenValiditySeconds } returns 10
        }
        val tokenRequest: OAuth2TokenRequest = mockk {
            every { scopes } returns null
            every { refreshToken } returns "requestRefreshToken"
        }
        val storedAccessToken: OAuth2AuthorizedAccessToken = mockk {
            every { username } returns PrincipalUsername("username")
            every { client } returns OAuth2ClientId("clientId")
            every { tokenGrantType } returns AuthorizationGrantType.AUTHORIZATION_CODE
            every { scopes } returns setOf(AuthorityCode("stored-scope-1"), AuthorityCode("stored-scope-2"), AuthorityCode("stored-scope-3")).toMutableSet()

        }
        val storedRefreshToken: OAuth2AuthorizedRefreshToken = mockk(relaxed = true) {
            every { isExpired() } returns false
            every { accessToken } returns storedAccessToken
        }

        every { validator.validateScopes(setOf("stored-scope-1", "stored-scope-2", "stored-scope-3"), null) }
            .returns(true)
        every { refreshTokenRepository.findById(OAuth2TokenId("requestRefreshToken")) } returns Optional.of(storedRefreshToken)

        val result = granter.createAccessToken(clientDetails, tokenRequest)
        assertThat(result.scopes).isEqualTo(setOf(AuthorityCode("stored-scope-1"), AuthorityCode("stored-scope-2"), AuthorityCode("stored-scope-3")))
    }

    @Test
    fun `create access token when request scope is empty`() {
        val clientDetails: OAuth2ClientDetails = mockk {
            every { clientId } returns "clientId"
            every { accessTokenValiditySeconds } returns 10
            every { refreshTokenValiditySeconds } returns 10
        }
        val tokenRequest: OAuth2TokenRequest = mockk {
            every { scopes } returns emptySet()
            every { refreshToken } returns "requestRefreshToken"
        }
        val storedAccessToken: OAuth2AuthorizedAccessToken = mockk {
            every { username } returns PrincipalUsername("username")
            every { client } returns OAuth2ClientId("clientId")
            every { tokenGrantType } returns AuthorizationGrantType.AUTHORIZATION_CODE
            every { scopes } returns setOf(AuthorityCode("stored-scope-1"), AuthorityCode("stored-scope-2"), AuthorityCode("stored-scope-3")).toMutableSet()

        }
        val storedRefreshToken: OAuth2AuthorizedRefreshToken = mockk(relaxed = true) {
            every { isExpired() } returns false
            every { accessToken } returns storedAccessToken
        }

        every { validator.validateScopes(setOf("stored-scope-1", "stored-scope-2", "stored-scope-3"), emptySet()) }
            .returns(true)
        every { refreshTokenRepository.findById(OAuth2TokenId("requestRefreshToken")) } returns Optional.of(storedRefreshToken)

        val result = granter.createAccessToken(clientDetails, tokenRequest)
        assertThat(result.scopes).isEqualTo(setOf(AuthorityCode("stored-scope-1"), AuthorityCode("stored-scope-2"), AuthorityCode("stored-scope-3")))
    }

    @Test
    fun `returns existing token method should false`() {
        assertThat(granter.isReturnsExistsToken(mockk(), mockk())).isFalse
    }
}