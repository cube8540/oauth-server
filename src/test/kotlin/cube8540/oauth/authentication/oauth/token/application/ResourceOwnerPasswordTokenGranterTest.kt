package cube8540.oauth.authentication.oauth.token.application

import cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientId
import cube8540.oauth.authentication.oauth.error.InvalidGrantException
import cube8540.oauth.authentication.oauth.error.InvalidRequestException
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails
import cube8540.oauth.authentication.oauth.security.OAuth2RequestValidator
import cube8540.oauth.authentication.oauth.security.OAuth2TokenRequest
import cube8540.oauth.authentication.oauth.token.domain.*
import cube8540.oauth.authentication.security.AuthorityCode
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.catchThrowable
import org.junit.jupiter.api.Test
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.oauth2.core.OAuth2ErrorCodes

class ResourceOwnerPasswordTokenGranterTest {

    private val tokenIdGenerator: OAuth2TokenIdGenerator = mockk {
        every { generateTokenValue() } returns OAuth2TokenId("tokenId")
    }
    private val repository: OAuth2AccessTokenRepository = mockk(relaxed = true) {
        every { save(any()) } returnsArgument 0
    }
    private val validator: OAuth2RequestValidator = mockk()
    private val authenticationManager: AuthenticationManager = mockk(relaxed = true)

    private val granter = ResourceOwnerPasswordTokenGranter(tokenIdGenerator, repository, authenticationManager)

    init {
        granter.tokenRequestValidator = validator
    }

    @Test
    fun `create access token when request username is null`() {
        val clientDetails: OAuth2ClientDetails = mockk(relaxed = true)
        val tokenRequest: OAuth2TokenRequest = mockk {
            every { username } returns null
        }

        val thrown = catchThrowable { granter.createAccessToken(clientDetails, tokenRequest) }
        assertThat(thrown).isInstanceOf(InvalidRequestException::class.java)
        assertThat((thrown as InvalidRequestException).error.errorCode).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST)
    }

    @Test
    fun `create access token when request password is null`() {
        val clientDetails: OAuth2ClientDetails = mockk(relaxed = true)
        val tokenRequest: OAuth2TokenRequest = mockk {
            every { username } returns "username"
            every { password } returns null
        }

        val thrown = catchThrowable { granter.createAccessToken(clientDetails, tokenRequest) }
        assertThat(thrown).isInstanceOf(InvalidRequestException::class.java)
        assertThat((thrown as InvalidRequestException).error.errorCode).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST)
    }

    @Test
    fun `create access token when request scope is invalid`() {
        val clientDetails: OAuth2ClientDetails = mockk(relaxed = true)
        val tokenRequest: OAuth2TokenRequest = mockk {
            every { username } returns "username"
            every { password } returns "password"
            every { scopes } returns setOf("scope-1", "scope-2", "scope-3")
        }

        every { validator.validateScopes(clientDetails, setOf("scope-1", "scope-2", "scope-3")) } returns false

        val thrown = catchThrowable { granter.createAccessToken(clientDetails, tokenRequest) }
        assertThat(thrown).isInstanceOf(InvalidGrantException::class.java)
        assertThat((thrown as InvalidGrantException).error.errorCode).isEqualTo(OAuth2ErrorCodes.INVALID_SCOPE)
    }

    @Test
    fun `create access token when authentication fails`() {
        val clientDetails: OAuth2ClientDetails = mockk(relaxed = true)
        val tokenRequest: OAuth2TokenRequest = mockk {
            every { username } returns "username"
            every { password } returns "password"
            every { scopes } returns setOf("scope-1", "scope-2", "scope-3")
        }

        every { validator.validateScopes(clientDetails, setOf("scope-1", "scope-2", "scope-3")) } returns true
        every { authenticationManager.authenticate(UsernamePasswordAuthenticationToken("username", "password")) }
            .throws(BadCredentialsException("authentication fails"))

        val thrown = catchThrowable { granter.createAccessToken(clientDetails, tokenRequest) }
        assertThat(thrown).isInstanceOf(AuthenticationException::class.java)
    }

    @Test
    fun `create access token when refresh token id generator is not set`() {
        val clientDetails: OAuth2ClientDetails = mockk(relaxed = true) {
            every { clientId } returns "clientId"
        }
        val authentication: Authentication = mockk(relaxed = true) {
            every { name } returns "username"
        }
        val tokenRequest: OAuth2TokenRequest = mockk {
            every { username } returns "username"
            every { password } returns "password"
            every { scopes } returns setOf("scope-1", "scope-2", "scope-3")
        }

        granter.refreshTokenIdGenerator = null
        every { validator.validateScopes(clientDetails, setOf("scope-1", "scope-2", "scope-3")) } returns true
        every { authenticationManager.authenticate(UsernamePasswordAuthenticationToken("username", "password")) }
            .returns(authentication)

        val accessToken: OAuth2AuthorizedAccessToken = granter.createAccessToken(clientDetails, tokenRequest)
        assertThat(accessToken.refreshToken).isNotNull
        assertThat(accessToken.refreshToken!!.tokenId).isEqualTo(OAuth2TokenId("tokenId"))
        assertThat(accessToken.tokenId).isEqualTo(OAuth2TokenId("tokenId"))
        assertThat(accessToken.client).isEqualTo(OAuth2ClientId("clientId"))
        assertThat(accessToken.username).isEqualTo(PrincipalUsername("username"))
    }

    @Test
    fun `create access token when refresh token id generator is set`() {
        val clientDetails: OAuth2ClientDetails = mockk(relaxed = true) {
            every { clientId } returns "clientId"
        }
        val authentication: Authentication = mockk(relaxed = true) {
            every { name } returns "username"
        }
        val tokenRequest: OAuth2TokenRequest = mockk {
            every { username } returns "username"
            every { password } returns "password"
            every { scopes } returns setOf("scope-1", "scope-2", "scope-3")
        }

        granter.refreshTokenIdGenerator = mockk {
            every { generateTokenValue() } returns OAuth2TokenId("refreshTokenId")
        }
        every { validator.validateScopes(clientDetails, setOf("scope-1", "scope-2", "scope-3")) } returns true
        every { authenticationManager.authenticate(UsernamePasswordAuthenticationToken("username", "password")) }
            .returns(authentication)

        val accessToken: OAuth2AuthorizedAccessToken = granter.createAccessToken(clientDetails, tokenRequest)
        assertThat(accessToken.refreshToken).isNotNull
        assertThat(accessToken.refreshToken!!.tokenId).isEqualTo(OAuth2TokenId("refreshTokenId"))
        assertThat(accessToken.tokenId).isEqualTo(OAuth2TokenId("tokenId"))
        assertThat(accessToken.client).isEqualTo(OAuth2ClientId("clientId"))
        assertThat(accessToken.username).isEqualTo(PrincipalUsername("username"))
    }

    @Test
    fun `create access token when request scope is null`() {
        val clientDetails: OAuth2ClientDetails = mockk(relaxed = true) {
            every { clientId } returns "clientId"
            every { scopes } returns setOf("client-scope-1", "client-scope-2", "client-scope-3")
        }
        val authentication: Authentication = mockk(relaxed = true) {
            every { name } returns "username"
        }
        val tokenRequest: OAuth2TokenRequest = mockk {
            every { username } returns "username"
            every { password } returns "password"
            every { scopes } returns null
        }

        every { validator.validateScopes(clientDetails, null) } returns true
        every { authenticationManager.authenticate(UsernamePasswordAuthenticationToken("username", "password")) }
            .returns(authentication)

        val accessToken: OAuth2AuthorizedAccessToken = granter.createAccessToken(clientDetails, tokenRequest)
        assertThat(accessToken.scopes).isEqualTo(setOf(AuthorityCode("client-scope-1"), AuthorityCode("client-scope-2"), AuthorityCode("client-scope-3")))
        assertThat(accessToken.tokenId).isEqualTo(OAuth2TokenId("tokenId"))
        assertThat(accessToken.client).isEqualTo(OAuth2ClientId("clientId"))
        assertThat(accessToken.username).isEqualTo(PrincipalUsername("username"))
    }

    @Test
    fun `create access token when request scope is empty`() {
        val clientDetails: OAuth2ClientDetails = mockk(relaxed = true) {
            every { clientId } returns "clientId"
            every { scopes } returns setOf("client-scope-1", "client-scope-2", "client-scope-3")
        }
        val authentication: Authentication = mockk(relaxed = true) {
            every { name } returns "username"
        }
        val tokenRequest: OAuth2TokenRequest = mockk {
            every { username } returns "username"
            every { password } returns "password"
            every { scopes } returns emptySet()
        }

        every { validator.validateScopes(clientDetails, emptySet()) } returns true
        every { authenticationManager.authenticate(UsernamePasswordAuthenticationToken("username", "password")) }
            .returns(authentication)

        val accessToken: OAuth2AuthorizedAccessToken = granter.createAccessToken(clientDetails, tokenRequest)
        assertThat(accessToken.scopes).isEqualTo(setOf(AuthorityCode("client-scope-1"), AuthorityCode("client-scope-2"), AuthorityCode("client-scope-3")))
        assertThat(accessToken.tokenId).isEqualTo(OAuth2TokenId("tokenId"))
        assertThat(accessToken.client).isEqualTo(OAuth2ClientId("clientId"))
        assertThat(accessToken.username).isEqualTo(PrincipalUsername("username"))
    }

    @Test
    fun `create access token when request scope is allowed`() {
        val clientDetails: OAuth2ClientDetails = mockk(relaxed = true) {
            every { clientId } returns "clientId"
            every { scopes } returns setOf("client-scope-1", "client-scope-2", "client-scope-3")
        }
        val authentication: Authentication = mockk(relaxed = true) {
            every { name } returns "username"
        }
        val tokenRequest: OAuth2TokenRequest = mockk {
            every { username } returns "username"
            every { password } returns "password"
            every { scopes } returns setOf("request-scope-1", "request-scope-2", "request-scope-3")
        }

        every { validator.validateScopes(clientDetails, setOf("request-scope-1", "request-scope-2", "request-scope-3")) } returns true
        every { authenticationManager.authenticate(UsernamePasswordAuthenticationToken("username", "password")) }
            .returns(authentication)

        val accessToken: OAuth2AuthorizedAccessToken = granter.createAccessToken(clientDetails, tokenRequest)
        assertThat(accessToken.scopes).isEqualTo(setOf(AuthorityCode("request-scope-1"), AuthorityCode("request-scope-2"), AuthorityCode("request-scope-3")))
        assertThat(accessToken.tokenId).isEqualTo(OAuth2TokenId("tokenId"))
        assertThat(accessToken.client).isEqualTo(OAuth2ClientId("clientId"))
        assertThat(accessToken.username).isEqualTo(PrincipalUsername("username"))
    }
}