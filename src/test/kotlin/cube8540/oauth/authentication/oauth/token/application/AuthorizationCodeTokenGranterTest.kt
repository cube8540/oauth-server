package cube8540.oauth.authentication.oauth.token.application

import com.nimbusds.oauth2.sdk.pkce.CodeVerifier
import cube8540.oauth.authentication.UnitTestAuthenticationException
import cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientId
import cube8540.oauth.authentication.oauth.error.InvalidGrantException
import cube8540.oauth.authentication.oauth.error.InvalidRequestException
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails
import cube8540.oauth.authentication.oauth.security.OAuth2RequestValidator
import cube8540.oauth.authentication.oauth.security.OAuth2TokenRequest
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AccessTokenRepository
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizationCode
import cube8540.oauth.authentication.oauth.token.domain.OAuth2TokenId
import cube8540.oauth.authentication.oauth.token.domain.OAuth2TokenIdGenerator
import cube8540.oauth.authentication.oauth.token.domain.PrincipalUsername
import cube8540.oauth.authentication.security.AuthorityCode
import io.mockk.Runs
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.slot
import java.net.URI
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.catchThrowable
import org.junit.jupiter.api.Test
import org.springframework.security.oauth2.core.OAuth2ErrorCodes

class AuthorizationCodeTokenGranterTest {

    private val tokenIdGenerator: OAuth2TokenIdGenerator = mockk {
        every { generateTokenValue() } returns OAuth2TokenId("tokenId")
    }
    private val repository: OAuth2AccessTokenRepository = mockk(relaxed = true) {
        every { save(any()) } returnsArgument 0
    }
    private val consumer: OAuth2AuthorizationCodeConsumer = mockk()
    private val validator: OAuth2RequestValidator = mockk()

    private val granter: AuthorizationCodeTokenGranter = AuthorizationCodeTokenGranter(tokenIdGenerator, repository, consumer)

    init {
        granter.tokenRequestValidator = validator
    }

    @Test
    fun `create access token when request authorization code is null`() {
        val clientDetails: OAuth2ClientDetails = mockk()
        val tokenRequest: OAuth2TokenRequest = mockk {
            every { code } returns null
        }

        val thrown = catchThrowable { granter.createAccessToken(clientDetails, tokenRequest) }
        assertThat(thrown).isInstanceOf(InvalidRequestException::class.java)
        assertThat((thrown as InvalidRequestException).error.errorCode).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST)
    }

    @Test
    fun `create access token when request authorization code is not found`() {
        val clientDetails: OAuth2ClientDetails = mockk()
        val tokenRequest: OAuth2TokenRequest = mockk {
            every { code } returns "authorizationCode"
        }

        every { consumer.consume("authorizationCode") } returns null

        val thrown = catchThrowable { granter.createAccessToken(clientDetails, tokenRequest) }
        assertThat(thrown).isInstanceOf(InvalidRequestException::class.java)
        assertThat((thrown as InvalidRequestException).error.errorCode).isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST)
    }

    @Test
    fun `create access token when request authorization code scope is invalid`() {
        val clientDetails: OAuth2ClientDetails = mockk(relaxed = true)
        val tokenRequest: OAuth2TokenRequest = mockk {
            every { code } returns "authorizationCode"
        }
        val authorizationCode: OAuth2AuthorizationCode = mockk {
            every { code } returns "authorizationCode"
            every { clientId } returns OAuth2ClientId("clientId")
            every { username } returns PrincipalUsername("username")
            every { approvedScopes } returns setOf(AuthorityCode("code-1"), AuthorityCode("code-2"), AuthorityCode("code-3")).toMutableSet()
        }

        every { consumer.consume("authorizationCode") } returns authorizationCode
        every { validator.validateScopes(clientDetails, setOf("code-1", "code-2", "code-3")) } returns false

        val thrown = catchThrowable { granter.createAccessToken(clientDetails, tokenRequest) }
        assertThat(thrown).isInstanceOf(InvalidGrantException::class.java)
        assertThat((thrown as InvalidGrantException).error.errorCode).isEqualTo(OAuth2ErrorCodes.INVALID_SCOPE)
    }

    @Test
    fun `create access token when request authorization code scope is null`() {
        val clientDetails: OAuth2ClientDetails = mockk(relaxed = true)
        val tokenRequest: OAuth2TokenRequest = mockk {
            every { code } returns "authorizationCode"
        }
        val authorizationCode: OAuth2AuthorizationCode = mockk {
            every { code } returns "authorizationCode"
            every { clientId } returns OAuth2ClientId("clientId")
            every { username } returns PrincipalUsername("username")
            every { approvedScopes } returns null
        }

        every { consumer.consume("authorizationCode") } returns authorizationCode
        every { validator.validateScopes(clientDetails, null) } returns true

        val thrown = catchThrowable { granter.createAccessToken(clientDetails, tokenRequest) }
        assertThat(thrown).isInstanceOf(InvalidGrantException::class.java)
        assertThat((thrown as InvalidGrantException).error.errorCode).isEqualTo(OAuth2ErrorCodes.INVALID_SCOPE)
    }

    @Test
    fun `create access token when request authorization code scope is empty`() {
        val clientDetails: OAuth2ClientDetails = mockk(relaxed = true)
        val tokenRequest: OAuth2TokenRequest = mockk {
            every { code } returns "authorizationCode"
        }
        val authorizationCode: OAuth2AuthorizationCode = mockk {
            every { code } returns "authorizationCode"
            every { clientId } returns OAuth2ClientId("clientId")
            every { username } returns PrincipalUsername("username")
            every { approvedScopes } returns emptySet<AuthorityCode>().toMutableSet()
        }

        every { consumer.consume("authorizationCode") } returns authorizationCode
        every { validator.validateScopes(clientDetails, emptySet()) } returns true

        val thrown = catchThrowable { granter.createAccessToken(clientDetails, tokenRequest) }
        assertThat(thrown).isInstanceOf(InvalidGrantException::class.java)
        assertThat((thrown as InvalidGrantException).error.errorCode).isEqualTo(OAuth2ErrorCodes.INVALID_SCOPE)
    }

    @Test
    fun `create access token when request authorization code is invalid`() {
        val tokenRequestCaptor = slot<OAuth2TokenRequest>()
        val clientDetails: OAuth2ClientDetails = mockk {
            every { clientId } returns "clientId"
            every { scopes } returns setOf("client-1", "client-2", "client-3").toMutableSet()
        }
        val tokenRequest: OAuth2TokenRequest = mockk {
            every { code } returns "authorizationCode"
            every { username } returns "username"
            every { state } returns "state"
            every { redirectUri } returns URI.create("http://localhost")
            every { scopes } returns setOf("request-1", "request-2", "request-3")
            every { codeVerifier } returns CodeVerifier("FP7Am8xqMbyTCBgSYiTVuVkVv8ffScYCt2wali8JVC8")
        }
        val authorizationCode: OAuth2AuthorizationCode = mockk {
            every { code } returns "authorizationCode"
            every { clientId } returns OAuth2ClientId("clientId")
            every { username } returns PrincipalUsername("username")
            every { approvedScopes } returns setOf(AuthorityCode("code-1"), AuthorityCode("code-2"), AuthorityCode("code-3")).toMutableSet()
        }

        every { consumer.consume("authorizationCode") } returns authorizationCode
        every { validator.validateScopes(clientDetails, setOf("code-1", "code-2", "code-3")) } returns true
        every { authorizationCode.validateWithAuthorizationRequest(capture(tokenRequestCaptor)) }
            .throws(UnitTestAuthenticationException("test error"))

        val thrown = catchThrowable { granter.createAccessToken(clientDetails, tokenRequest) }
        assertThat(thrown).isInstanceOf(UnitTestAuthenticationException::class.java)
        assertThat(tokenRequestCaptor.isCaptured).isTrue
        assertThat(tokenRequestCaptor.captured.code).isEqualTo("authorizationCode")
        assertThat(tokenRequestCaptor.captured.username).isEqualTo("username")
        assertThat(tokenRequestCaptor.captured.state).isEqualTo("state")
        assertThat(tokenRequestCaptor.captured.redirectUri).isEqualTo(URI.create("http://localhost"))
        assertThat(tokenRequestCaptor.captured.scopes).isEqualTo(setOf("request-1", "request-2", "request-3"))
        assertThat(tokenRequestCaptor.captured.codeVerifier).isEqualTo(CodeVerifier("FP7Am8xqMbyTCBgSYiTVuVkVv8ffScYCt2wali8JVC8"))
    }

    @Test
    fun `create access token when refresh token id generator is not set`() {
        val tokenRequestCaptor = slot<OAuth2TokenRequest>()
        val clientDetails: OAuth2ClientDetails = mockk(relaxed = true) {
            every { clientId } returns "clientId"
            every { scopes } returns setOf("client-1", "client-2", "client-3").toMutableSet()
        }
        val tokenRequest: OAuth2TokenRequest = mockk {
            every { code } returns "authorizationCode"
            every { username } returns "username"
            every { state } returns "state"
            every { redirectUri } returns URI.create("http://localhost")
            every { scopes } returns setOf("request-1", "request-2", "request-3")
            every { codeVerifier } returns CodeVerifier("FP7Am8xqMbyTCBgSYiTVuVkVv8ffScYCt2wali8JVC8")
        }
        val authorizationCode: OAuth2AuthorizationCode = mockk {
            every { code } returns "authorizationCode"
            every { clientId } returns OAuth2ClientId("clientId")
            every { username } returns PrincipalUsername("username")
            every { approvedScopes } returns setOf(AuthorityCode("code-1"), AuthorityCode("code-2"), AuthorityCode("code-3")).toMutableSet()
        }

        granter.refreshTokenIdGenerator = null
        every { consumer.consume("authorizationCode") } returns authorizationCode
        every { validator.validateScopes(clientDetails, setOf("code-1", "code-2", "code-3")) } returns true
        every { authorizationCode.validateWithAuthorizationRequest(capture(tokenRequestCaptor)) } just Runs

        val accessToken = granter.createAccessToken(clientDetails, tokenRequest)
        assertThat(accessToken.tokenId).isEqualTo(OAuth2TokenId("tokenId"))
        assertThat(accessToken.refreshToken).isNotNull
        assertThat(accessToken.refreshToken!!.tokenId).isEqualTo(OAuth2TokenId("tokenId"))
        assertThat(tokenRequestCaptor.isCaptured).isTrue
        assertThat(tokenRequestCaptor.captured.code).isEqualTo("authorizationCode")
        assertThat(tokenRequestCaptor.captured.username).isEqualTo("username")
        assertThat(tokenRequestCaptor.captured.state).isEqualTo("state")
        assertThat(tokenRequestCaptor.captured.redirectUri).isEqualTo(URI.create("http://localhost"))
        assertThat(tokenRequestCaptor.captured.scopes).isEqualTo(setOf("request-1", "request-2", "request-3"))
        assertThat(tokenRequestCaptor.captured.codeVerifier).isEqualTo(CodeVerifier("FP7Am8xqMbyTCBgSYiTVuVkVv8ffScYCt2wali8JVC8"))
    }

    @Test
    fun `create access token when refresh token id generator is set`() {
        val tokenRequestCaptor = slot<OAuth2TokenRequest>()
        val clientDetails: OAuth2ClientDetails = mockk(relaxed = true) {
            every { clientId } returns "clientId"
            every { scopes } returns setOf("client-1", "client-2", "client-3").toMutableSet()
        }
        val tokenRequest: OAuth2TokenRequest = mockk {
            every { code } returns "authorizationCode"
            every { username } returns "username"
            every { state } returns "state"
            every { redirectUri } returns URI.create("http://localhost")
            every { scopes } returns setOf("request-1", "request-2", "request-3")
            every { codeVerifier } returns CodeVerifier("FP7Am8xqMbyTCBgSYiTVuVkVv8ffScYCt2wali8JVC8")
        }
        val authorizationCode: OAuth2AuthorizationCode = mockk {
            every { code } returns "authorizationCode"
            every { clientId } returns OAuth2ClientId("clientId")
            every { username } returns PrincipalUsername("username")
            every { approvedScopes } returns setOf(AuthorityCode("code-1"), AuthorityCode("code-2"), AuthorityCode("code-3")).toMutableSet()
        }

        granter.refreshTokenIdGenerator = mockk {
            every { generateTokenValue() } returns OAuth2TokenId("refreshTokenId")
        }
        every { consumer.consume("authorizationCode") } returns authorizationCode
        every { validator.validateScopes(clientDetails, setOf("code-1", "code-2", "code-3")) } returns true
        every { authorizationCode.validateWithAuthorizationRequest(capture(tokenRequestCaptor)) } just Runs

        val accessToken = granter.createAccessToken(clientDetails, tokenRequest)
        assertThat(accessToken.tokenId).isEqualTo(OAuth2TokenId("tokenId"))
        assertThat(accessToken.refreshToken).isNotNull
        assertThat(accessToken.refreshToken!!.tokenId).isEqualTo(OAuth2TokenId("refreshTokenId"))
        assertThat(tokenRequestCaptor.isCaptured).isTrue
        assertThat(tokenRequestCaptor.captured.code).isEqualTo("authorizationCode")
        assertThat(tokenRequestCaptor.captured.username).isEqualTo("username")
        assertThat(tokenRequestCaptor.captured.state).isEqualTo("state")
        assertThat(tokenRequestCaptor.captured.redirectUri).isEqualTo(URI.create("http://localhost"))
        assertThat(tokenRequestCaptor.captured.scopes).isEqualTo(setOf("request-1", "request-2", "request-3"))
        assertThat(tokenRequestCaptor.captured.codeVerifier).isEqualTo(CodeVerifier("FP7Am8xqMbyTCBgSYiTVuVkVv8ffScYCt2wali8JVC8"))
    }
}