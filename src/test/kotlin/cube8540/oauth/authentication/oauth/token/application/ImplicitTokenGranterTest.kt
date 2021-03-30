package cube8540.oauth.authentication.oauth.token.application

import cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientId
import cube8540.oauth.authentication.oauth.error.InvalidRequestException
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails
import cube8540.oauth.authentication.oauth.security.OAuth2RequestValidator
import cube8540.oauth.authentication.oauth.security.OAuth2TokenRequest
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AccessTokenRepository
import cube8540.oauth.authentication.oauth.token.domain.OAuth2TokenId
import cube8540.oauth.authentication.oauth.token.domain.OAuth2TokenIdGenerator
import cube8540.oauth.authentication.oauth.token.domain.PrincipalUsername
import cube8540.oauth.authentication.security.AuthorityCode
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.catchThrowable
import org.junit.jupiter.api.Test
import org.springframework.security.oauth2.core.OAuth2ErrorCodes

class ImplicitTokenGranterTest {

    private val tokenIdGenerator: OAuth2TokenIdGenerator = mockk {
        every { generateTokenValue() } returns OAuth2TokenId("tokenId")
    }
    private val repository: OAuth2AccessTokenRepository = mockk(relaxed = true) {
        every { save(any()) } returnsArgument 0
    }
    private val validator: OAuth2RequestValidator = mockk()

    private val granter = ImplicitTokenGranter(tokenIdGenerator, repository)

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
    fun `create access token when request scope is null`() {
        val clientDetails: OAuth2ClientDetails = mockk(relaxed = true) {
            every { clientId } returns "clientId"
            every { scopes } returns setOf("client-scope-1", "client-scope-2", "client-scope-3")
        }
        val tokenRequest: OAuth2TokenRequest = mockk {
            every { username } returns "username"
            every { scopes } returns null
        }

        every { validator.validateScopes(clientDetails, null) } returns true

        val result = granter.createAccessToken(clientDetails, tokenRequest)
        assertThat(result.username).isEqualTo(PrincipalUsername("username"))
        assertThat(result.client).isEqualTo(OAuth2ClientId("clientId"))
        assertThat(result.scopes)
            .isEqualTo(setOf(AuthorityCode("client-scope-1"), AuthorityCode("client-scope-2"), AuthorityCode("client-scope-3")))
    }

    @Test
    fun `create access token when request scope is empty`() {
        val clientDetails: OAuth2ClientDetails = mockk(relaxed = true) {
            every { clientId } returns "clientId"
            every { scopes } returns setOf("client-scope-1", "client-scope-2", "client-scope-3")
        }
        val tokenRequest: OAuth2TokenRequest = mockk {
            every { username } returns "username"
            every { scopes } returns emptySet()
        }

        every { validator.validateScopes(clientDetails, emptySet()) } returns true

        val result = granter.createAccessToken(clientDetails, tokenRequest)
        assertThat(result.username).isEqualTo(PrincipalUsername("username"))
        assertThat(result.client).isEqualTo(OAuth2ClientId("clientId"))
        assertThat(result.scopes)
            .isEqualTo(setOf(AuthorityCode("client-scope-1"), AuthorityCode("client-scope-2"), AuthorityCode("client-scope-3")))
    }

    @Test
    fun `create access token when request scope is allowed`() {
        val clientDetails: OAuth2ClientDetails = mockk(relaxed = true) {
            every { clientId } returns "clientId"
            every { scopes } returns setOf("client-scope-1", "client-scope-2", "client-scope-3")
        }
        val tokenRequest: OAuth2TokenRequest = mockk {
            every { username } returns "username"
            every { scopes } returns setOf("request-scope-1", "request-scope-2", "request-scope-3")
        }

        every { validator.validateScopes(clientDetails, setOf("request-scope-1", "request-scope-2", "request-scope-3")) } returns true

        val result = granter.createAccessToken(clientDetails, tokenRequest)
        assertThat(result.username).isEqualTo(PrincipalUsername("username"))
        assertThat(result.client).isEqualTo(OAuth2ClientId("clientId"))
        assertThat(result.scopes).isEqualTo(setOf(AuthorityCode("request-scope-1"), AuthorityCode("request-scope-2"), AuthorityCode("request-scope-3")))
    }
}